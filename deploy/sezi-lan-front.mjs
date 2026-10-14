// sezi-lan-front.mjs: the front of a Sezi relay that "the people on my network" reach directly.
//
// WHY. `wrangler dev` passes a client's own `cf-connecting-ip` (and `x-real-ip`,
// `x-forwarded-for`) through untouched, and it is the only place a relay with no proxy in front
// could learn who is calling. So a relay bound to 0.0.0.0 could not tell its LAN clients apart:
// either every client got a fresh rate-limit budget per forged header, or (the stopgap,
// `SEZI_TRUSTED_PROXY_HEADER=none`) the whole network shared one, and one person typing wrong
// invite codes locked everyone out of joining for five minutes.
//
// WHAT. This file listens on the LAN port, starts wrangler on loopback behind it, and forwards
// every request and WebSocket upgrade with the client-address headers REPLACED by one it sets
// itself from the socket: `x-real-ip`. The relay trusts that header and no other
// (`--var SEZI_TRUSTED_PROXY_HEADER:x-real-ip`). Bodies stream through (an upload is never held
// in memory or on disk), and no request is timed out here.
//
// HOW IT RUNS. One systemd unit (written by the Sezi app, `relay_unit.dart`), one process tree:
//
//   node sezi-lan-front.mjs --ip 0.0.0.0 --port 8787 --inner-port 18787 -- <wrangler command>
//
// The wrangler command after `--` must listen on 127.0.0.1:<inner-port>. If wrangler exits, this
// exits with its code and systemd restarts both; a signal to this process is passed on to it.
// Needs nothing but Node (the relay's own, >= 20).

import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

/** Every header that claims to name the client. A client's own value of any of them is dropped. */
export const CLIENT_ADDRESS_HEADERS = [
  'x-real-ip',
  'x-forwarded-for',
  'cf-connecting-ip',
  'forwarded',
  'true-client-ip',
  'x-client-ip',
];

/** The socket's peer as the relay should see it: an IPv4-mapped IPv6 address as plain IPv4. */
export function clientAddress(socket) {
  const a = socket.remoteAddress || '';
  return a.startsWith('::ffff:') && a.includes('.') ? a.slice('::ffff:'.length) : a;
}

/** The request's headers with the client-address claims replaced by the socket's own. */
export function forwardedHeaders(headers, socket) {
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!CLIENT_ADDRESS_HEADERS.includes(name.toLowerCase())) out[name] = value;
  }
  out['x-real-ip'] = clientAddress(socket);
  return out;
}

/** `--ip A --port N --inner-port M -- cmd...` → the options and the child's command. */
export function parseArgs(argv) {
  const split = argv.indexOf('--');
  const own = split < 0 ? argv : argv.slice(0, split);
  const command = split < 0 ? [] : argv.slice(split + 1);
  const value = (flag) => {
    const i = own.indexOf(flag);
    return i < 0 ? undefined : own[i + 1];
  };
  return {
    ip: value('--ip') ?? '0.0.0.0',
    port: Number(value('--port')),
    innerPort: Number(value('--inner-port')),
    command,
  };
}

/** The front itself, forwarding to 127.0.0.1:`innerPort`. */
export function createFront(innerPort) {
  const server = http.createServer((req, res) => {
    const upstream = http.request(
      {
        host: '127.0.0.1',
        port: innerPort,
        method: req.method,
        path: req.url,
        headers: forwardedHeaders(req.headers, req.socket),
      },
      (answer) => {
        res.writeHead(answer.statusCode ?? 502, answer.statusMessage, answer.rawHeaders);
        answer.pipe(res);
      },
    );
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('relay not answering');
    });
    req.pipe(upstream);
  });
  // An upload of a large file is one long request: nothing here cuts it off.
  server.requestTimeout = 0;
  server.headersTimeout = 60_000;

  server.on('upgrade', (req, socket, head) => {
    const upstream = net.connect(innerPort, '127.0.0.1', () => {
      let lines = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
      for (const [name, value] of Object.entries(forwardedHeaders(req.headers, req.socket))) {
        for (const one of Array.isArray(value) ? value : [value]) lines += `${name}: ${one}\r\n`;
      }
      upstream.write(`${lines}\r\n`);
      if (head && head.length) upstream.write(head);
      socket.pipe(upstream).pipe(socket);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  });
  return server;
}

function main() {
  const { ip, port, innerPort, command } = parseArgs(process.argv.slice(2));
  if (!Number.isInteger(port) || !Number.isInteger(innerPort) || command.length === 0) {
    console.error('usage: sezi-lan-front.mjs --ip <addr> --port <lan port> --inner-port <loopback port> -- <wrangler command>');
    process.exit(2);
  }
  const child = spawn(command[0], command.slice(1), { stdio: 'inherit' });
  child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    process.on(signal, () => child.kill(signal));
  }
  const front = createFront(innerPort);
  front.on('error', (e) => {
    console.error(`sezi-lan-front: cannot listen on ${ip}:${port}: ${e.message}`);
    child.kill('SIGTERM');
    process.exit(1);
  });
  front.listen(port, ip, () => {
    console.log(`sezi-lan-front: ${ip}:${port} -> 127.0.0.1:${innerPort} (x-real-ip from the socket)`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
