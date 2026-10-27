# Sezi Server — hardening kit for a VPS or your own device

This folder holds ready files for running the Sezi relay **production-safe, around the clock, on a
VPS or on your own device (Raspberry Pi / mini-PC)**. If you installed with the "Deploy to
Cloudflare" button you do NOT need any of this — the kit is for a **self-managed** install, on an
operating system you run yourself.

> ⚠️ **The most critical rule — BIND:** the relay listens on **`127.0.0.1` only**. Outside access
> comes ONLY through (a) a cloudflared tunnel or (b) a caddy/nginx TLS reverse proxy in front of it.
> `--ip 0.0.0.0` puts the relay **on the internet as plain HTTP, signing key and all** — a real
> security hole. Every recipe below keeps to this rule.

Network layout (both paths keep the relay on localhost):

```
  [Phone]──TLS──►  cloudflared edge  ──tunnel──►  nginx :8787 ──► workerd 127.0.0.1:8788
        (A) the Cloudflare path                    (WS shim)         (sezi-relay)

  [Phone]──TLS──►  caddy :443 (Let's Encrypt) ───────────────────► workerd 127.0.0.1:8788
        (B) the fully independent path, no CF                      (sezi-relay)
```

The relay runs on **bare workerd** — the same runtime Cloudflare runs it on, as one process. No
Node, no wrangler, no npm at run time: the repository carries the prebuilt WASM and the workerd
config generated from it (`workerd/config.capnp`), and `workerd/WORKERD.lock` names the exact
workerd build that config was tested with, with its sha512 for each architecture.

---

## 0. Prerequisites

- 64-bit Linux (x86_64 or ARM64) with **glibc ≥ 2.35** (workerd's floor): Debian 12/13, Ubuntu
  22.04+, Raspberry Pi OS 64-bit (bookworm). Ubuntu 20.04, RHEL 9, Alpine (musl) and 32-bit Pi
  OS are **NOT SUPPORTED** — workerd is not built for them.
- `git`, `curl`, `tar`, `sha512sum`. **No Node.js.**
- ~35 MB to download once; the relay takes ~110–150 MB of memory, so 1 GB of RAM is plenty.

---

## 1. Fetch workerd at the PINNED version (no version drift)

```bash
sudo useradd --system --home /var/lib/sezi --shell /usr/sbin/nologin sezi || true
sudo mkdir -p /var/lib/sezi/state /var/lib/sezi/backups
sudo git clone https://github.com/hasantr/sezi-server /opt/sezi-server   # or your fork
sudo chown -R sezi:sezi /opt/sezi-server /var/lib/sezi
sudo -u sezi -H sh /opt/sezi-server/deploy/fetch-workerd.sh
```

`fetch-workerd.sh` downloads the workerd build `workerd/WORKERD.lock` names from the npm registry,
checks the tarball's sha512 against the lock **before** unpacking it, and installs it into
`/var/lib/sezi/.local/sezi-workerd/<version>/`, with `current` pointing at it. A download that
does not match is not installed. Nothing system-wide is touched.

> **An update is `sudo bash /opt/sezi-server/deploy/update.sh`.** It pulls and, when
> `workerd/WORKERD.lock` changed, fetches the new workerd while the relay still runs; then it stops
> the relay only to back up `state/` and start it again (about two seconds of downtime — clients
> reconnect and resend what was not acked), checks that it is healthy on the new build, and rolls
> code, workerd and data back if it is not. By hand it is the same steps: `git pull`,
> `fetch-workerd.sh` if the lock changed, restart; the old workerd stays beside the new one, so
> going back is moving `current`.

---

## 2. Install the relay service (systemd, localhost only)

```bash
sudo cp /opt/sezi-server/deploy/sezi-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sezi-relay
curl -s http://127.0.0.1:8788/healthz    # {"ok":true}
```

`sezi-relay.service` runs `workerd serve` on `workerd/config.capnp`, listening on
`127.0.0.1:8788`, with its stores in `/var/lib/sezi/state/v3/` (see the comments in the file).
`Restart=always`.

**Settings** (all optional) go in `/opt/sezi-server/.dev.vars` as `KEY=value` lines, owned by
`sezi` and `chmod 600`; the unit reads them as its environment. The names the relay accepts:
`SEZI_CLAIM_SECRET`, `SEZI_TRUSTED_PROXY_HEADER`, `SEZI_WEB_ORIGINS`, `TURN_KEY_ID`,
`TURN_API_TOKEN`, `TURN_MONTHLY_CAP`, `TURN_USER_MONTHLY_CAP`, `FCM_PROJECT_ID`,
`FCM_SERVICE_ACCOUNT`, `PUSH_RELAY_URL`, `RESET_PASSWORD`. Nothing else is read from the
environment — the signing key is generated on first start and kept in the database.

---

## 3. Outside access — PATH A: a cloudflared tunnel (tied to CF)

The **nginx WS shim** sits between cloudflared and the relay. It was made REQUIRED by the older
wrangler-based install, whose Node proxy stalled the WebSocket's 101 upgrade (see the comment
inside `sezi-ws-shim.conf`); bare workerd has no Node proxy, but the tunnel path has not been
measured without the shim yet, so keep it.

```bash
sudo apt install -y nginx
sudo cp deploy/sezi-ws-shim.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
# cloudflared Public Hostname → Service: http://127.0.0.1:8787
```

> **Installed the shim before it set `client_max_body_size`?** Then nginx's 1 MB default refuses
> every upload above 1 MB (a group-library recording's 4 MiB parts, photos, voice notes) with a
> 413 before the relay sees it. Run this once — it adds the size limit and streams bodies to the
> relay instead of first writing them to nginx's disk, only if the lines are missing, then tests
> and reloads nginx:
>
> ```bash
> grep -q proxy_request_buffering /etc/nginx/conf.d/sezi-ws-shim.conf || { sudo sed -i '/listen 127.0.0.1:8787;/a\    client_max_body_size 210m;\n    proxy_request_buffering off;' /etc/nginx/conf.d/sezi-ws-shim.conf && sudo nginx -t && sudo systemctl reload nginx; }
> ```

> **Cloudflare's own 100 MB cap applies on this path.** Every request through the tunnel passes
> Cloudflare's edge, which refuses a request body over 100 MB (Free and Pro plans) whatever nginx
> allows. Photos, videos and voice notes (50 MiB at most) and library parts (4 MiB) are well under
> it. The one upload that can be bigger is the **instrument pack** (up to 200 MiB): on a tunnel
> relay, use a pack under ~95 MB, or reach the relay by the caddy path (B) below, which has no
> such cap.

Firewall (cloudflared connects OUTBOUND only, so no inbound port is needed):

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp          # SSH — do not lock yourself out!
sudo ufw enable
```

## 3. Outside access — PATH B: caddy + Let's Encrypt (fully independent of CF)

Your own domain and your own TLS; zero dependency on Cloudflare. caddy proxies WebSockets as
they are, so **no separate WS shim is needed**, and it sets no request-body limit of its own.

```bash
# install caddy: https://caddyserver.com/docs/install
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo sed -i 's/sezi.example.com/your.domain/' /etc/caddy/Caddyfile
sudo systemctl reload caddy

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp          # Let's Encrypt ACME
sudo ufw allow 443/tcp         # HTTPS + WSS
sudo ufw enable
```

> **Why `header_up cf-connecting-ip {remote_host}`?** The worker's per-IP rate limits (bootstrap,
> verify, redeem, the invite page) read only the `cf-connecting-ip` header. On the CF path
> Cloudflare sets it; on the caddy path caddy does (with the real client address, not
> spoofable). Without it every request falls into one shared "local" bucket and the per-IP limits
> collapse.

> **A relay only your local network reaches (no tunnel, no caddy).** Here the relay faces the
> network itself, so it must not believe any header a client sends about its own address. Set
> `SEZI_TRUSTED_PROXY_HEADER=socket` in `.dev.vars` and change the unit's
> `--socket-addr=http=127.0.0.1:8788` to `--socket-addr=http=0.0.0.0:8787`: workerd hands the
> relay the TCP peer, and the rate limits are keyed on that alone. No front process is needed.
> The Sezi app's "This network" install writes exactly this into its unit. Plain HTTP on a
> network you trust only — sign-ins cross it in the clear.
>
> (`sezi-lan-front.mjs` is the older wrangler-based install's answer to the same problem, kept
> for relays still running that way.)

---

## 4. Turn the rate limits ON (the self-host profile)

`workerd/config.capnp` is generated from `wrangler.selfhost.toml`, the self-host profile —
**separate** from the root `wrangler.toml` (the button deploy). It declares
`[[kv_namespaces]] RATE_LIMIT`, so the local KV is **free**, has no CF daily limit, and the rate
limits (bootstrap enumeration slow-down, auth/verify, per-user message and media ceilings)
**really work**. No extra step.

---

## 5. Atomic backup + nightly restart (timer)

A live copy of `/var/lib/sezi/state` risks a torn WAL (D1, DO and R2 are three separate SQLite files).
`backup.sh` stops the relay → rsyncs → starts it again (a consistent snapshot) and prunes old
backups.

```bash
sudo cp deploy/sezi-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sezi-backup.timer
# By hand: sudo systemctl start sezi-backup.service ; ls /var/lib/sezi/backups
```

**Restore:** `sudo systemctl stop sezi-relay && sudo rsync -a --delete \
/var/lib/sezi/backups/state-<stamp>/ /var/lib/sezi/state/ && sudo systemctl start sezi-relay`

---

## 6. Liveness watchdog (healthz)

`Restart=always` recovers a process that died; the watchdog catches one that is "hung but alive"
(/healthz != 200 → restart).

```bash
sudo cp deploy/sezi-healthz.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sezi-healthz.timer
```

---

## Known limit (an honest note)

The relay runs on the runtime Cloudflare itself uses, with its development services (the
binding proxy, the storage browser) removed from the generated config. Its stores are workerd's
local SQLite files, one machine's worth: there is no replication, so the nightly backup above is
the whole of your disaster recovery. A native relay (D1 → SQLite, R2 → files/S3, DO → actors) is
planned; it changes nothing the app sees.
