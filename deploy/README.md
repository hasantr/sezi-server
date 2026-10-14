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
  [Phone]──TLS──►  cloudflared edge  ──tunnel──►  nginx :8787 ──► wrangler 127.0.0.1:8788
        (A) the Cloudflare path                    (WS shim)         (sezi-relay)

  [Phone]──TLS──►  caddy :443 (Let's Encrypt) ───────────────────► wrangler 127.0.0.1:8788
        (B) the fully independent path, no CF                      (sezi-relay)
```

---

## 0. Prerequisites

- Debian 12/13 or Ubuntu 22.04+ (x86_64 or ARM64). **glibc ≥ 2.35** is required (workerd's
  floor), so Ubuntu 20.04 / RHEL 9 / Alpine (musl) are **NOT SUPPORTED**.
- Node.js 20+ (`node -v`).
- ~2 GB RAM recommended (Node + workerd take ~200–400 MB; 1 GB is tight).

---

## 1. Install wrangler at a PINNED version (no version drift)

`npx wrangler@4` fetches "the latest 4.x" every time, so miniflare's state format and workerd's
behaviour can change without notice. Instead, `package.json` pins an **exact version** and
`npm ci` installs **bit-identically from the lockfile**.

```bash
cd /opt/sezi-server
npm ci --omit=dev          # a reproducible install from package-lock.json
```

> **package-lock.json MUST be committed.** If the repository has none, run `npm install` once and
> commit `package.json` and `package-lock.json` together. `npm ci` refuses to run WITHOUT a
> lockfile (deliberately — that is the reproducibility guarantee).
>
> **An update is a deliberate commit:** raise the `wrangler` version in `package.json` by hand →
> `npm install` (refreshes the lockfile) → smoke-test with the prebuilt WASM → commit. Nothing
> drifts on its own.

---

## 2. Install the relay service (systemd, localhost only)

```bash
sudo useradd --system --home /var/lib/sezi --shell /usr/sbin/nologin sezi || true
sudo mkdir -p /var/lib/sezi/state /var/lib/sezi/backups
sudo chown -R sezi:sezi /opt/sezi-server /var/lib/sezi
sudo chmod +x /opt/sezi-server/deploy/*.sh    # a clone made on Windows does not carry the exec bit

sudo cp deploy/sezi-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sezi-relay
curl -s http://127.0.0.1:8788/healthz    # {"ok":true}
```

`sezi-relay.service` runs with `--ip 127.0.0.1 --port 8788 --persist-to /var/lib/sezi/state` (see
the comments in the file). `Restart=always`.

---

## 3. Outside access — PATH A: a cloudflared tunnel (tied to CF)

For the WebSocket (live /sync) the **nginx WS shim is REQUIRED**: in the chain cloudflared →
wrangler dev's Node proxy the 101 upgrade stalls (see the comment inside `sezi-ws-shim.conf`).

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

---

## 4. Turn the rate limits ON (the self-host profile)

`sezi-relay.service` already runs with `--config wrangler.selfhost.toml`. That profile is
**separate** from the root `wrangler.toml` (the button deploy) and declares
`[[kv_namespaces]] RATE_LIMIT`, so the local miniflare KV is **free**, has no CF daily limit, and
the rate limits (bootstrap enumeration slow-down, auth/verify, per-user message and media
ceilings) **really work**. No extra step: just run with the self-host config.

---

## 5. Atomic backup + nightly restart (timer)

A live `cp .wrangler/state` risks a torn WAL (D1, DO and R2 are three separate SQLite files).
`backup.sh` stops the relay → rsyncs → starts it again (a consistent snapshot) and prunes old
backups. The nightly window also refreshes wrangler dev (insurance for a long-lived process).

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

This kit takes an install from "family pilot" to "small production". wrangler dev is a
development server; the lasting answer is a native relay (D1 → SQLite, R2 → files/S3, DO → actors,
KV → memory, cron → an interval). When that arrives, the WS shim and the nightly-restart insurance
are no longer needed.
