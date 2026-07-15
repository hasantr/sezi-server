# Sezi Server — VPS / kendi-cihaz sertleştirme paketi

Bu klasör, Sezi relay'ini **VPS'te ya da kendi cihazında (Raspberry Pi / mini-PC)**
7/24 **üretim-güvenli** çalıştırmak için hazır dosyalar içerir. "Deploy to Cloudflare"
butonuyla kuruyorsan buna GEREK YOK — bu paket **self-managed** (kendi işletim
sistemin üstünde) kurulum içindir.

> ⚠️ **En kritik kural — BIND:** relay **yalnız `127.0.0.1`** dinler. Dış erişim
> SADECE (a) cloudflared tüneli veya (b) caddy/nginx TLS reverse-proxy önünden olur.
> `--ip 0.0.0.0` relay'i **düz-HTTP + imza-anahtarıyla doğrudan internete açar** =
> gerçek güvenlik açığı. Aşağıdaki reçetelerin hepsi bu kurala uyar.

Ağ şeması (her iki yol da relay'i localhost'ta tutar):

```
  [Telefon]──TLS──►  cloudflared-edge  ──tünel──►  nginx :8787 ──► wrangler 127.0.0.1:8788
        (A) Cloudflare yolu                         (WS-shim)          (sezi-relay)

  [Telefon]──TLS──►  caddy :443 (Let's Encrypt) ─────────────────► wrangler 127.0.0.1:8788
        (B) CF'siz tam-bağımsız yol                                 (sezi-relay)
```

---

## 0. Ön-koşullar

- Debian 12/13 veya Ubuntu 22.04+ (x86_64 ya da ARM64). **glibc ≥ 2.35** gerekir
  (workerd kapısı) → Ubuntu 20.04 / RHEL 9 / Alpine-musl **DESTEKLENMEZ**.
- Node.js 20+ (`node -v`).
- ~2 GB RAM öner (Node + workerd ~200–400 MB; 1 GB sınırda).

---

## 1. wrangler'ı SABİT sürümden kur (sürüm-drift kilidi)

`npx wrangler@4` her seferinde "latest 4.x" çeker → miniflare state-formatı/workerd
davranışı habersiz değişebilir. Bunun yerine `package.json` **tam sürüme** pinler ve
`npm ci` **lockfile'dan bit-aynı** kurar.

```bash
cd /opt/sezi-server
npm ci --omit=dev          # package-lock.json'dan reprodüksiyon-kilitli kurulum
```

> **package-lock.json commit'li OLMALI.** Repo'da yoksa bir kez `npm install`
> çalıştırıp `package.json` + `package-lock.json`'u birlikte commit'le. `npm ci`
> lockfile OLMADAN çalışmaz (bilinçli — reprodüksiyon garantisi).
>
> **Güncelleme = bilinçli commit:** `package.json`'daki `wrangler` sürümünü elle
> yükselt → `npm install` (lockfile tazelenir) → prebuilt-WASM ile smoke-test →
> commit. Otomatik-drift YOK.

---

## 2. Relay servisini kur (systemd, sadece-localhost)

```bash
sudo useradd --system --home /var/lib/sezi --shell /usr/sbin/nologin sezi || true
sudo mkdir -p /var/lib/sezi/state /var/lib/sezi/backups
sudo chown -R sezi:sezi /opt/sezi-server /var/lib/sezi
sudo chmod +x /opt/sezi-server/deploy/*.sh    # Windows'ta klonlandıysa exec-bit taşınmaz

sudo cp deploy/sezi-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sezi-relay
curl -s http://127.0.0.1:8788/healthz    # {"ok":true}
```

`sezi-relay.service` `--ip 127.0.0.1 --port 8788 --persist-to /var/lib/sezi/state`
kullanır (bkz. dosya içi yorumlar). `Restart=always`.

---

## 3. Dış erişim — YOL A: cloudflared tüneli (mevcut, CF'e bağlı)

WebSocket (canlı /sync) için **nginx WS-shim ZORUNLU** — cloudflared → wrangler-dev
Node-proxy zincirinde 101-upgrade takılır (bkz. `sezi-ws-shim.conf` içi açıklama).

```bash
sudo apt install -y nginx
sudo cp deploy/sezi-ws-shim.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
# cloudflared Public Hostname → Service: http://127.0.0.1:8787
```

Güvenlik duvarı (cloudflared yalnız OUTBOUND bağlanır → inbound port GEREKMEZ):

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp          # SSH — kendini kilitleme!
sudo ufw enable
```

## 3. Dış erişim — YOL B: caddy + Let's Encrypt (CF'siz tam-bağımsız)

Kendi domain'in + kendi TLS'in; Cloudflare'e sıfır bağımlılık. caddy WebSocket'i
doğal proxy'ler → **ayrı WS-shim gerekmez**.

```bash
# caddy kur: https://caddyserver.com/docs/install
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo sed -i 's/sezi.example.com/senin.domainin/' /etc/caddy/Caddyfile
sudo systemctl reload caddy

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp          # Let's Encrypt ACME
sudo ufw allow 443/tcp         # HTTPS + WSS
sudo ufw enable
```

> **Neden `header_up cf-connecting-ip {remote_host}`?** Worker per-IP hız-limitleri
> (bootstrap/verify/redeem) yalnız `cf-connecting-ip` başlığını okur. CF-yolunda CF
> bunu koyar; caddy-yolunda caddy koyar (gerçek istemci IP'siyle, spoof-korumalı).
> Koymazsan tüm istekler tek "local" kovaya düşer = per-IP limit çöker.

---

## 4. Hız-limitini AÇ (self-host profili)

`sezi-relay.service` zaten `--config wrangler.selfhost.toml` kullanır. Bu profil kök
`wrangler.toml`'dan (buton-deploy) **ayrıdır** ve `[[kv_namespaces]] RATE_LIMIT`
içerir → lokal miniflare-KV **bedava**, CF-günlük-limiti yok → hız-limitleri
(bootstrap enumerasyon-yavaşlatma, auth/verify, per-user mesaj/medya tavanları)
**gerçekten çalışır**. Ekstra adım gerekmez; sadece self-host config'iyle çalıştır.

---

## 5. Atomik yedek + gece-restart (timer)

Canlı `cp .wrangler/state` = bozuk-WAL riski (D1+DO+R2 üç ayrı SQLite). `backup.sh`
relay'i durdurur → rsync → başlatır (tutarlı snapshot) + eski yedekleri budar. Gece
penceresi aynı zamanda wrangler-dev'i tazeler (uzun-ömür sigortası).

```bash
sudo cp deploy/sezi-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sezi-backup.timer
# Elle test: sudo systemctl start sezi-backup.service ; ls /var/lib/sezi/backups
```

**Geri-yükleme:** `sudo systemctl stop sezi-relay && sudo rsync -a --delete \
/var/lib/sezi/backups/state-<damga>/ /var/lib/sezi/state/ && sudo systemctl start sezi-relay`

---

## 6. Canlılık bekçisi (healthz watchdog)

`Restart=always` süreç ölürse toparlar; watchdog "asılı ama canlı" durumunu yakalar
(/healthz != 200 → restart).

```bash
sudo cp deploy/sezi-healthz.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sezi-healthz.timer
```

---

## Bilinen sınır (dürüstlük notu)

Bu paket kurulumu **"aile-pilotu → küçük-üretim"** sınıfına taşır. wrangler-dev bir
geliştirme-sunucusudur; kalıcı native çözüm **Faz-3 `sezi-serverd` (axum)** —
D1→rusqlite, R2→FS/S3, DO→tokio-actor, KV→bellek, cron→interval. O gelince WS-shim
ve gece-restart sigortaları gereksizleşir. Bkz. `SEZI_SERVER_PLATFORM_PLAN.md`.
