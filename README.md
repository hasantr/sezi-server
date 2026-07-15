# Sezi Server

**Sezi**'nin (uçtan-uca şifreli, dışa-kapalı grup mesajlaşma + uygulama platformu) kendi sunucunu kurmak için hazır paketi. Sunucu **kör bir relay**dir: mesaj içeriğini, medyayı, eklenti verisini **okuyamaz** — yalnız şifreli baytları sıralar ve taşır. Anahtarlar cihazlarda kalır.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/hasantr/sezi-server)

## Kurulum (5 dakika, komut satırı gerekmez)

1. **Cloudflare hesabı aç** (ücretsiz): <https://dash.cloudflare.com/sign-up>
2. Yukarıdaki **Deploy to Cloudflare** butonuna bas — Cloudflare repo'yu senin hesabına kopyalar, veritabanını (D1) ve hız-limiti deposunu (KV, brute-force freni) otomatik oluşturur, deploy eder.
3. Deploy bitince sana bir adres verilir: `https://sezi-server.<hesabın>.workers.dev`
4. **Sezi uygulamasında** "Sunucu ekle → Kendi sunucunu kur" adımında bu adresi yapıştır. **İlk kayıt olan hesap sunucunun sahibi (owner) olur** — davetleri, limitleri, her şeyi uygulamadan yönetirsin.

Hepsi bu. İmza anahtarları ilk açılışta sunucu tarafından otomatik üretilir; veritabanı şeması ilk istekte kendini kurar. `wrangler secret` ya da migration komutu **gerekmez**. Kart bilgisi **istenmez**.

> **Lite kurulum:** Bu şablon "hafif" kurulur — mesajlaşma, gruplar ve aramalar tam çalışır; **fotoğraf/dosya paylaşımı** için Cloudflare'da R2 depolamayı sonradan etkinleştirmen yeterlidir (kart doğrulaması ister; 10 GB'a kadar ücretsiz, üstü cüzi). Nasıl: dashboard'da R2'yi etkinleştir → `sezi-media` bucket'ı oluştur → Worker → Settings → **Bindings → R2 ekle** (`MEDIA` / `sezi-media`). Kod/komut gerekmez; uygulama özelliği kendiliğinden gösterir.
> Kendi cihazında `wrangler dev` ile çalıştırıyorsan R2 aboneliği hiç gerekmez:
> `wrangler.toml`'daki `[[r2_buckets]]` bloğunu aç — medya yerel diskte saklanır.

## Ne alırsın

- 🔒 **Kör relay** — içerik E2E-şifreli; sunucu yalnız boyut/sayı görür
- 👑 **Owner yönetimi uygulamadan** — davet, üye, saklama süresi, depolama limitleri, kullanım paneli
- 📊 **Kullanım paneli** — depolama / arama (TURN) / günlük-aylık hacim; istersen CF API token'ıyla "faturayla birebir" mod (token'ı da uygulamadan girersin)
- 💸 **Bütçe bekçileri** — TURN aylık tavanı + owner-ayarlı depolama kotaları: ücretsiz katmanda sürpriz fatura yok
- 📱 Çoklu cihaz, gruplar (Megolm), sesli/görüntülü arama (LAN/STUN; istersen CF TURN), eklenti platformu
- 🧲 **Takılabilir depolama** — medyayı R2 yerine/yanına KENDİ deponda tut (aşağıya bak)

## 🧲 Takılabilir depolama: kendi bulutun ya da kendi diskin

Medya deposu R2 ile sınırlı değil. **Her S3-uyumlu depoyu** sunucuya uygulamadan
bağlayabilirsin — kod, komut, redeploy gerekmez:

- **Bulut:** Backblaze B2, Wasabi, iDrive e2, MinIO-bulut, başka bir R2 hesabı…
- **Kendi diskin (self-host):** aynı cihazda çalışan bir [MinIO](https://min.io)
  (örn. Raspberry Pi + büyük HDD) → `http://localhost:9000`

**Nasıl:** Uygulamada owner olarak → Sunucu → panel → **DEPOLAMA** bölümü →
depo ekle (endpoint / bölge / bucket / erişim anahtarları) → **Sına**. Hepsi bu;
yeni medya artık oraya yazılır. Aynı yerden depo **boşaltılır** (drain: blob'lar
taşınır) ve **kaldırılır**; sağlık ve doluluk da panelde görünür.

**Gizlilik notu:** Medya blob'ları uçtan-uca şifreli yazılır — bağladığın depo
sağlayıcısı (Backblaze, MinIO, kim olursa) yalnız **şifreli çöp** görür.
Anahtarlar hep cihazlarda.

## Alternatif: komut satırıyla kurulum

```bash
git clone https://github.com/hasantr/sezi-server && cd sezi-server
npx wrangler login
npx wrangler d1 create sezi          # çıktıdaki database_id'yi wrangler.toml'a yaz
npx wrangler kv namespace create RATE_LIMIT   # çıktıdaki id'yi wrangler.toml'a yaz
npx wrangler deploy
```

`build/` klasörü derlenmiş WASM içerir — **Rust kurmana gerek yok**. Kaynaktan kendin derlemek istersen: `cargo install worker-build && worker-build --release`.

## Kendi cihazında / VPS'te çalıştırma (Cloudflare'siz, ileri düzey)

Sunucuyu Cloudflare'e hiç bağlanmadan **kendi VPS'inde ya da cihazında (Raspberry Pi / mini-PC)** 7/24 çalıştırabilirsin. Bu, `wrangler dev` lokal-workerd'i systemd altında kalıcılaştırır ve dışarıya ya cloudflared tüneli ya da caddy TLS reverse-proxy ile açar.

> ⚠️ **Güvenlik-kritik:** self-managed kurulumda relay **yalnız `127.0.0.1`** dinlemeli; dış erişim **sadece** tünel veya TLS-proxy önünden olmalı. `--ip 0.0.0.0` sunucuyu düz-HTTP olarak internete açar — **yapma**.

Hazır sertleştirme paketi (wrangler EXACT-PIN, localhost-bind, WS-shim, atomik yedek, healthz-watchdog, ufw) [`deploy/`](deploy/) klasöründe adım-adım anlatılıyor → **[deploy/README.md](deploy/README.md)**. Self-host için ayrı bir config kullanılır (`wrangler.selfhost.toml`; hız-limiti KV'si açık) — "Deploy to Cloudflare" butonu bundan etkilenmez.

## Opsiyonel yapılandırma

| Ne | Nasıl | Yoksa ne olur |
|---|---|---|
| Kendi imza anahtarın | `wrangler secret put JWT_SIGNING_KEY` (Ed25519 PKCS8 PEM) | İlk açılışta otomatik üretilir (D1'de saklanır) |
| Sesli/görüntülü arama TURN relay | CF Realtime → TURN anahtarı → `TURN_KEY_ID` + `TURN_API_TOKEN` secret | Aramalar LAN/STUN ile çalışır (çoğu ağda yeterli) |
| Android push | Firebase projesi → `FCM_PROJECT_ID` var + `FCM_SERVICE_ACCOUNT` secret | Uygulama açıkken teslim (WS); kapalıyken bekler |
| Faturayla-birebir kullanım raporu | Uygulamadan: Sunucu → Kullanım → CF Analytics → token gir | Sunucu kendi sayaçlarını raporlar |

## Güncelleme

1. GitHub'da fork'unda **Sync fork → Update branch** yap.
2. Cloudflare'a bağlı kurulumda bu genellikle otomatik yeniden-deploy tetikler; **tetiklenmezse** Cloudflare dashboard → Workers & Pages → sunucun → **Deployments/Builds** sekmesinden "Retry/Deploy" ile elle tetikle, ya da bilgisayarında tek komut: `npx wrangler deploy` (fork klasöründe).

Veritabanı şeması kendini günceller (self-migration) — veri kaybolmaz.

## Aynı hesapta birden fazla sunucu

Kurarken **veritabanı adı çakışmasına** dikkat: ikinci sunucuyu aynı Cloudflare hesabına kurarken kurulum ekranında **D1 veritabanı adını** benzersiz yap (örn. `sezi-aile`, `sezi-okul`). Aynı adı kullanırsan iki sunucu **aynı veritabanını paylaşır** (üyeler/veriler karışır). Worker/KV adlarının değişmesi zararsızdır. Not: ücretsiz plan kotaları (istek/depolama) hesaptaki tüm sunucular arasında paylaşılır.

## Mimari (kısaca)

Rust → WASM Cloudflare Worker. D1 (SQLite) metadata + kuyruk, R2 şifreli medya, kullanıcı-başına Durable Object gelen-kutusu (WebSocket). İçerik vodozemac (Olm/Megolm) ile uçtan-uca şifreli — sunucu tasarım gereği okuyamaz.

## Lisans

Henüz belirlenmedi — yayın öncesi eklenecek.
