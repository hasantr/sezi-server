//! Hoş-geldin sayfası — `GET /` (kesin-çözüm paketi 2026-07-06).
//!
//! SAHA GEREKÇESİ: taze kurulumda kullanıcı workers.dev adresine tarayıcıdan
//! tıklayınca 404/çıplak-JSON görüyordu — "sunucum çalışıyor mu?" sorusuna
//! güven vermiyor. Bu sayfa üç durumda insan-okur Türkçe cevap verir:
//!   - Owner YOK (taze kurulum): "sunucun hazır" + adresi-kopyala + app'e
//!     yapıştırma yönergesi + KURULUŞ KODU (Hasan-kararı 2026-07-07: app'in
//!     otomatik-genesis-çekimi aksarsa görünür yedek-yol). Güvenlik-eşdeğer:
//!     kod owner-yokken zaten `GET /bootstrap`'tan public (kendini-kapatan
//!     kapı) → sayfada göstermek ek yüzey açmaz. Owner oluşunca kod bir daha
//!     ASLA gösterilmez.
//!   - Owner VAR: "sunucu aktif" + davet-kodu yönergesi.
//!   - D1-hatası: FAIL-OPEN nötr metin (sayfa yine döner; durum iddiası yok).
//!
//! Estetik: MurmurTokens sıcak-krem paleti (mobile palette.dart hex'leriyle
//! bire-bir: page #F1E6D4 / paper #FAF1E6 / ink #201812 / accent #F97316),
//! inline-CSS, dış kaynak yok (self-contained; dışa-kapalı sunucu felsefesi).

use serde::Deserialize;
use worker::*;

use crate::auth::bootstrap::ensure_genesis_token;
use crate::d1util::d1_text;

/// `GET /` — owner-durumuna göre hoş-geldin sayfası. `Response::from_html`
/// `Content-Type: text/html; charset=utf-8` başlığını kendisi koyar.
pub async fn welcome(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // FAIL-OPEN: owner-sorgusu düşerse (D1 yok/geçici hata) None → nötr metin.
    let owner = owner_exists(&ctx.env).await;
    // Kuruluş kodu YALNIZ owner-YOK durumunda çekilir (owner-var / D1-hata
    // kollarında ASLA). /bootstrap ile aynı get-or-mint yolu (M10 yarış-deseni
    // dahil). FAIL-OPEN: kod alınamazsa None → sayfa yine döner, kod kutusu
    // yerine "birazdan yenile" satırı.
    let genesis = if owner == Some(false) {
        match ctx.env.d1("DB") {
            Ok(db) => ensure_genesis_token(&db).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };
    // Adres = isteğin origin'i (scheme://host[:port]) — kullanıcının tarayıcıda
    // gördüğü adresin aynısı; custom-domain'de de doğru kalır.
    let origin = req
        .url()
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_default();
    Response::from_html(render_welcome(owner, &origin, genesis.as_deref()))
}

/// Owner var mı? (verify'daki ilk-kullanıcı=owner kuralı → owner-satırı =
/// "kuruluş yapılmış" işareti; bootstrap.rs ile aynı sorgu ailesi.) Hafif:
/// tek indexli SELECT, LIMIT 1. Hata → None (fail-open, sayfa yine döner).
async fn owner_exists(env: &Env) -> Option<bool> {
    #[derive(Deserialize)]
    struct One {
        #[allow(dead_code)]
        one: i64,
    }
    let db = env.d1("DB").ok()?;
    let row: Option<One> = db
        .prepare("SELECT 1 AS one FROM users WHERE role = ? LIMIT 1")
        .bind(&[d1_text("owner")])
        .ok()?
        .first(None)
        .await
        .ok()?;
    Some(row.is_some())
}

/// Sayfa iskeleti — `format!` yerine `replace` (CSS `{}` süslü-parantezleriyle
/// format-string çakışmasın). `__CONTENT__` tek enjeksiyon noktası; içerik
/// `render_welcome`da kurulur, kullanıcı-girdisi (origin) HTML-escape'lenir.
const PAGE: &str = r#"<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sezi</title>
<style>
  :root {
    --page: #F1E6D4; --paper: #FAF1E6; --surface: #FFFFFF;
    --ink: #201812; --ink-soft: #6F6357; --ink-faint: #A3968A;
    --rule: #E7DAC6; --accent: #F97316; --accent-dark: #EA580C;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --page: #16100B; --paper: #1D1610; --surface: #282017;
      --ink: #F1E9DE; --ink-soft: #A79B8D; --ink-faint: #71655A;
      --rule: #3A2F24; --accent: #F97316; --accent-dark: #FB923C;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
    background: var(--page); color: var(--ink);
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    padding: 24px;
  }
  .card {
    background: var(--paper); border: 1px solid var(--rule);
    border-radius: 18px; max-width: 440px; width: 100%;
    padding: 36px 32px; text-align: center;
    box-shadow: 0 2px 6px rgba(58,42,24,.07), 0 8px 28px rgba(58,42,24,.10);
  }
  .emoji { font-size: 44px; line-height: 1; margin-bottom: 14px; }
  h1 { font-size: 21px; margin: 0 0 10px; letter-spacing: -.2px; }
  p { font-size: 14.5px; line-height: 1.55; color: var(--ink-soft); margin: 0 0 14px; }
  p b { color: var(--ink); }
  .addr {
    display: flex; gap: 8px; align-items: center; margin: 18px 0;
    background: var(--surface); border: 1px solid var(--rule);
    border-radius: 12px; padding: 10px 12px;
  }
  .addr code {
    flex: 1; font-size: 13px; overflow-wrap: anywhere; text-align: left;
    color: var(--ink); font-family: ui-monospace, Consolas, monospace;
  }
  .addr button {
    flex-shrink: 0; border: 0; border-radius: 9px; cursor: pointer;
    background: var(--accent); color: #fff; font-size: 12.5px;
    font-weight: 600; padding: 8px 12px; font-family: inherit;
  }
  .addr button:hover { background: var(--accent-dark); }
  .lbl {
    font-size: 11.5px; font-weight: 600; letter-spacing: .5px;
    text-transform: uppercase; color: var(--ink-faint);
    margin: 20px 0 6px; text-align: left;
  }
  .foot { font-size: 12px; color: var(--ink-faint); margin: 18px 0 0; }
</style>
</head>
<body>
<main class="card">
__CONTENT__
<p class="foot">Sezi — self-hosted, uçtan uca şifreli grup platformu</p>
</main>
</body>
</html>
"#;

/// İçeriği kur (SAF → unit-testli). `owner`: `Some(false)`=taze kurulum,
/// `Some(true)`=aktif sunucu, `None`=D1-hatası (nötr). `genesis`: kuruluş
/// kodu — YALNIZ `Some(false)` kolunda gösterilir (o durumda kod zaten
/// /bootstrap'tan public; görünür yedek-yol). Owner-var/D1-hata kollarında
/// çağıran `None` geçer, kod ASLA gömülmez.
fn render_welcome(owner: Option<bool>, origin: &str, genesis: Option<&str>) -> String {
    let addr = html_escape(origin);
    // Kopyala-butonu adresi DOM'dan okur (`#addr`) → adres için ayrıca
    // JS-string-escape gerekmez; pano API'siz eski tarayıcıda buton sessiz düşer,
    // adres yine seçilip elle kopyalanabilir.
    let addr_box = format!(
        r#"<div class="addr"><code id="addr">{addr}</code><button onclick="navigator.clipboard.writeText(document.getElementById('addr').textContent).then(()=>{{this.textContent='Kopyalandı ✓'}})">Adresi kopyala</button></div>"#
    );
    // Kuruluş-kodu kutusu (yalnız taze-kurulum kolunda kullanılır). Kod b64u
    // olsa da savunmacı HTML-escape; kopyala-butonu adres-kopyala deseninin
    // aynısı (DOM'dan okur, `#gcode`). FAIL-OPEN: kod yoksa kutu yerine
    // "birazdan yenile" satırı — sayfa yine döner.
    let code_box = match genesis {
        Some(code) => {
            let code = html_escape(code);
            format!(
                r#"<p class="lbl">Kuruluş kodu</p><div class="addr"><code id="gcode">{code}</code><button onclick="navigator.clipboard.writeText(document.getElementById('gcode').textContent).then(()=>{{this.textContent='Kopyalandı ✓'}})">Kodu kopyala</button></div><p>Bu kodla <b>ilk kaydolan</b> sunucunun sahibi olur; sunucu sahiplenince kod geçersizleşir. Uygulama bu kodu normalde kendisi alır — burası yedek yol.</p>"#
            )
        }
        None => "<p>Kuruluş kodu şu an alınamadı — sayfayı birazdan yenile.</p>".to_string(),
    };
    let content = match owner {
        Some(false) => format!(
            "<div class=\"emoji\">🎉</div>\
             <h1>Sezi sunucun hazır ve çalışıyor</h1>\
             <p>Bu sunucu şu an boş — kurulumu tamamlayan ilk kişi sunucu sahibi olur.</p>\
             {addr_box}\
             <p>Sezi uygulamasında <b>“Sunucu ekle → Kendi sunucunu kur”</b> adımına bu adresi yapıştır — kuruluş kodu otomatik alınır.</p>\
             {code_box}"
        ),
        Some(true) => format!(
            "<div class=\"emoji\">✅</div>\
             <h1>Bu Sezi sunucusu aktif</h1>\
             <p>Katılmak için sunucu sahibinden <b>davet kodu</b> iste.</p>\
             {addr_box}"
        ),
        // D1-hatası: durum iddiasız nötr metin (fail-open).
        None => format!(
            "<div class=\"emoji\">🟠</div>\
             <h1>Sezi sunucusu</h1>\
             <p>Sunucu çalışıyor. Katılım durumu şu an okunamadı — Sezi uygulamasından bu adrese bağlanmayı deneyebilirsin.</p>\
             {addr_box}"
        ),
    };
    PAGE.replace("__CONTENT__", &content)
}

/// Minimal HTML-escape (origin savunmacı olarak escape'lenir; origin ASCII
/// scheme://host[:port] döndürür ama Host-header kaynaklı olduğundan körü
/// körüne gömülmez).
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://sezi-ornek.workers.dev";
    /// Gerçek genesis 24-char b64u; test için ayırt-edici sabit yeter.
    const KOD: &str = "GENESIS_ORNEK_KOD_24chr0";

    #[test]
    fn taze_kurulum_sayfasi_yonerge_adres_ve_kurulus_kodu_icerir() {
        let html = render_welcome(Some(false), ORIGIN, Some(KOD));
        assert!(html.contains("hazır ve çalışıyor"));
        assert!(html.contains("Kendi sunucunu kur"));
        assert!(html.contains(ORIGIN));
        assert!(html.contains("charset=\"utf-8\""));
        assert!(html.contains("otomatik alınır"), "app-yolu yönergesi kalır");
        // Hasan-kararı 2026-07-07: owner-YOKKEN kuruluş kodu SAYFADA GÖRÜNÜR
        // (görünür yedek-yol; kod bu durumda /bootstrap'tan zaten public).
        assert!(html.contains(KOD), "kuruluş kodu sayfada gösterilmeli");
        assert!(html.contains("Kuruluş kodu"));
        assert!(html.contains("ilk kaydolan"), "sahiplenme uyarısı");
        assert!(html.contains("yedek"), "yedek-yol uyarısı");
        assert!(!html.contains("alınamadı"), "kod varken fail-open satırı yok");
    }

    /// FAIL-OPEN: kod alınamazsa sayfa YİNE döner; kod kutusu yerine yenile-satırı.
    #[test]
    fn taze_kurulum_kod_alinamazsa_yenile_satiri() {
        let html = render_welcome(Some(false), ORIGIN, None);
        assert!(html.contains("hazır ve çalışıyor"), "sayfa yine tam döner");
        assert!(html.contains("alınamadı"));
        assert!(html.contains("yenile"));
        assert!(!html.contains("id=\"gcode\""), "kod kutusu gösterilmez");
    }

    #[test]
    fn aktif_sunucu_sayfasi_davet_yonergesi_icerir_kod_asla_sizmaz() {
        // Savunmacı kilit: genesis yanlışlıkla Some geçse bile owner-VAR
        // kolunda kod ASLA gömülmez (render tek-otorite).
        let html = render_welcome(Some(true), ORIGIN, Some(KOD));
        assert!(html.contains("Sezi sunucusu aktif"));
        assert!(html.contains("davet kodu"));
        // Aktif sunucuda kurulum-yönergesi GÖSTERİLMEZ (genesis kapısı kapandı).
        assert!(!html.contains("Kendi sunucunu kur"));
        assert!(!html.contains(KOD), "owner-VAR: kuruluş kodu sızmaz");
        assert!(!html.contains("Kuruluş kodu"));
    }

    #[test]
    fn d1_hatasi_notr_sayfa_doner_fail_open_kod_sizmaz() {
        let html = render_welcome(None, ORIGIN, Some(KOD));
        assert!(html.contains("Sezi sunucusu"));
        assert!(html.contains("okunamadı"));
        // Nötr sayfa durum İDDİA ETMEZ: ne "hazır" ne "aktif".
        assert!(!html.contains("hazır ve çalışıyor"));
        assert!(!html.contains("sunucusu aktif"));
        // D1-hata kolunda kod ASLA gömülmez (owner-durumu bilinmiyor).
        assert!(!html.contains(KOD), "D1-hata: kuruluş kodu sızmaz");
    }

    #[test]
    fn origin_ve_kod_html_escape_leniyor() {
        let html = render_welcome(Some(false), "https://a<script>b", Some("k<img>d"));
        assert!(!html.contains("a<script>b"));
        assert!(html.contains("a&lt;script&gt;b"));
        assert!(!html.contains("k<img>d"));
        assert!(html.contains("k&lt;img&gt;d"));
        assert_eq!(html_escape(r#"<a href="x">&"#), "&lt;a href=&quot;x&quot;&gt;&amp;");
    }

    #[test]
    fn sayfa_iskeleti_tek_enjeksiyon_noktasi_dolduruluyor() {
        for (owner, genesis) in
            [(Some(true), None), (Some(false), Some(KOD)), (Some(false), None), (None, None)]
        {
            let html = render_welcome(owner, ORIGIN, genesis);
            assert!(!html.contains("__CONTENT__"), "placeholder dolmalı");
            assert!(html.contains("prefers-color-scheme: dark"), "koyu tema desteği");
            assert!(html.starts_with("<!doctype html>"));
        }
    }
}
