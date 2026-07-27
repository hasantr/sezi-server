//! Welcome page — `GET /` (part of the 2026-07-06 hardening package).
//!
//! FIELD RATIONALE: on a fresh install, clicking the workers.dev address in a browser
//! used to show a 404 or bare JSON, which answers "is my server running?" with zero
//! confidence. This page gives a human-readable answer in three states (the rendered
//! copy is Turkish):
//!   - NO owner (fresh install): "your server is ready" + copy-the-address + paste-it
//!     into-the-app instructions + the GENESIS CODE (Hasan's 2026-07-07 call: a visible
//!     fallback for when the app's automatic genesis fetch fails). Security-equivalent:
//!     while there is no owner that code is already public via `GET /bootstrap` — a gate
//!     that closes itself — so showing it here opens no extra surface. Once an owner
//!     exists the code is NEVER shown again.
//!   - Owner EXISTS: "server is active" + how to get an invite code.
//!   - D1 error: FAIL-OPEN neutral copy (the page still renders and claims nothing
//!     about server state).
//!
//! Styling: the MurmurTokens warm-cream palette, matching mobile's palette.dart hexes
//! exactly (page #F1E6D4 / paper #FAF1E6 / ink #201812 / accent #F97316), inline CSS
//! and no external resources — self-contained, in keeping with the closed-server
//! philosophy.

use serde::Deserialize;
use worker::*;

use crate::auth::bootstrap::ensure_genesis_token;
use crate::d1util::d1_text;

/// `GET /` — the welcome page, keyed on owner state. `Response::from_html` sets the
/// `Content-Type: text/html; charset=utf-8` header itself.
pub async fn welcome(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // FAIL-OPEN: if the owner query fails (no D1, transient error) → None → neutral copy.
    let owner = owner_exists(&ctx.env).await;
    // The genesis code is fetched ONLY in the no-owner state, NEVER in the owner-exists
    // or D1-error branches. Same get-or-mint path as /bootstrap, including the M10 race
    // pattern. FAIL-OPEN: if the code cannot be obtained → None → the page still renders,
    // with a "refresh in a moment" line in place of the code box.
    let genesis = if owner == Some(false) {
        match ctx.env.d1("DB") {
            Ok(db) => ensure_genesis_token(&db).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };
    // The address is the request's own origin (scheme://host[:port]) — exactly what the
    // user sees in the browser bar, so it stays correct behind a custom domain too.
    let origin = req
        .url()
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_default();
    Response::from_html(render_welcome(owner, &origin, genesis.as_deref()))
}

/// Does an owner exist? (verify's first-user-becomes-owner rule means an owner row is
/// the marker for "this server has been claimed"; same query family as bootstrap.rs.)
/// Cheap: one indexed SELECT with LIMIT 1. On error → None (fail-open, the page still
/// renders).
///
/// SINGLE AUTHORITY: this is the ONLY place that produces the `owner_exists` bool. The
/// welcome page (`GET /`) and `/server/info` (onboarding's "is it claimed?" probe) read
/// from the SAME SELECT — two divergent definitions of "owner" would be a bug, so
/// nothing is copy-pasted.
pub(crate) async fn owner_exists(env: &Env) -> Option<bool> {
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

/// The page shell — `replace` instead of `format!` so the CSS braces cannot collide
/// with format-string syntax. `__CONTENT__` is the single injection point; the content
/// is assembled in `render_welcome`, and user-supplied input (the origin) is
/// HTML-escaped.
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

/// Build the page content (PURE → unit-testable). `owner`: `Some(false)` = fresh
/// install, `Some(true)` = active server, `None` = D1 error (neutral copy). `genesis`
/// is the genesis code, rendered ONLY in the `Some(false)` branch — in that state the
/// code is already public via /bootstrap, so this is just a visible fallback. In the
/// owner-exists and D1-error branches the caller passes `None` and the code is NEVER
/// embedded.
fn render_welcome(owner: Option<bool>, origin: &str, genesis: Option<&str>) -> String {
    let addr = html_escape(origin);
    // The copy button reads the address back out of the DOM (`#addr`), so no separate
    // JS-string escaping is needed. On an old browser without the clipboard API the
    // button just does nothing, and the address can still be selected and copied by hand.
    let addr_box = format!(
        r#"<div class="addr"><code id="addr">{addr}</code><button onclick="navigator.clipboard.writeText(document.getElementById('addr').textContent).then(()=>{{this.textContent='Kopyalandı ✓'}})">Adresi kopyala</button></div>"#
    );
    // The genesis-code box (used only in the fresh-install branch). The code is b64u,
    // but it is HTML-escaped defensively anyway; the copy button follows the same
    // read-from-DOM pattern as the address one (`#gcode`). FAIL-OPEN: with no code the
    // box is replaced by a "refresh in a moment" line and the page still renders.
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
        // D1 error: neutral copy that asserts nothing about state (fail-open).
        None => format!(
            "<div class=\"emoji\">🟠</div>\
             <h1>Sezi sunucusu</h1>\
             <p>Sunucu çalışıyor. Katılım durumu şu an okunamadı — Sezi uygulamasından bu adrese bağlanmayı deneyebilirsin.</p>\
             {addr_box}"
        ),
    };
    PAGE.replace("__CONTENT__", &content)
}

/// Minimal HTML escaping. The origin is escaped defensively: it resolves to an ASCII
/// scheme://host[:port], but it ultimately derives from the Host header, so it is
/// never embedded blindly.
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
    /// A real genesis code is 24 b64u chars; for tests any distinctive constant will do.
    const KOD: &str = "GENESIS_ORNEK_KOD_24chr0";

    #[test]
    fn taze_kurulum_sayfasi_yonerge_adres_ve_kurulus_kodu_icerir() {
        let html = render_welcome(Some(false), ORIGIN, Some(KOD));
        assert!(html.contains("hazır ve çalışıyor"));
        assert!(html.contains("Kendi sunucunu kur"));
        assert!(html.contains(ORIGIN));
        assert!(html.contains("charset=\"utf-8\""));
        assert!(html.contains("otomatik alınır"), "app-yolu yönergesi kalır");
        // Hasan's 2026-07-07 call: while there is NO owner the genesis code IS shown on
        // the page (visible fallback; in that state it is already public via /bootstrap).
        assert!(html.contains(KOD), "kuruluş kodu sayfada gösterilmeli");
        assert!(html.contains("Kuruluş kodu"));
        assert!(html.contains("ilk kaydolan"), "sahiplenme uyarısı");
        assert!(html.contains("yedek"), "yedek-yol uyarısı");
        assert!(!html.contains("alınamadı"), "kod varken fail-open satırı yok");
    }

    /// FAIL-OPEN: if the code cannot be obtained the page STILL renders, with a
    /// refresh line in place of the code box.
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
        // Defensive lock: even if genesis is accidentally passed as Some, the
        // owner-exists branch NEVER embeds the code (render is the single authority).
        let html = render_welcome(Some(true), ORIGIN, Some(KOD));
        assert!(html.contains("Sezi sunucusu aktif"));
        assert!(html.contains("davet kodu"));
        // An active server does NOT show the setup instructions (the genesis gate closed).
        assert!(!html.contains("Kendi sunucunu kur"));
        assert!(!html.contains(KOD), "owner-VAR: kuruluş kodu sızmaz");
        assert!(!html.contains("Kuruluş kodu"));
    }

    #[test]
    fn d1_hatasi_notr_sayfa_doner_fail_open_kod_sizmaz() {
        let html = render_welcome(None, ORIGIN, Some(KOD));
        assert!(html.contains("Sezi sunucusu"));
        assert!(html.contains("okunamadı"));
        // The neutral page CLAIMS nothing: neither "ready" nor "active".
        assert!(!html.contains("hazır ve çalışıyor"));
        assert!(!html.contains("sunucusu aktif"));
        // The D1-error branch NEVER embeds the code (owner state is unknown).
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
