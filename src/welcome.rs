//! Welcome page — `GET /` (part of the 2026-07-06 hardening package).
//!
//! FIELD RATIONALE: on a fresh install, clicking the workers.dev address in a browser
//! used to show a 404 or bare JSON, which answers "is my server running?" with zero
//! confidence. This page gives a human-readable answer in three states, in English or Turkish
//! (`Lang::from_accept_language`, defaulting to English):
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
//!
//! LANGUAGE: the copy here is a PRODUCT SURFACE, not source language, and is the ONE place in the
//! Rust tree exempt from the English-source rule (K6). Everywhere else, Turkish in Rust was a
//! problem because the text had to cross into the app and could no longer be translated once it
//! had. This page never crosses anything: it is rendered here and served straight to a browser —
//! the same category as an ARB value, which K6 explicitly does not touch. Do not sweep these
//! strings and do not count them in the K6 numbers.
//!
//! It used to be Turkish-only with `<html lang="tr">` hard-coded, so anyone self-hosting from
//! outside Turkey was greeted in a language they may not read — on the very page whose whole job is
//! to answer "is my server running?". Both languages now live in [`Copy`], picked per request:
//! an explicit `?lang=` wins, otherwise `Accept-Language` decides, otherwise English (the language
//! an arbitrary visitor is likeliest to read; a Turkish browser sends `tr` and still gets Turkish).
//! Adding a third language means one more `Copy` const and one more arm in `Lang::parse`.

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
    let url = req.url().ok();
    let origin = url
        .as_ref()
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_default();
    // An explicit `?lang=` beats the header: it makes the page linkable in a chosen language
    // (support threads, docs) and gives a visitor whose browser is set to a third language a
    // way out. Anything unrecognised falls through to the header.
    let forced = url
        .as_ref()
        .and_then(|u| u.query_pairs().find(|(k, _)| k == "lang").map(|(_, v)| v.into_owned()))
        .and_then(|v| Lang::from_tag(&v));
    let lang = forced.unwrap_or_else(|| {
        Lang::from_accept_language(req.headers().get("accept-language").ok().flatten().as_deref())
    });
    Response::from_html(render_welcome(lang, owner, &origin, genesis.as_deref()))
}

/// The languages the welcome page speaks. English is the default for an unrecognised or absent
/// `Accept-Language`; a Turkish browser sends `tr` and gets Turkish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lang {
    En,
    Tr,
}

impl Lang {
    /// A single language tag → `Lang`, matching on the PRIMARY subtag so `tr-TR`, `tr_TR` and
    /// `TR` all land on Turkish. Unknown → `None` (the caller decides what that means).
    fn from_tag(tag: &str) -> Option<Lang> {
        let primary = tag
            .trim()
            .split(['-', '_'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        match primary.as_str() {
            "tr" => Some(Lang::Tr),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    /// Negotiate from an `Accept-Language` header (`tr-TR,tr;q=0.9,en-US;q=0.8`). Picks the
    /// highest-q tag we actually speak; ties keep header order, which is what a browser means
    /// by listing them. A missing header, `*`, or only languages we do not speak → English.
    ///
    /// Deliberately hand-rolled rather than strict RFC 4647: this decides which of two texts to
    /// show a browser, so a malformed q or an exotic tag must degrade to a readable page, never
    /// to an error.
    fn from_accept_language(header: Option<&str>) -> Lang {
        let Some(header) = header else {
            return Lang::En;
        };
        let mut best: Option<(f32, Lang)> = None;
        for part in header.split(',') {
            let mut bits = part.split(';');
            let Some(lang) = bits.next().and_then(Lang::from_tag) else {
                continue;
            };
            // q defaults to 1.0 and an unparsable q is treated as 0.0 rather than as a
            // full-weight preference, so junk cannot outrank a well-formed entry.
            let q = bits
                .find_map(|b| b.trim().strip_prefix("q=").map(|v| v.trim().parse::<f32>().unwrap_or(0.0)))
                .unwrap_or(1.0);
            if best.is_none_or(|(best_q, _)| q > best_q) {
                best = Some((q, lang));
            }
        }
        best.map(|(_, l)| l).unwrap_or(Lang::En)
    }

    fn copy(self) -> &'static Copy {
        match self {
            Lang::En => &EN,
            Lang::Tr => &TR,
        }
    }
}

/// Every piece of prose on the page, in one language. Two consts implement it, so a missing
/// translation is a COMPILE error rather than a sentence that silently stays in the other
/// language — the failure mode a `HashMap<&str, &str>` would have had.
pub(crate) struct Copy {
    html_lang: &'static str,
    foot: &'static str,
    copy_address: &'static str,
    copied: &'static str,
    genesis_label: &'static str,
    copy_code: &'static str,
    /// Carries `<b>` markup; written per language because the emphasis does not fall on the
    /// same words in a translation.
    genesis_note: &'static str,
    genesis_unavailable: &'static str,
    fresh_title: &'static str,
    fresh_body: &'static str,
    /// Carries `<b>` around the in-app menu path.
    fresh_paste: &'static str,
    active_title: &'static str,
    /// Carries `<b>` around "invite code".
    active_body: &'static str,
    neutral_title: &'static str,
    neutral_body: &'static str,
}

const EN: Copy = Copy {
    html_lang: "en",
    foot: "Sezi — self-hosted, end-to-end encrypted group platform",
    copy_address: "Copy address",
    copied: "Copied ✓",
    genesis_label: "Genesis code",
    copy_code: "Copy code",
    genesis_note: "Whoever <b>signs up first</b> with this code becomes the server's owner; the code stops working the moment the server is claimed. The app normally fetches it by itself — this is the fallback.",
    genesis_unavailable: "The genesis code could not be fetched right now — reload the page in a moment.",
    fresh_title: "Your Sezi server is up and running",
    fresh_body: "This server is empty — the first person to finish setup becomes its owner.",
    fresh_paste: "In the Sezi app, paste this address into <b>“Add server → Set up your own”</b> — the genesis code is fetched automatically.",
    active_title: "This Sezi server is active",
    active_body: "Ask the server's owner for an <b>invite code</b> to join.",
    neutral_title: "Sezi server",
    neutral_body: "The server is running. Its join state could not be read just now — you can try connecting to this address from the Sezi app.",
};

const TR: Copy = Copy {
    html_lang: "tr",
    foot: "Sezi — self-hosted, uçtan uca şifreli grup platformu",
    copy_address: "Adresi kopyala",
    copied: "Kopyalandı ✓",
    genesis_label: "Kuruluş kodu",
    copy_code: "Kodu kopyala",
    genesis_note: "Bu kodla <b>ilk kaydolan</b> sunucunun sahibi olur; sunucu sahiplenince kod geçersizleşir. Uygulama bu kodu normalde kendisi alır — burası yedek yol.",
    genesis_unavailable: "Kuruluş kodu şu an alınamadı — sayfayı birazdan yenile.",
    fresh_title: "Sezi sunucun hazır ve çalışıyor",
    fresh_body: "Bu sunucu şu an boş — kurulumu tamamlayan ilk kişi sunucu sahibi olur.",
    fresh_paste: "Sezi uygulamasında <b>“Sunucu ekle → Kendi sunucunu kur”</b> adımına bu adresi yapıştır — kuruluş kodu otomatik alınır.",
    active_title: "Bu Sezi sunucusu aktif",
    active_body: "Katılmak için sunucu sahibinden <b>davet kodu</b> iste.",
    neutral_title: "Sezi sunucusu",
    neutral_body: "Sunucu çalışıyor. Katılım durumu şu an okunamadı — Sezi uygulamasından bu adrese bağlanmayı deneyebilirsin.",
};

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
/// HTML-escaped. `__LANG__` and `__FOOT__` come from the negotiated [`Copy`] — `lang` on
/// `<html>` is what tells a screen reader and a browser translator which language they are
/// looking at, so it has to move with the copy.
const PAGE: &str = r#"<!doctype html>
<html lang="__LANG__">
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
<p class="foot">__FOOT__</p>
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
fn render_welcome(lang: Lang, owner: Option<bool>, origin: &str, genesis: Option<&str>) -> String {
    let c = lang.copy();
    let addr = html_escape(origin);
    // The copy button reads the address back out of the DOM (`#addr`), so no separate
    // JS-string escaping is needed. On an old browser without the clipboard API the
    // button just does nothing, and the address can still be selected and copied by hand.
    let (copied, copy_address) = (c.copied, c.copy_address);
    let addr_box = format!(
        r#"<div class="addr"><code id="addr">{addr}</code><button onclick="navigator.clipboard.writeText(document.getElementById('addr').textContent).then(()=>{{this.textContent='{copied}'}})">{copy_address}</button></div>"#
    );
    // The genesis-code box (used only in the fresh-install branch). The code is b64u,
    // but it is HTML-escaped defensively anyway; the copy button follows the same
    // read-from-DOM pattern as the address one (`#gcode`). FAIL-OPEN: with no code the
    // box is replaced by a "refresh in a moment" line and the page still renders.
    let code_box = match genesis {
        Some(code) => {
            let code = html_escape(code);
            let (label, copy_code, note) = (c.genesis_label, c.copy_code, c.genesis_note);
            format!(
                r#"<p class="lbl">{label}</p><div class="addr"><code id="gcode">{code}</code><button onclick="navigator.clipboard.writeText(document.getElementById('gcode').textContent).then(()=>{{this.textContent='{copied}'}})">{copy_code}</button></div><p>{note}</p>"#
            )
        }
        None => format!("<p>{}</p>", c.genesis_unavailable),
    };
    let content = match owner {
        Some(false) => format!(
            "<div class=\"emoji\">🎉</div><h1>{}</h1><p>{}</p>{addr_box}<p>{}</p>{code_box}",
            c.fresh_title, c.fresh_body, c.fresh_paste
        ),
        Some(true) => format!(
            "<div class=\"emoji\">✅</div><h1>{}</h1><p>{}</p>{addr_box}",
            c.active_title, c.active_body
        ),
        // D1 error: neutral copy that asserts nothing about state (fail-open).
        None => format!(
            "<div class=\"emoji\">🟠</div><h1>{}</h1><p>{}</p>{addr_box}",
            c.neutral_title, c.neutral_body
        ),
    };
    PAGE.replace("__LANG__", c.html_lang)
        .replace("__FOOT__", c.foot)
        .replace("__CONTENT__", &content)
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

    const ORIGIN: &str = "https://sezi-example.workers.dev";
    /// A real genesis code is 24 b64u chars; for tests any distinctive constant will do.
    const CODE: &str = "GENESIS_EXAMPLE_CODE_24c";
    /// Every language the page can be served in — the state tests run against ALL of them, so a
    /// branch that renders correctly in one language and not the other cannot pass.
    const ALL: [Lang; 2] = [Lang::En, Lang::Tr];

    #[test]
    fn fresh_install_page_shows_instructions_address_and_genesis_code() {
        for lang in ALL {
            let c = lang.copy();
            let html = render_welcome(lang, Some(false), ORIGIN, Some(CODE));
            assert!(html.contains(c.fresh_title));
            assert!(html.contains(c.fresh_paste), "the in-app path instruction stays");
            assert!(html.contains(ORIGIN));
            assert!(html.contains("charset=\"utf-8\""));
            // Hasan's 2026-07-07 call: while there is NO owner the genesis code IS shown on
            // the page (visible fallback; in that state it is already public via /bootstrap).
            assert!(html.contains(CODE), "the genesis code must be shown");
            assert!(html.contains(c.genesis_label));
            assert!(html.contains(c.genesis_note), "the claim-warning stays");
            assert!(!html.contains(c.genesis_unavailable), "no fail-open line when the code is there");
        }
    }

    /// FAIL-OPEN: if the code cannot be obtained the page STILL renders, with a
    /// refresh line in place of the code box.
    #[test]
    fn fresh_install_shows_a_retry_line_when_the_code_is_unavailable() {
        for lang in ALL {
            let c = lang.copy();
            let html = render_welcome(lang, Some(false), ORIGIN, None);
            assert!(html.contains(c.fresh_title), "the page still renders in full");
            assert!(html.contains(c.genesis_unavailable));
            assert!(!html.contains("id=\"gcode\""), "the code box is not shown");
        }
    }

    #[test]
    fn active_server_page_shows_invite_guidance_and_never_leaks_the_code() {
        for lang in ALL {
            let c = lang.copy();
            // Defensive lock: even if genesis is accidentally passed as Some, the
            // owner-exists branch NEVER embeds the code (render is the single authority).
            let html = render_welcome(lang, Some(true), ORIGIN, Some(CODE));
            assert!(html.contains(c.active_title));
            assert!(html.contains(c.active_body));
            // An active server does NOT show the setup instructions (the genesis gate closed).
            assert!(!html.contains(c.fresh_paste));
            assert!(!html.contains(CODE), "owner EXISTS: the genesis code does not leak");
            assert!(!html.contains(c.genesis_label));
        }
    }

    #[test]
    fn a_d1_error_returns_a_neutral_page_fail_open_without_leaking_the_code() {
        for lang in ALL {
            let c = lang.copy();
            let html = render_welcome(lang, None, ORIGIN, Some(CODE));
            assert!(html.contains(c.neutral_body));
            // The neutral page CLAIMS nothing: neither "ready" nor "active".
            assert!(!html.contains(c.fresh_title));
            assert!(!html.contains(c.active_title));
            // The D1-error branch NEVER embeds the code (owner state is unknown).
            assert!(!html.contains(CODE), "D1 error: the genesis code does not leak");
        }
    }

    #[test]
    fn origin_and_code_are_html_escaped() {
        let html = render_welcome(Lang::En, Some(false), "https://a<script>b", Some("k<img>d"));
        assert!(!html.contains("a<script>b"));
        assert!(html.contains("a&lt;script&gt;b"));
        assert!(!html.contains("k<img>d"));
        assert!(html.contains("k&lt;img&gt;d"));
        assert_eq!(html_escape(r#"<a href="x">&"#), "&lt;a href=&quot;x&quot;&gt;&amp;");
    }

    #[test]
    fn the_page_skeleton_fills_every_injection_point() {
        for lang in ALL {
            for (owner, genesis) in
                [(Some(true), None), (Some(false), Some(CODE)), (Some(false), None), (None, None)]
            {
                let html = render_welcome(lang, owner, ORIGIN, genesis);
                for placeholder in ["__CONTENT__", "__LANG__", "__FOOT__"] {
                    assert!(!html.contains(placeholder), "{placeholder} must be filled");
                }
                assert!(html.contains("prefers-color-scheme: dark"), "dark theme support");
                assert!(html.starts_with("<!doctype html>"));
            }
        }
    }

    /// The `lang` attribute must MOVE with the copy: a page whose prose is English while
    /// `<html lang="tr">` stays behind tells a screen reader and a browser translator the wrong
    /// thing, which is the bug that hard-coding it caused in the first place.
    #[test]
    fn the_html_lang_attribute_matches_the_rendered_copy() {
        assert!(render_welcome(Lang::En, Some(true), ORIGIN, None).contains(r#"<html lang="en">"#));
        assert!(render_welcome(Lang::Tr, Some(true), ORIGIN, None).contains(r#"<html lang="tr">"#));
    }

    #[test]
    fn accept_language_picks_the_highest_q_language_we_speak() {
        let pick = Lang::from_accept_language;
        assert_eq!(pick(Some("tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7")), Lang::Tr);
        assert_eq!(pick(Some("en-GB,en;q=0.9")), Lang::En);
        // q ORDER decides, not header order.
        assert_eq!(pick(Some("en;q=0.4,tr;q=0.9")), Lang::Tr);
        assert_eq!(pick(Some("tr;q=0.3,en;q=0.8")), Lang::En);
        // A language we do not speak is skipped rather than winning by being first.
        assert_eq!(pick(Some("de-DE,de;q=0.9,tr;q=0.5")), Lang::Tr);
    }

    /// Negative side: anything we cannot read must land on English rather than on a panic, an
    /// empty page, or a coin flip.
    #[test]
    fn an_unreadable_accept_language_falls_back_to_english() {
        let pick = Lang::from_accept_language;
        assert_eq!(pick(None), Lang::En, "no header at all");
        assert_eq!(pick(Some("")), Lang::En);
        assert_eq!(pick(Some("*")), Lang::En);
        assert_eq!(pick(Some("de,fr;q=0.8,ja")), Lang::En, "only languages we do not speak");
        assert_eq!(pick(Some("tr;q=notanumber")), Lang::Tr, "a junk q still beats no match");
        // A junk q must not outrank a well-formed one (it is read as 0.0, not as 1.0).
        assert_eq!(pick(Some("tr;q=zzz,en;q=0.1")), Lang::En);
    }

    #[test]
    fn a_language_tag_matches_on_its_primary_subtag() {
        for tag in ["tr", "TR", "tr-TR", "tr_TR", " tr-tr "] {
            assert_eq!(Lang::from_tag(tag), Some(Lang::Tr), "{tag}");
        }
        for tag in ["en", "en-US", "EN-gb"] {
            assert_eq!(Lang::from_tag(tag), Some(Lang::En), "{tag}");
        }
        for tag in ["de", "", "*", "turkish"] {
            assert_eq!(Lang::from_tag(tag), None, "{tag}");
        }
    }
}
