//! The browser half of the invite page: what a person who opened `<base>/<CODE>` reads.
//!
//! LANGUAGE: like `welcome.rs`, the copy here is a PRODUCT SURFACE rendered here and served
//! straight to a browser, never crossing into the app — so its Turkish is translation, not source
//! language, and is exempt from the English-source rule in the same way. Both languages live in
//! [`Copy`], two consts, so a missing translation is a compile error.
//!
//! The shell (palette, card, dark theme) is the welcome page's (`welcome::PAGE`): one look for the
//! two pages a browser can reach. No external resources, no tracking; the only script is the copy
//! button, which reads its text back out of the DOM.
//!
//! There is no app link to tap: the app registers no URL scheme and no verified link, so the page
//! hands over what the app's server door does read — the projector URL itself (the core's
//! `parse_invite`) — with a copy button, and the code to type on another device.

use super::lookup::{InviteKind, InviteView};
use crate::welcome::{html_escape, Lang, PAGE};

/// Every sentence on the invite page, in one language. Fields that carry `{}` are filled with
/// HTML-escaped values; fields that carry `<b>` are written per language because the emphasis
/// does not fall on the same words in a translation.
pub(crate) struct Copy {
    html_lang: &'static str,
    foot: &'static str,
    /// `{}` = the server's name.
    title: &'static str,
    /// `{}` = the inviter's display name.
    invited_by: &'static str,
    /// For an invite whose minter set no display name.
    invited: &'static str,
    class_badge: &'static str,
    class_untitled: &'static str,
    /// `{}` = the group's name.
    landing: &'static str,
    landing_approval: &'static str,
    /// `{}` = a count.
    seats_left: &'static str,
    /// `{}` = a count.
    expires_days: &'static str,
    /// `{}` = a count.
    expires_hours: &'static str,
    /// Carries `<b>` around the in-app place to paste into.
    how_to: &'static str,
    code_label: &'static str,
    copy_link: &'static str,
    copied: &'static str,
    no_app: &'static str,
    gone_title: &'static str,
    gone_body: &'static str,
    busy_title: &'static str,
    /// `{}` = minutes.
    busy_body: &'static str,
}

pub(crate) const EN: Copy = Copy {
    html_lang: "en",
    foot: "Sezi — self-hosted, end-to-end encrypted group platform",
    title: "You are invited to {}",
    invited_by: "<b>{}</b> invited you.",
    invited: "Someone on this server invited you.",
    class_badge: "Class invite",
    class_untitled: "Untitled",
    landing: "You also join the group <b>{}</b>",
    landing_approval: " once one of its admins approves.",
    seats_left: "{} seats left",
    expires_days: "valid for {} more days",
    expires_hours: "valid for {} more hours",
    how_to: "Open the Sezi app and paste this link where it asks for a server — <b>Add server</b> if you already use Sezi.",
    code_label: "Or type the code",
    copy_link: "Copy link",
    copied: "Copied ✓",
    no_app: "No Sezi app yet? Ask whoever invited you where to get it.",
    gone_title: "This invite cannot be used",
    gone_body: "It may have been used up, expired or withdrawn, or the code was typed wrong. Ask whoever invited you for a new one.",
    busy_title: "Too many tries from this network",
    busy_body: "Wait {} min, then reload this page.",
};

pub(crate) const TR: Copy = Copy {
    html_lang: "tr",
    foot: "Sezi — self-hosted, uçtan uca şifreli grup platformu",
    title: "{} sunucusuna davetlisin",
    invited_by: "<b>{}</b> seni davet etti.",
    invited: "Bu sunucudan biri seni davet etti.",
    class_badge: "Sınıf daveti",
    class_untitled: "Adsız",
    landing: "<b>{}</b> grubuna da katılırsın",
    landing_approval: "; grubun yöneticilerinden biri onaylayınca.",
    seats_left: "{} kişilik yer kaldı",
    expires_days: "{} gün daha geçerli",
    expires_hours: "{} saat daha geçerli",
    how_to: "Sezi uygulamasını aç ve sunucu sorulan yere bu bağlantıyı yapıştır — Sezi'yi zaten kullanıyorsan <b>Sunucu ekle</b>.",
    code_label: "Ya da kodu yaz",
    copy_link: "Bağlantıyı kopyala",
    copied: "Kopyalandı ✓",
    no_app: "Sezi uygulaman yok mu? Seni davet edene nereden indireceğini sor.",
    gone_title: "Bu davet kullanılamıyor",
    gone_body: "Kullanılmış, süresi dolmuş ya da geri alınmış olabilir; kod yanlış da yazılmış olabilir. Seni davet edenden yenisini iste.",
    busy_title: "Bu ağdan çok fazla deneme yapıldı",
    busy_body: "{} dk bekle, sonra sayfayı yenile.",
};

pub(crate) fn copy_for(lang: Lang) -> &'static Copy {
    match lang {
        Lang::En => &EN,
        Lang::Tr => &TR,
    }
}

/// `{}` → the escaped value. One placeholder per sentence, so a plain replace is exact.
fn fill(template: &str, value: &str) -> String {
    template.replacen("{}", &html_escape(value), 1)
}

fn page(c: &Copy, content: &str) -> String {
    PAGE.replace("__LANG__", c.html_lang)
        .replace("__FOOT__", c.foot)
        .replace("__CONTENT__", content)
}

/// "valid for 3 more days" / "valid for 5 more hours" — never "0": an invite with less than an
/// hour left says one.
fn expiry_line(c: &Copy, expires_at: i64, now: i64) -> String {
    let left = (expires_at - now).max(0);
    const HOUR: i64 = 3_600;
    if left >= 48 * HOUR {
        fill(c.expires_days, &(left / (24 * HOUR)).to_string())
    } else {
        fill(c.expires_hours, &(left / HOUR).max(1).to_string())
    }
}

/// The page for a usable invite. `link` is the URL the person opened (origin + `/` + the code in
/// display form) and `code` the code in display form — both what the visitor already holds.
pub(crate) fn render_invite(
    lang: Lang,
    view: &InviteView,
    link: &str,
    code: &str,
    now: i64,
) -> String {
    let c = copy_for(lang);
    let mut content = format!(
        "<div class=\"emoji\">💌</div><h1>{}</h1>",
        fill(c.title, &view.server_name)
    );
    match view.kind {
        InviteKind::Class => {
            let label = view.label.as_deref().unwrap_or(c.class_untitled);
            content.push_str(&format!(
                "<p>{} · <b>{}</b></p>",
                c.class_badge,
                html_escape(label)
            ));
        }
        InviteKind::Personal => match view.inviter_name.as_deref() {
            Some(name) => content.push_str(&format!("<p>{}</p>", fill(c.invited_by, name))),
            None => content.push_str(&format!("<p>{}</p>", c.invited)),
        },
    }
    if let Some(group) = view.landing_group.as_deref() {
        let tail = if view.landing_needs_approval {
            c.landing_approval
        } else {
            "."
        };
        content.push_str(&format!("<p>{}{tail}</p>", fill(c.landing, group)));
    }
    let mut facts = Vec::new();
    if let Some(left) = view.seats_left {
        facts.push(fill(c.seats_left, &left.to_string()));
    }
    facts.push(expiry_line(c, view.expires_at, now));
    content.push_str(&format!("<p>{}</p>", facts.join(" · ")));
    let (copied, copy_link) = (c.copied, c.copy_link);
    content.push_str(&format!(
        r#"<p>{}</p><div class="addr"><code id="link">{}</code><button onclick="navigator.clipboard.writeText(document.getElementById('link').textContent).then(()=>{{this.textContent='{copied}'}})">{copy_link}</button></div><p class="lbl">{}</p><div class="addr"><code>{}</code></div><p>{}</p>"#,
        c.how_to,
        html_escape(link),
        c.code_label,
        html_escape(code),
        c.no_app,
    ));
    page(c, &content)
}

/// The page for every invite that cannot be used — unknown, spent, expired, withdrawn or full.
/// One page for all of them, deliberately: it must not tell a guesser which it hit.
pub(crate) fn render_unavailable(lang: Lang) -> String {
    let c = copy_for(lang);
    page(
        c,
        &format!(
            "<div class=\"emoji\">🔒</div><h1>{}</h1><p>{}</p>",
            c.gone_title, c.gone_body
        ),
    )
}

/// The page for an address that has asked too often.
pub(crate) fn render_rate_limited(lang: Lang, retry_after_s: u64) -> String {
    let c = copy_for(lang);
    let minutes = retry_after_s.div_ceil(60).max(1);
    page(
        c,
        &format!(
            "<div class=\"emoji\">⏳</div><h1>{}</h1><p>{}</p>",
            c.busy_title,
            fill(c.busy_body, &minutes.to_string())
        ),
    )
}
