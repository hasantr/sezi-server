//! The browser page: it says what the invite is in the visitor's language, hands over the link the
//! app reads, escapes everything a person typed, loads nothing from anywhere, and says the same
//! thing about every invite that cannot be used.

use super::html::{render_invite, render_rate_limited, render_unavailable};
use super::lookup::{InviteKind, InviteView};
use crate::welcome::Lang;

const NOW: i64 = 1_780_000_000;
const LINK: &str = "https://sezi.kampus.edu.tr/K7QM-4827";
const CODE: &str = "K7QM-4827";
const ALL: [Lang; 2] = [Lang::En, Lang::Tr];

fn personal() -> InviteView {
    InviteView {
        kind: InviteKind::Personal,
        server_name: "Kampüs Sezi".into(),
        inviter_name: Some("Ayşe Demir".into()),
        label: None,
        landing_group: None,
        landing_needs_approval: false,
        seats_left: None,
        expires_at: NOW + 3 * 86_400 + 10,
    }
}

fn class() -> InviteView {
    InviteView {
        kind: InviteKind::Class,
        server_name: "Kampüs Sezi".into(),
        inviter_name: Some("Ayşe Demir".into()),
        label: Some("BIL203 · 2026 fall".into()),
        landing_group: Some("BİL203 Ders".into()),
        landing_needs_approval: true,
        seats_left: Some(37),
        expires_at: NOW + 5 * 3_600 + 10,
    }
}

#[test]
fn a_personal_invite_page_names_the_server_the_inviter_and_the_way_in() {
    for lang in ALL {
        let html = render_invite(lang, &personal(), LINK, CODE, NOW);
        assert!(html.contains("Kampüs Sezi"));
        assert!(html.contains("Ayşe Demir"));
        assert!(
            html.contains(LINK),
            "the link the app reads is there to copy"
        );
        assert!(
            html.contains(CODE),
            "and the code to type on another device"
        );
        assert!(html.contains(&format!(
            "<html lang=\"{}\">",
            match lang {
                Lang::En => "en",
                Lang::Tr => "tr",
            }
        )));
        let days = match lang {
            Lang::En => "valid for 3 more days",
            Lang::Tr => "3 gün daha geçerli",
        };
        assert!(html.contains(days), "{lang:?}");
    }
}

#[test]
fn a_class_invite_page_names_itself_its_group_and_its_seats() {
    for lang in ALL {
        let html = render_invite(lang, &class(), LINK, CODE, NOW);
        assert!(html.contains("BIL203 · 2026 fall"));
        assert!(html.contains("BİL203 Ders"));
        let (seats, hours) = match lang {
            Lang::En => ("37 seats left", "valid for 5 more hours"),
            Lang::Tr => ("37 kişilik yer kaldı", "5 saat daha geçerli"),
        };
        assert!(html.contains(seats) && html.contains(hours), "{lang:?}");
    }
}

/// Every name on the page was typed by a person somewhere — the server's owner, the inviter, a
/// group admin — so every one is escaped.
#[test]
fn every_typed_name_is_escaped() {
    let mut view = class();
    view.server_name = "<script>alert(1)</script>".into();
    view.label = Some("<img src=x onerror=alert(2)>".into());
    view.landing_group = Some("\"><b>g</b>".into());
    let html = render_invite(Lang::En, &view, "https://a/<x>", CODE, NOW);
    for raw in [
        "<script>alert(1)",
        "<img src=x",
        "\"><b>g</b>",
        "https://a/<x>",
    ] {
        assert!(!html.contains(raw), "{raw} reached the page unescaped");
    }
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    let mut p = personal();
    p.inviter_name = Some("<i>x</i>".into());
    assert!(!render_invite(Lang::Tr, &p, LINK, CODE, NOW).contains("<i>x</i>"));
}

#[test]
fn an_invite_whose_inviter_set_no_name_still_reads() {
    let mut view = personal();
    view.inviter_name = None;
    for lang in ALL {
        let html = render_invite(lang, &view, LINK, CODE, NOW);
        assert!(html.contains(match lang {
            Lang::En => "Someone on this server invited you.",
            Lang::Tr => "Bu sunucudan biri seni davet etti.",
        }));
    }
}

/// Light and closed: nothing is fetched from anywhere — no stylesheet, image, font or script
/// source — so opening the page tells no third party anything.
#[test]
fn the_page_loads_nothing_from_anywhere() {
    for lang in ALL {
        for html in [
            render_invite(lang, &class(), LINK, CODE, NOW),
            render_invite(lang, &personal(), LINK, CODE, NOW),
            render_unavailable(lang),
            render_rate_limited(lang, 90),
        ] {
            for needle in ["src=", "<link", "@import", "url(", "<iframe"] {
                assert!(!html.contains(needle), "{needle} on the page");
            }
            for placeholder in ["__CONTENT__", "__LANG__", "__FOOT__", "{}"] {
                assert!(!html.contains(placeholder), "{placeholder} left unfilled");
            }
            assert!(html.starts_with("<!doctype html>"));
        }
    }
}

#[test]
fn the_unavailable_page_names_no_reason_and_no_server() {
    for lang in ALL {
        let html = render_unavailable(lang);
        assert!(html.contains(match lang {
            Lang::En => "This invite cannot be used",
            Lang::Tr => "Bu davet kullanılamıyor",
        }));
        assert!(!html.contains("Kampüs Sezi"));
    }
}

#[test]
fn the_rate_limited_page_counts_whole_minutes_up() {
    assert!(render_rate_limited(Lang::En, 1).contains("Wait 1 min,"));
    assert!(render_rate_limited(Lang::En, 61).contains("Wait 2 min,"));
    assert!(render_rate_limited(Lang::Tr, 300).contains("5 dk bekle"));
}
