//! A link's preview card, carried WITH the text that contains the link:
//! `ext.link = {"url", "site", "title", "desc", "img": "<base64 JPEG>", "iw", "ih"}`.
//!
//! Hasan, 2026-10-30: the SENDER's device fetches the page when a link is typed (the WhatsApp
//! way — the sender is about to visit it anyway), and the card travels inside the encrypted
//! message. The receiver and the server never touch the site: fetching on the receiver would tell
//! every site the address and online time of every reader of a link, and the server fetching
//! would show the server every link.
//!
//! The card rides on an ordinary TEXT rather than the older `InnerMessage::LinkPreview` kind, so a
//! message with a link still takes a reply, a mention and an edit like any other text, and a
//! client that knows no cards shows the text with its link. It is believed only while the text
//! still contains its url ([`believed`]): an edit that removes the link takes the card with it.
//!
//! Pure shape checks only; the sender's core fetches (`core/src/link_card_fetch.rs`), the kernel
//! writes the key where a text's ext is built, the projection reads it (`MessageView.link_card`).

/// The key under `ext`.
pub const EXT_KEY: &str = "link";

/// The longest url believed.
pub const MAX_URL: usize = 2048;
/// The site name, title and description are cut to these many characters.
pub const MAX_SITE_CHARS: usize = 80;
pub const MAX_TITLE_CHARS: usize = 200;
pub const MAX_DESC_CHARS: usize = 300;
/// The page's picture, re-encoded by the sender's core: wide enough for a 1.91:1 card.
pub const MAX_IMAGE_BYTES: usize = 24 * 1024;
const MAX_SIDE: u32 = 30_000;

/// A link's card (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkCard {
    pub url: String,
    pub site: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    /// JPEG bytes of the page's picture, and the picture's size as fetched.
    pub image: Option<Vec<u8>>,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
}

impl LinkCard {
    /// The card as it may be sent or believed: `None` when the url is not an http(s) address of
    /// sane length, or when nothing but the url would be drawn; words cut to their limits, blank
    /// ones dropped, a picture that is not a small JPEG dropped (and its size with it).
    pub fn checked(self) -> Option<Self> {
        let url = self.url.trim().to_string();
        if url.len() > MAX_URL || !is_web_url(&url) {
            return None;
        }
        let words = |s: Option<String>, max: usize| {
            s.map(|s| collapse(&s).chars().take(max).collect::<String>())
                .filter(|s| !s.is_empty())
        };
        let image = self
            .image
            .filter(|b| b.len() <= MAX_IMAGE_BYTES && b.starts_with(&[0xFF, 0xD8, 0xFF]));
        let side = |s: Option<u32>| s.filter(|s| (1..=MAX_SIDE).contains(s));
        let (image_width, image_height) = match (&image, side(self.image_width), side(self.image_height)) {
            (Some(_), Some(w), Some(h)) => (Some(w), Some(h)),
            _ => (None, None),
        };
        let card = Self {
            url,
            site: words(self.site, MAX_SITE_CHARS),
            title: words(self.title, MAX_TITLE_CHARS),
            description: words(self.description, MAX_DESC_CHARS),
            image,
            image_width,
            image_height,
        };
        (card.title.is_some() || card.description.is_some() || card.image.is_some()).then_some(card)
    }
}

/// Whitespace runs collapsed to one space, the ends trimmed: a card's words are one line of prose.
fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// An `http://` or `https://` address with something after the scheme that could be a host.
fn is_web_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    match rest {
        Some(rest) => {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            !host.is_empty() && !host.contains(char::is_whitespace) && !host.starts_with('@')
        }
        None => false,
    }
}

/// The endings a bare domain ("adobe.com") is believed with — the same short list the chat's
/// link finder uses (`mobile/lib/src/k7/k7_text_links.dart`), so a card is fetched for exactly
/// the words the bubble draws as a link. A file name ("rapor.pdf") must not become one.
const BARE_ENDINGS: &[&str] = &[
    "com", "net", "org", "io", "app", "dev", "ai", "edu", "gov", "info", "work", "tr", "eu", "de", "uk",
];

/// The first web address in [text], as it would be opened: `https://…` or `http://…`, with the
/// punctuation a sentence puts after a link (`.`, `,`, `)` …) left off. An address written
/// without its scheme — `www.example.com`, or a bare `example.com` with an ending from
/// [BARE_ENDINGS] — is opened as `https://` plus the words as written. `None` when there is none.
pub fn first_link(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|word| {
        let tail = |s: &str| {
            s.trim_end_matches(|c: char| {
                matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}' | '>' | '"' | '\'' | '…')
            })
            .to_string()
        };
        let lower = word.to_ascii_lowercase();
        let url = if let Some(start) = lower.find("http") {
            tail(&word[start..])
        } else {
            let lead = word.trim_start_matches(['(', '[', '{', '<', '"', '\'', '«', '“']);
            let candidate = tail(lead);
            if candidate.contains('@') || !(starts_www(&candidate) || is_bare_domain(&candidate)) {
                return None;
            }
            format!("https://{candidate}")
        };
        (url.len() <= MAX_URL && is_web_url(&url)).then_some(url)
    })
}

fn starts_www(s: &str) -> bool {
    s.len() > 4 && s[..4].eq_ignore_ascii_case("www.")
}

/// `example.com`, `a.b.com.tr/path?q`: dot-separated labels of letters, digits and inner hyphens,
/// the last one an ending from [BARE_ENDINGS].
fn is_bare_domain(s: &str) -> bool {
    let host = s.split(['/', '?', '#']).next().unwrap_or("");
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    labels.len() >= 2
        && labels.iter().all(label_ok)
        && BARE_ENDINGS.contains(&labels[labels.len() - 1].to_ascii_lowercase().as_str())
}

/// Do [body]'s words still hold [url] — as written, or (for an address [first_link] gave a
/// scheme) without its `https://`, standing as a word of its own?
pub fn holds_link(body: &str, url: &str) -> bool {
    if body.contains(url) {
        return true;
    }
    let Some(bare) = url.strip_prefix("https://") else { return false };
    body.match_indices(bare).any(|(at, _)| {
        body[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '.' | '/' | '@' | '-' | '_')))
    })
}

/// The card an `ext` carries, checked ([`LinkCard::checked`]). Not yet compared with the text it
/// rides on — that is [`believed`].
pub fn read(ext: &serde_json::Value) -> Option<LinkCard> {
    let m = ext.get(EXT_KEY)?;
    let text = |k: &str| m.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let side = |k: &str| m.get(k).and_then(|v| u32::try_from(v.as_u64()?).ok());
    let image = m
        .get("img")
        .and_then(|v| v.as_str())
        .filter(|s| s.len() <= MAX_IMAGE_BYTES * 4 / 3 + 4)
        .and_then(|s| vodozemac::base64_decode(s).ok());
    LinkCard {
        url: text("url")?,
        site: text("site"),
        title: text("title"),
        description: text("desc"),
        image,
        image_width: side("iw"),
        image_height: side("ih"),
    }
    .checked()
}

/// The card a text is drawn with: [`read`], and only while [body] still contains its url.
pub fn believed(ext: &serde_json::Value, body: &str) -> Option<LinkCard> {
    read(ext).filter(|c| holds_link(body, &c.url))
}

/// `ext` with [card] written in, checked first; `None` (or a card that does not pass) leaves
/// `ext` without one.
pub fn write(ext: serde_json::Value, card: Option<&LinkCard>) -> serde_json::Value {
    let mut obj = match ext {
        serde_json::Value::Object(o) => o,
        serde_json::Value::Null => serde_json::Map::new(),
        other => return other,
    };
    obj.remove(EXT_KEY);
    if let Some(card) = card.cloned().and_then(LinkCard::checked) {
        let mut m = serde_json::Map::new();
        m.insert("url".into(), card.url.into());
        for (k, v) in [("site", card.site), ("title", card.title), ("desc", card.description)] {
            if let Some(v) = v {
                m.insert(k.into(), v.into());
            }
        }
        if let Some(img) = &card.image {
            m.insert("img".into(), vodozemac::base64_encode(img).into());
            if let (Some(w), Some(h)) = (card.image_width, card.image_height) {
                m.insert("iw".into(), w.into());
                m.insert("ih".into(), h.into());
            }
        }
        obj.insert(EXT_KEY.into(), serde_json::Value::Object(m));
    }
    if obj.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg() -> Vec<u8> {
        let mut b = vec![0xFF, 0xD8, 0xFF, 0xE0];
        b.resize(900, 3);
        b
    }

    fn card() -> LinkCard {
        LinkCard {
            url: "https://hukukgundemi.com/h/48213".into(),
            site: Some("hukukgundemi.com".into()),
            title: Some("Tebligat süreleri değişiyor".into()),
            description: Some("Elektronik  tebligatta\nbeş günlük süre".into()),
            image: Some(jpeg()),
            image_width: Some(1200),
            image_height: Some(630),
        }
    }

    #[test]
    fn a_card_written_reads_back_with_its_words_tidied() {
        let ext = write(serde_json::json!({"reply": {"uid": "u"}}), Some(&card()));
        let back = read(&ext).unwrap();
        assert_eq!(back.description.as_deref(), Some("Elektronik tebligatta beş günlük süre"));
        assert_eq!(back.image, Some(jpeg()));
        assert_eq!((back.image_width, back.image_height), (Some(1200), Some(630)));
        assert!(ext.get("reply").is_some(), "the rest of ext is kept");
    }

    #[test]
    fn a_card_is_believed_only_while_its_text_holds_the_link() {
        let ext = write(serde_json::Value::Null, Some(&card()));
        assert!(believed(&ext, "Bunu gördün mü? https://hukukgundemi.com/h/48213").is_some());
        assert!(believed(&ext, "Bunu gördün mü?").is_none(), "an edit that took the link out");
    }

    #[test]
    fn a_card_that_says_nothing_or_points_nowhere_is_not_a_card() {
        assert!(LinkCard { url: "https://a.example".into(), ..Default::default() }.checked().is_none());
        for url in ["javascript:alert(1)", "file:///etc/passwd", "https://", "ftp://a.example"] {
            assert!(LinkCard { url: url.into(), ..card() }.checked().is_none(), "{url}");
        }
        let png = LinkCard { image: Some(b"\x89PNG....".to_vec()), ..card() }.checked().unwrap();
        assert_eq!((png.image, png.image_width), (None, None));
    }

    #[test]
    fn writing_none_takes_an_old_card_out() {
        let ext = write(serde_json::Value::Null, Some(&card()));
        assert_eq!(write(ext, None), serde_json::Value::Null);
    }

    #[test]
    fn the_first_link_is_found_without_the_sentences_punctuation() {
        assert_eq!(
            first_link("Bak: (https://example.com/a?b=1).").as_deref(),
            Some("https://example.com/a?b=1")
        );
        assert_eq!(first_link("iki https://x.example/1 ve http://y.example").as_deref(), Some("https://x.example/1"));
        assert_eq!(first_link("dosya rapor.pdf ve main.dart, adres yok"), None);
        assert_eq!(first_link("yaz: ali@example.com"), None, "an e-mail address is not a link");
        assert_eq!(first_link("https:// boş"), None);
    }

    #[test]
    fn an_address_without_its_scheme_is_found_as_https() {
        assert_eq!(first_link("bak www.example.com/a.").as_deref(), Some("https://www.example.com/a"));
        assert_eq!(first_link("(adobe.com)").as_deref(), Some("https://adobe.com"));
        assert_eq!(first_link("huggingface.co değil ama huggingface.com").as_deref(), Some("https://huggingface.com"));
        assert_eq!(first_link("site.com.tr/haber?id=3").as_deref(), Some("https://site.com.tr/haber?id=3"));
    }

    #[test]
    fn a_card_for_a_bare_address_is_believed_on_its_bare_words() {
        let c = LinkCard { url: "https://adobe.com".into(), ..card() };
        let ext = write(serde_json::Value::Null, Some(&c));
        assert!(believed(&ext, "şuna bak adobe.com").is_some());
        assert!(believed(&ext, "https://adobe.com").is_some());
        assert!(believed(&ext, "notadobe.com").is_none());
        assert!(believed(&ext, "x.adobe.com").is_none());
        assert!(believed(&ext, "silindi").is_none());
    }
}
