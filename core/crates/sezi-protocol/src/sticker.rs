//! A sticker: a big animated emoji drawn from art every client ships (Google's Noto Animated
//! Emoji). On the wire it is an ordinary TEXT whose body is the emoji itself, plus
//! `ext.sticker = {"set": "noto", "id": "<id>"}` — so a client that knows no stickers shows the
//! emoji, and one that does draws the animation.
//!
//! `id` names the emoji by its code points: lowercase hex, two to six digits each, joined by `_`,
//! at most eight of them (`1f602`, `2764_fe0f`, `1f468_200d_1f4bb`) — the names the Noto files
//! carry. A sticker is believed only when its body IS the emoji its id spells: anything else is
//! the text it says, so a sender cannot make a bubble animate one thing while the words (and every
//! older client, and the chat list) say another.
//!
//! Pure shape checks only; the kernel builds the message (`kernel/stickers.rs`).

use serde::{Deserialize, Serialize};

/// The key under `ext`.
pub const EXT_KEY: &str = "sticker";

/// The sets a client may name. Only Noto exists; a set nobody ships would draw nothing.
pub const SETS: [&str; 1] = ["noto"];

/// At most this many code points in an id.
const MAX_POINTS: usize = 8;

/// A sticker's reference: which set, which emoji.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StickerRef {
    pub set: String,
    pub id: String,
}

impl StickerRef {
    /// A sticker as it may be sent, with the body it is sent as. `Err` with a stable code when the
    /// set is unknown or the id spells no emoji.
    pub fn new(set: &str, id: &str) -> Result<(Self, String), &'static str> {
        if !SETS.contains(&set) {
            return Err("sticker/unknown-set");
        }
        let body = emoji_of_id(id).ok_or("sticker/bad-id")?;
        Ok((Self { set: set.to_string(), id: id.to_string() }, body))
    }
}

/// The emoji an id spells, if it is one: every part 2–6 lowercase hex digits, at most eight
/// parts, each a Unicode scalar value, and the whole an emoji a reaction could carry
/// (`crate::reaction::valid_emoji` — no letters, digits, spaces or controls).
pub fn emoji_of_id(id: &str) -> Option<String> {
    let parts: Vec<&str> = id.split('_').collect();
    if parts.is_empty() || parts.len() > MAX_POINTS {
        return None;
    }
    let mut out = String::new();
    for p in parts {
        let hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
        if !(2..=6).contains(&p.len()) || !p.chars().all(hex) {
            return None;
        }
        out.push(char::from_u32(u32::from_str_radix(p, 16).ok()?)?);
    }
    crate::reaction::valid_emoji(&out).then_some(out)
}

/// The sticker an `ext` carries, its shape checked — a known set and an id that spells an emoji.
/// Not yet compared with the body: that is [`believed`].
pub fn read(ext: &serde_json::Value) -> Option<StickerRef> {
    let s: StickerRef = serde_json::from_value(ext.get(EXT_KEY)?.clone()).ok()?;
    (SETS.contains(&s.set.as_str()) && emoji_of_id(&s.id).is_some()).then_some(s)
}

/// The sticker a text is: [`read`], and only when `body` is exactly the emoji the id spells.
pub fn believed(body: &str, ext: &serde_json::Value) -> Option<StickerRef> {
    read(ext).filter(|s| emoji_of_id(&s.id).as_deref() == Some(body))
}

/// `ext` with this sticker under [`EXT_KEY`] (or without it), every other key kept; an `ext` left
/// empty is `Null`.
pub fn write(ext: serde_json::Value, sticker: Option<&StickerRef>) -> serde_json::Value {
    let mut obj = match ext {
        serde_json::Value::Object(o) => o,
        _ => serde_json::Map::new(),
    };
    match sticker {
        Some(s) => {
            obj.insert(EXT_KEY.into(), serde_json::to_value(s).expect("sticker serializes"));
        }
        None => {
            obj.remove(EXT_KEY);
        }
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

    #[test]
    fn an_id_spells_its_emoji() {
        assert_eq!(emoji_of_id("1f602").as_deref(), Some("😂"));
        assert_eq!(emoji_of_id("2764_fe0f").as_deref(), Some("❤️"));
        assert_eq!(emoji_of_id("1f468_200d_1f4bb").as_deref(), Some("👨‍💻"));
    }

    #[test]
    fn a_malformed_id_spells_nothing() {
        for bad in [
            "", "1F602", "f", "1f6022a", "1f602_", "_1f602", "1f602__2764", "d800",
            "110000", "41", "1f602 ", "zz", "1f602_fe0f_fe0f_fe0f_fe0f_fe0f_fe0f_fe0f_fe0f",
        ] {
            assert_eq!(emoji_of_id(bad), None, "{bad:?}");
        }
        // Eight parts is the limit, not seven.
        assert!(emoji_of_id("1f468_200d_1f469_200d_1f467_200d_1f466_fe0f").is_some());
    }

    #[test]
    fn a_sticker_is_built_with_its_body_and_refused_with_a_code() {
        let (s, body) = StickerRef::new("noto", "1f602").unwrap();
        assert_eq!((s.set.as_str(), s.id.as_str(), body.as_str()), ("noto", "1f602", "😂"));
        assert_eq!(StickerRef::new("apple", "1f602"), Err("sticker/unknown-set"));
        assert_eq!(StickerRef::new("noto", "1F602"), Err("sticker/bad-id"));
    }

    #[test]
    fn a_sticker_is_believed_only_when_the_body_is_its_emoji() {
        let (s, body) = StickerRef::new("noto", "1f602").unwrap();
        let ext = write(serde_json::json!({"forwarded": true}), Some(&s));
        assert_eq!(believed(&body, &ext), Some(s.clone()));
        assert_eq!(believed("😮", &ext), None, "the words say another emoji");
        assert_eq!(believed("haha", &ext), None);
        assert_eq!(write(ext, None), serde_json::json!({"forwarded": true}));
        let forged = serde_json::json!({"sticker": {"set": "noto", "id": "41"}});
        assert_eq!(believed("A", &forged), None, "an id that spells a letter is no sticker");
        let unknown = serde_json::json!({"sticker": {"set": "apple", "id": "1f602"}});
        assert_eq!(believed("😂", &unknown), None);
        assert_eq!(believed("😂", &serde_json::json!({"sticker": "1f602"})), None);
    }
}
