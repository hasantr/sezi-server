//! Mentions in a group text: which members a message names, and where in its text (board
//! R5-Mentions, decision D9 of `docs/FIELD_READINESS_PLAN.md`).
//!
//! A mention travels in the payload's `ext` as `"mentions": [{"u": <user id>, "at": 6, "len": 11}]`
//! — `{"all": true, …}` for `@herkes` — beside a text body that still reads `@Ayşe Demir`. An old
//! client ignores `ext` and shows the words; nothing about the message changes for it.
//!
//! The span names a member by USER ID, never by the name in the text: a member who is renamed
//! later is still the one mentioned, and two members with one name stay apart. Offsets are UTF-16
//! code units into the body — the unit the app's text field counts in — so a span drawn on the
//! sender's screen covers the same characters on every receiver's.
//!
//! Everything here is pure and checks shape only. WHO may use `@herkes` (a group admin or the
//! owner) is decided by the kernel on both ends — the sender's refuses to send it, the receiver's
//! drops it from anyone else — because the receiver is the one a forged span would reach.

use serde::{Deserialize, Serialize};

/// The key under `ext`.
pub const EXT_KEY: &str = "mentions";

/// More spans than this in one message are dropped (the first ones are kept). A class is 30–80
/// people; a message naming more than fifty of them one by one is not a mention.
pub const MAX_MENTIONS: usize = 50;

/// A user id longer than this is not one (the relay's are UUIDs).
const MAX_USER_ID_LEN: usize = 128;

/// One `@name` in a message's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionSpan {
    /// The member named. `None` for `@herkes` (`all`).
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// `@herkes`: every member of the room.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    /// Where the `@` is, in UTF-16 code units from the start of the body.
    pub at: u32,
    /// How many UTF-16 code units the mention covers, the `@` included.
    pub len: u32,
}

impl MentionSpan {
    pub fn user(user_id: impl Into<String>, at: u32, len: u32) -> Self {
        Self { user_id: Some(user_id.into()), all: false, at, len }
    }

    pub fn everyone(at: u32, len: u32) -> Self {
        Self { user_id: None, all: true, at, len }
    }

    /// Exactly one target: a plausible user id, or `all`.
    fn has_one_target(&self) -> bool {
        match (&self.user_id, self.all) {
            (Some(id), false) => !id.is_empty() && id.len() <= MAX_USER_ID_LEN,
            (None, true) => true,
            _ => false,
        }
    }
}

/// The spans that are well formed against `body`, sorted by position: one target each, inside
/// the text, starting on an `@`, covering more than the `@` alone, overlapping none kept before
/// it, at most [`MAX_MENTIONS`]. Anything else is dropped rather than refused — a malformed span
/// from any sender leaves ordinary words, never an error.
pub fn vet(body: &str, spans: &[MentionSpan]) -> Vec<MentionSpan> {
    let units: Vec<u16> = body.encode_utf16().collect();
    let mut sorted: Vec<&MentionSpan> = spans.iter().collect();
    sorted.sort_by_key(|s| (s.at, s.len));
    let mut out: Vec<MentionSpan> = Vec::new();
    let mut taken_until = 0u32;
    for s in sorted {
        if out.len() == MAX_MENTIONS {
            break;
        }
        let end = match s.at.checked_add(s.len) {
            Some(end) => end,
            None => continue,
        };
        let starts_on_at = units.get(s.at as usize) == Some(&u16::from(b'@'));
        let fits = s.len >= 2 && (end as usize) <= units.len();
        let after_previous = out.is_empty() || s.at >= taken_until;
        if s.has_one_target() && starts_on_at && fits && after_previous && !splits_a_pair(&units, s.at, end)
        {
            taken_until = end;
            out.push(s.clone());
        }
    }
    out
}

/// Would a span ending at `end` cut a surrogate pair in half (an emoji in a name)? Then its
/// offsets were counted in some other unit, and the span is not trusted.
fn splits_a_pair(units: &[u16], at: u32, end: u32) -> bool {
    let low = |i: u32| units.get(i as usize).is_some_and(|u| (0xDC00..=0xDFFF).contains(u));
    low(at) || low(end)
}

/// The spans an `ext` carries. Tolerant: no key, a key that is not a list, or an item that is
/// not a span all read as nothing. Not vetted — call [`vet`] against the body.
pub fn read(ext: &serde_json::Value) -> Vec<MentionSpan> {
    ext.get(EXT_KEY)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::from_value::<MentionSpan>(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// `ext` with these spans under [`EXT_KEY`], every other key kept. No spans removes the key, and
/// an `ext` left with nothing in it becomes `Null`, so an ordinary message stays byte for byte
/// what it was.
pub fn write(ext: serde_json::Value, spans: &[MentionSpan]) -> serde_json::Value {
    let mut obj = match ext {
        serde_json::Value::Object(o) => o,
        _ => serde_json::Map::new(),
    };
    if spans.is_empty() {
        obj.remove(EXT_KEY);
    } else {
        obj.insert(
            EXT_KEY.into(),
            serde_json::to_value(spans).expect("mention spans serialize"),
        );
    }
    if obj.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(obj)
    }
}

/// Does any span name this user?
pub fn names_user(spans: &[MentionSpan], user_id: &str) -> bool {
    !user_id.is_empty() && spans.iter().any(|s| s.user_id.as_deref() == Some(user_id))
}

/// Is there an `@herkes`?
pub fn names_everyone(spans: &[MentionSpan]) -> bool {
    spans.iter().any(|s| s.all)
}

/// The spans without `@herkes` — what is left of a message whose sender may not address everyone.
pub fn without_everyone(spans: Vec<MentionSpan>) -> Vec<MentionSpan> {
    spans.into_iter().filter(|s| !s.all).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_len(s: &str) -> u32 {
        s.encode_utf16().count() as u32
    }

    #[test]
    fn a_span_on_the_words_it_names_is_kept() {
        let body = "Ödevimi gönderdim @Ayşe Demir bakar mısınız?";
        let at = utf16_len("Ödevimi gönderdim ");
        let span = MentionSpan::user("u-ayse", at, utf16_len("@Ayşe Demir"));
        assert_eq!(vet(body, std::slice::from_ref(&span)), vec![span]);
    }

    #[test]
    fn offsets_are_utf16_so_an_emoji_before_the_name_counts_twice() {
        let body = "🎉 @Can tebrikler";
        // The party popper is one char, two UTF-16 units: the `@` is at 3, not 2.
        assert_eq!(vet(body, &[MentionSpan::user("u-can", 2, 4)]), vec![]);
        let ok = MentionSpan::user("u-can", 3, 4);
        assert_eq!(vet(body, std::slice::from_ref(&ok)), vec![ok]);
    }

    #[test]
    fn a_span_that_is_not_on_an_at_sign_past_the_end_or_bare_is_dropped() {
        let body = "selam @Deniz";
        assert!(vet(body, &[MentionSpan::user("u", 0, 5)]).is_empty(), "not on an @");
        assert!(vet(body, &[MentionSpan::user("u", 6, 30)]).is_empty(), "past the end");
        assert!(vet(body, &[MentionSpan::user("u", 6, 1)]).is_empty(), "the @ alone");
        assert!(vet(body, &[MentionSpan::user("u", u32::MAX, 2)]).is_empty(), "overflow");
    }

    #[test]
    fn a_span_needs_exactly_one_target() {
        let body = "@herkes yarın";
        let both = MentionSpan { user_id: Some("u".into()), all: true, at: 0, len: 7 };
        let none = MentionSpan { user_id: None, all: false, at: 0, len: 7 };
        let empty = MentionSpan::user("", 0, 7);
        let long = MentionSpan::user("x".repeat(129), 0, 7);
        assert!(vet(body, &[both, none, empty, long]).is_empty());
        assert_eq!(vet(body, &[MentionSpan::everyone(0, 7)]).len(), 1);
    }

    #[test]
    fn overlapping_spans_keep_the_first_and_the_list_is_sorted() {
        let body = "@Ali @Veli";
        let a = MentionSpan::user("u-ali", 0, 4);
        let v = MentionSpan::user("u-veli", 5, 5);
        let over = MentionSpan::user("u-x", 0, 10);
        assert_eq!(vet(body, &[v.clone(), over, a.clone()]), vec![a, v]);
    }

    #[test]
    fn at_most_fifty_are_kept() {
        let body = "@a ".repeat(60);
        let spans: Vec<_> = (0..60).map(|i| MentionSpan::user(format!("u{i}"), i * 3, 2)).collect();
        assert_eq!(vet(&body, &spans).len(), MAX_MENTIONS);
    }

    #[test]
    fn ext_round_trips_and_keeps_its_other_keys() {
        let spans = vec![MentionSpan::user("u-ayse", 0, 5), MentionSpan::everyone(6, 7)];
        let ext = write(serde_json::json!({"forwarded": true}), &spans);
        assert_eq!(ext["forwarded"], true);
        assert_eq!(
            ext[EXT_KEY],
            serde_json::json!([{"u": "u-ayse", "at": 0, "len": 5}, {"all": true, "at": 6, "len": 7}])
        );
        assert_eq!(read(&ext), spans);
        assert_eq!(write(serde_json::Value::Null, &[]), serde_json::Value::Null);
        assert_eq!(write(ext, &[]), serde_json::json!({"forwarded": true}));
    }

    #[test]
    fn a_malformed_ext_reads_as_no_mentions() {
        assert!(read(&serde_json::Value::Null).is_empty());
        assert!(read(&serde_json::json!({"mentions": "x"})).is_empty());
        let mixed = serde_json::json!({"mentions": [{"u": "a", "at": 0, "len": 2}, 7, {"at": "x"}]});
        assert_eq!(read(&mixed), vec![MentionSpan::user("a", 0, 2)]);
    }

    #[test]
    fn who_is_named() {
        let spans = vec![MentionSpan::user("u-selin", 0, 6)];
        assert!(names_user(&spans, "u-selin"));
        assert!(!names_user(&spans, "u-can"));
        assert!(!names_user(&spans, ""));
        assert!(!names_everyone(&spans));
        let all = vec![MentionSpan::everyone(0, 7), MentionSpan::user("u", 8, 2)];
        assert!(names_everyone(&all));
        assert_eq!(without_everyone(all), vec![MentionSpan::user("u", 8, 2)]);
    }
}
