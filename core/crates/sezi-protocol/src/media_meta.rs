//! A picture's or video's shape, carried with the file so the receiver can draw it before a byte
//! of it has arrived: `ext.media = {"w": 1600, "h": 1200, "ms": 84000, "thumb": "<base64 JPEG>"}`.
//!
//! Without it a receiver knew nothing about a picture until it was downloaded: the bubble was a
//! file card ("IMG_2042.jpg · 2,2 MB"), and a video was a black tile with its file name even once
//! it was here (Round 14, 2026-10-30). With it the bubble is the right shape at once, a picture
//! shows its own blurred miniature while it downloads, and a video shows its cover and length.
//!
//! - `w`/`h`: the picture's (or video's) size as it should be SHOWN — orientation already applied.
//!   Only the ratio is used; the numbers are kept because a size says more than a ratio.
//! - `ms`: a video's length. Absent for a picture.
//! - `thumb`: a small JPEG. For a picture a miniature of a few dozen pixels that the receiver draws
//!   blurred; for a video its cover frame, drawn sharp. Absent when the sender could not make one.
//!
//! Everything rides inside the E2E envelope, so the relay sees none of it. An older client ignores
//! the key. Pure shape checks only; the sender's core makes the thumbnail (`sezi-media`), the
//! kernel writes the key where the sender's row is built (`kernel/attachments.rs`,
//! `groups_outbound.rs`), and the projection reads it (`MessageView.media`).

/// The key under `ext`.
pub const EXT_KEY: &str = "media";

/// A side longer than this is not a picture anyone sends; the claim is not believed.
pub const MAX_SIDE: u32 = 30_000;

/// A video longer than a day is not believed.
pub const MAX_MS: u32 = 24 * 3600 * 1000;

/// The largest thumbnail believed, decoded. A video cover of ~320 px fits; the envelope's 64 KiB
/// leaves room for the rest of the message.
pub const MAX_THUMB_BYTES: usize = 16 * 1024;

/// A picture's or video's shape and miniature (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaMeta {
    pub width: u32,
    pub height: u32,
    pub duration_ms: Option<u32>,
    /// JPEG bytes.
    pub thumb: Option<Vec<u8>>,
}

impl MediaMeta {
    /// The meta as it may be sent or believed: `None` when the size is not a size; a length past
    /// [`MAX_MS`] or a thumbnail that is not a small JPEG is dropped and the rest kept — a bubble of
    /// the right shape is worth having without them.
    pub fn checked(self) -> Option<Self> {
        let side_ok = |s: u32| (1..=MAX_SIDE).contains(&s);
        if !side_ok(self.width) || !side_ok(self.height) {
            return None;
        }
        Some(Self {
            width: self.width,
            height: self.height,
            duration_ms: self.duration_ms.filter(|ms| *ms <= MAX_MS),
            thumb: self.thumb.filter(|t| is_small_jpeg(t)),
        })
    }
}

/// A JPEG (its SOI marker) no larger than [`MAX_THUMB_BYTES`]. Nothing more is checked: the bytes
/// are decoded by the platform's image decoder, which already has to survive any file a peer
/// sends as an attachment.
fn is_small_jpeg(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_THUMB_BYTES && bytes.starts_with(&[0xFF, 0xD8, 0xFF])
}

/// The media meta an `ext` carries, checked ([`MediaMeta::checked`]). Anything malformed reads as
/// absent, never as an error: the bubble then draws what it drew before this key existed.
pub fn read(ext: &serde_json::Value) -> Option<MediaMeta> {
    let m = ext.get(EXT_KEY)?;
    let side = |k: &str| u32::try_from(m.get(k)?.as_u64()?).ok();
    let duration_ms = m.get("ms").and_then(|v| u32::try_from(v.as_u64()?).ok());
    let thumb = m
        .get("thumb")
        .and_then(|v| v.as_str())
        // Far past the cap in base64 is not decoded at all.
        .filter(|s| s.len() <= MAX_THUMB_BYTES * 4 / 3 + 4)
        .and_then(|s| vodozemac::base64_decode(s).ok());
    MediaMeta { width: side("w")?, height: side("h")?, duration_ms, thumb }.checked()
}

/// `ext` with the media meta written in, checked first; a meta that does not pass leaves `ext`
/// as it was.
pub fn write(ext: serde_json::Value, meta: MediaMeta) -> serde_json::Value {
    let Some(meta) = meta.checked() else {
        return ext;
    };
    let mut obj = match ext {
        serde_json::Value::Object(o) => o,
        _ => serde_json::Map::new(),
    };
    let mut m = serde_json::Map::new();
    m.insert("w".into(), meta.width.into());
    m.insert("h".into(), meta.height.into());
    if let Some(ms) = meta.duration_ms {
        m.insert("ms".into(), ms.into());
    }
    if let Some(thumb) = &meta.thumb {
        m.insert("thumb".into(), vodozemac::base64_encode(thumb).into());
    }
    obj.insert(EXT_KEY.into(), serde_json::Value::Object(m));
    serde_json::Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg(len: usize) -> Vec<u8> {
        let mut b = vec![0xFF, 0xD8, 0xFF, 0xE0];
        b.resize(len, 7);
        b
    }

    fn meta() -> MediaMeta {
        MediaMeta { width: 1600, height: 1200, duration_ms: Some(84_000), thumb: Some(jpeg(600)) }
    }

    #[test]
    fn written_meta_reads_back_whole() {
        let ext = write(serde_json::json!({"caption": "x"}), meta());
        assert_eq!(read(&ext), Some(meta()));
        assert_eq!(ext["caption"], "x", "the rest of ext is kept");
    }

    #[test]
    fn a_size_that_is_not_one_is_not_believed() {
        for (w, h) in [(0, 10), (10, 0), (MAX_SIDE + 1, 10)] {
            let ext = serde_json::json!({"media": {"w": w, "h": h}});
            assert_eq!(read(&ext), None, "{w}x{h}");
            assert_eq!(write(serde_json::Value::Null, MediaMeta { width: w, height: h, ..meta() }),
                serde_json::Value::Null);
        }
        assert_eq!(read(&serde_json::json!({"media": {"w": -1, "h": 5}})), None);
        assert_eq!(read(&serde_json::json!({"media": {"w": "1", "h": 5}})), None);
    }

    #[test]
    fn a_bad_thumb_or_length_is_dropped_and_the_shape_kept() {
        let big = MediaMeta { thumb: Some(jpeg(MAX_THUMB_BYTES + 1)), ..meta() };
        assert_eq!(big.checked().unwrap().thumb, None);
        let png = MediaMeta { thumb: Some(vec![0x89, b'P', b'N', b'G']), ..meta() };
        assert_eq!(png.checked().unwrap().thumb, None);
        let long = MediaMeta { duration_ms: Some(MAX_MS + 1), ..meta() };
        assert_eq!(long.checked().unwrap().duration_ms, None);
        let ext = serde_json::json!({"media": {"w": 4, "h": 3, "thumb": "%%not base64%%"}});
        assert_eq!(read(&ext), Some(MediaMeta { width: 4, height: 3, duration_ms: None, thumb: None }));
    }

    #[test]
    fn no_key_reads_as_none() {
        assert_eq!(read(&serde_json::Value::Null), None);
        assert_eq!(read(&serde_json::json!({"caption": "x"})), None);
    }
}
