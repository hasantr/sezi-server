//! Is the text usable? (docs/HEARINGS_BOT_PLAN.md §3.1) And the small normalisations every input
//! gets first: line endings, decomposed Turkish letters, invisible characters, a text file saved
//! by Windows in code page 1254, and the classic Latin-1 reading of it (`ÞÝÐ` for `ŞİĞ`).

use serde::Serialize;

use crate::fold::fold;

/// What the check decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Usable,
    /// (Almost) no text at all: a scan or an image-only PDF.
    NoTextLayer,
    /// Text that is not text: unmapped glyphs, private-use code points, a font without ToUnicode.
    Garbled,
    /// Clean text, but no anchor of a hearing record.
    NotARecord,
}

/// Which anchors of a hearing record the text contains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Anchors {
    /// `ESAS`
    pub case: bool,
    /// `MAHKEME`
    pub court: bool,
    /// `DURUŞMA`
    pub hearing: bool,
    /// `TUTANAK` / `ZABIT` / `CELSE`
    pub record: bool,
}

impl Anchors {
    pub fn any(&self) -> bool {
        self.case || self.court || self.hearing
    }
}

/// The check's measurements and verdict. Numbers only, never text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Usability {
    pub verdict: Verdict,
    /// Characters that are not whitespace.
    pub chars: usize,
    /// Per mille of those that are unmapped or impossible (U+FFFD, private use, controls).
    pub bad_permille: u32,
    /// Per mille of those that are letters.
    pub letter_permille: u32,
    pub anchors: Anchors,
}

/// Fewer non-whitespace characters than this is no text layer.
pub const MIN_CHARS: usize = 40;
/// More unmapped glyphs than this (per mille) is mojibake whatever the anchors say.
pub const MAX_BAD_PERMILLE: u32 = 50;
/// Fewer letters than this (per mille) is not prose.
pub const MIN_LETTER_PERMILLE: u32 = 450;

fn bad(c: char) -> bool {
    matches!(c,
        '\u{FFFD}' | '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{10FFFF}' | '\u{80}'..='\u{9F}')
        || (c.is_control() && c != '\n' && c != '\t')
}

/// Assess `text`. `fonts_without_to_unicode` is the PDF's word that some font could not map its
/// glyphs; it turns an anchor-less text from "not a record" into "garbled".
pub fn assess(text: &str, fonts_without_to_unicode: bool) -> Usability {
    let mut chars = 0usize;
    let mut bad_n = 0usize;
    let mut letters = 0usize;
    for c in text.chars().filter(|c| !c.is_whitespace()) {
        chars += 1;
        if bad(c) {
            bad_n += 1;
        } else if c.is_alphabetic() {
            letters += 1;
        }
    }
    let permille = |n: usize| (n * 1000).checked_div(chars).unwrap_or(0) as u32;
    let folded = fold(text);
    let anchors = Anchors {
        case: folded.contains("esas"),
        court: folded.contains("mahkeme"),
        hearing: folded.contains("duruşma") || folded.contains("durusma"),
        record: folded.contains("tutanağı") || folded.contains("zabıt") || folded.contains("celse"),
    };
    let (bad_permille, letter_permille) = (permille(bad_n), permille(letters));
    let verdict = if chars < MIN_CHARS {
        Verdict::NoTextLayer
    } else if bad_permille > MAX_BAD_PERMILLE || letter_permille < MIN_LETTER_PERMILLE {
        Verdict::Garbled
    } else if !anchors.any() {
        if fonts_without_to_unicode || bad_permille > 5 {
            Verdict::Garbled
        } else {
            Verdict::NotARecord
        }
    } else {
        Verdict::Usable
    };
    Usability { verdict, chars, bad_permille, letter_permille, anchors }
}

/// Bytes of a text file as a string: UTF-8 (a BOM dropped), UTF-16 with a BOM, else Windows-1254
/// — what Turkish Notepad saved for years. `None` for binary.
pub fn decode_text(bytes: &[u8]) -> Option<String> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    if let Ok(s) = std::str::from_utf8(bytes) {
        return (!s.contains('\0')).then(|| s.to_string());
    }
    for (bom, le) in [(&b"\xFF\xFE"[..], true), (&b"\xFE\xFF"[..], false)] {
        if let Some(body) = bytes.strip_prefix(bom) {
            let units: Vec<u16> = body
                .chunks_exact(2)
                .map(|p| if le { u16::from_le_bytes([p[0], p[1]]) } else { u16::from_be_bytes([p[0], p[1]]) })
                .collect();
            return String::from_utf16(&units).ok();
        }
    }
    if bytes.contains(&0) {
        return None;
    }
    Some(bytes.iter().map(|&b| cp1254(b)).collect())
}

/// Windows-1254: Latin-1 with six Turkish letters in place of Icelandic ones, and the Windows
/// punctuation in 0x80–0x9F.
fn cp1254(b: u8) -> char {
    const HIGH: [char; 32] = [
        '€', '\u{FFFD}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{FFFD}', '\u{FFFD}',
        '\u{FFFD}', '\u{FFFD}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{FFFD}',
        '\u{FFFD}', 'Ÿ',
    ];
    match b {
        0x80..=0x9F => HIGH[(b - 0x80) as usize],
        0xD0 => 'Ğ',
        0xDD => 'İ',
        0xDE => 'Ş',
        0xF0 => 'ğ',
        0xFD => 'ı',
        0xFE => 'ş',
        b => b as char,
    }
}

/// The normalisations every input gets before it is read. Returns the text and whether the
/// Latin-1 reading of Turkish (`ÞÝÐ`) was repaired.
pub fn normalize(raw: &str) -> (String, bool) {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() != Some(&'\n') {
                    out.push('\n');
                }
            }
            '\u{000C}' | '\u{2028}' | '\u{2029}' => out.push('\n'),
            '\u{00AD}' | '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' => {}
            '\u{00A0}' | '\u{202F}' | '\u{2007}' => out.push(' '),
            c => match chars.peek().and_then(|&m| compose(c, m)) {
                Some(composed) => {
                    chars.next();
                    out.push(composed);
                }
                None => out.push(c),
            },
        }
    }
    // Trailing spaces on a line carry nothing and would leak into spans.
    let mut trimmed = String::with_capacity(out.len());
    for (i, line) in out.split('\n').enumerate() {
        if i > 0 {
            trimmed.push('\n');
        }
        trimmed.push_str(line.trim_end());
    }
    let latin1 = trimmed.chars().any(|c| matches!(c, 'Ý' | 'Þ' | 'Ð' | 'ý' | 'þ' | 'ð'));
    let turkish = trimmed.chars().any(|c| matches!(c, 'Ş' | 'ş' | 'Ğ' | 'ğ' | 'İ' | 'ı'));
    if latin1 && !turkish {
        let repaired = trimmed
            .chars()
            .map(|c| match c {
                'Ý' => 'İ',
                'Þ' => 'Ş',
                'Ð' => 'Ğ',
                'ý' => 'ı',
                'þ' => 'ş',
                'ð' => 'ğ',
                c => c,
            })
            .collect();
        return (repaired, true);
    }
    (trimmed, false)
}

/// A base letter and a combining mark as the one Turkish letter they spell, if they do.
fn compose(base: char, mark: char) -> Option<char> {
    Some(match (base, mark) {
        ('I', '\u{0307}') => 'İ',
        ('i', '\u{0307}') => 'i',
        ('S', '\u{0327}') => 'Ş',
        ('s', '\u{0327}') => 'ş',
        ('C', '\u{0327}') => 'Ç',
        ('c', '\u{0327}') => 'ç',
        ('G', '\u{0306}') => 'Ğ',
        ('g', '\u{0306}') => 'ğ',
        ('O', '\u{0308}') => 'Ö',
        ('o', '\u{0308}') => 'ö',
        ('U', '\u{0308}') => 'Ü',
        ('u', '\u{0308}') => 'ü',
        ('A', '\u{0302}') => 'Â',
        ('a', '\u{0302}') => 'â',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &str = "ANKARA 3. ASLİYE HUKUK MAHKEMESİ DURUŞMA TUTANAĞI ESAS NO 2024/123";

    #[test]
    fn verdicts() {
        assert_eq!(assess(RECORD, false).verdict, Verdict::Usable);
        assert_eq!(assess("  \n 1 \n", false).verdict, Verdict::NoTextLayer);
        let garbage: String = std::iter::repeat_n("\u{E012}\u{E013}x ", 30).collect();
        assert_eq!(assess(&garbage, false).verdict, Verdict::Garbled);
        let letter = "Sayın yetkili, ekte gönderdiğim teklif dosyası yazıcılar için hazırlanmıştır.";
        assert_eq!(assess(letter, false).verdict, Verdict::NotARecord);
        assert_eq!(assess(letter, true).verdict, Verdict::Garbled, "a font without ToUnicode");
        let symbols: String = std::iter::repeat_n("#$%& 1234 ()*+ ", 10).collect();
        assert_eq!(assess(&symbols, false).verdict, Verdict::Garbled);
    }

    #[test]
    fn anchors_survive_turkish_case() {
        let a = assess("DURUŞMA TUTANAĞI — Duruşma yapıldı, mahkemece esas hakkında ............", false);
        assert!(a.anchors.hearing && a.anchors.court && a.anchors.case && a.anchors.record);
    }

    #[test]
    fn cp1254_and_latin1_mojibake() {
        assert_eq!(decode_text(b"DURU\xdeMA TAR\xddH\xdd").unwrap(), "DURUŞMA TARİHİ");
        assert_eq!(decode_text("ÇAĞ".as_bytes()).unwrap(), "ÇAĞ");
        assert_eq!(decode_text(b"\xEF\xBB\xBFabc").unwrap(), "abc");
        assert!(decode_text(b"\x00\x01PK").is_none());
        let (fixed, repaired) = normalize("DURUÞMA TARÝHÝ : 14/10/2026\r\nKatip");
        assert_eq!(fixed, "DURUŞMA TARİHİ : 14/10/2026\nKatip");
        assert!(repaired);
    }

    #[test]
    fn decomposed_letters_are_composed() {
        let (s, _) = normalize("DURUS\u{0327}MA TARI\u{0307}HI\u{0307}  \nx\u{00AD}y");
        assert_eq!(s, "DURUŞMA TARİHİ\nxy");
    }
}
