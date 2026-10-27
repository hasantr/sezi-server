//! The normalized view every recognizer reads (§4.2), with a map back onto the original bytes.
//!
//! The masked text is built from the ORIGINAL, never from this view: whatever is not masked is
//! returned byte for byte. The view only makes matching robust:
//! - decomposed Turkish letters are composed (`I` + U+0307 → `İ`, `s` + U+0327 → `ş`…), the
//!   handful of compositions a Turkish text needs, instead of a full NFC table;
//! - a word hyphenated across a line break is joined (`YIL-⏎MAZ` → `YILMAZ`);
//! - zero-width characters and soft hyphens vanish (they split a name into two "words");
//! - every apostrophe becomes `'`, every dash `-`, every space `' '`, `\r` goes;
//! - every decimal digit (fullwidth, Arabic-Indic, Devanagari, mathematical bold…) becomes its
//!   ASCII digit, ligatures are expanded, a fullwidth
//!   or small `@` becomes `@`.

use crate::fold::is_mark;

pub struct View {
    pub text: String,
    /// `map[i]` = the original byte offset of the character the view's byte `i` came from;
    /// `map[text.len()] == orig.len()`.
    map: Vec<usize>,
}

impl View {
    pub fn new(orig: &str) -> View {
        let chars: Vec<(usize, char)> = orig.char_indices().collect();
        let mut v = View { text: String::with_capacity(orig.len()), map: Vec::with_capacity(orig.len() + 1) };
        let mut k = 0;
        while k < chars.len() {
            let (o, c) = chars[k];
            if matches!(c, '-' | '\u{00AD}' | '\u{2010}' | '\u{2011}') && v.last_is_letter() {
                if let Some(next) = hyphen_break(&chars, k) {
                    k = next;
                    continue;
                }
            }
            match c {
                m if is_mark(m) => v.mark(m, o),
                '\u{00AD}' | '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\r' => {}
                '\n' | '\u{000C}' | '\u{2028}' | '\u{2029}' => v.push('\n', o),
                '\u{2018}' | '\u{2019}' | '\u{201B}' | '`' | '\u{00B4}' | '\u{02BC}' | '\u{2032}' => v.push('\'', o),
                '\u{2010}'..='\u{2015}' | '\u{2212}' => v.push('-', o),
                '\u{FF20}' | '\u{FE6B}' => v.push('@', o),
                d if decimal(d).is_some() => v.push(digit(decimal(d).unwrap_or(0)), o),
                '\u{FB00}' => v.push_str("ff", o),
                '\u{FB01}' => v.push_str("fi", o),
                '\u{FB02}' => v.push_str("fl", o),
                '\u{FB03}' => v.push_str("ffi", o),
                '\u{FB04}' => v.push_str("ffl", o),
                w if w.is_whitespace() || w.is_control() => v.push(' ', o),
                _ => v.push(c, o),
            }
            k += 1;
        }
        v.map.push(orig.len());
        v
    }

    /// The original byte offset of the view's byte `i` (`i == text.len()` allowed).
    pub fn orig(&self, i: usize) -> usize {
        self.map[i]
    }

    /// The first view byte that comes from original offset `o` or later (the inverse of
    /// [`View::orig`], rounded up; always a char boundary of the view).
    pub fn norm_of(&self, o: usize) -> usize {
        let mut i = self.map.partition_point(|&m| m < o);
        while i < self.text.len() && !self.text.is_char_boundary(i) {
            i += 1;
        }
        i.min(self.text.len())
    }

    fn push(&mut self, c: char, o: usize) {
        for _ in 0..c.len_utf8() {
            self.map.push(o);
        }
        self.text.push(c);
    }

    fn push_str(&mut self, s: &str, o: usize) {
        for c in s.chars() {
            self.push(c, o);
        }
    }

    fn last_is_letter(&self) -> bool {
        self.text.chars().next_back().is_some_and(char::is_alphabetic)
    }

    /// A combining mark: composed with the letter before it when Turkish needs that, else kept
    /// (the tokenizer keeps a mark inside its word either way).
    fn mark(&mut self, m: char, o: usize) {
        if let Some(base) = self.text.chars().next_back() {
            if let Some(c) = compose(base, m) {
                self.text.pop();
                let new_len = self.text.len();
                let base_orig = self.map[new_len];
                self.map.truncate(new_len);
                self.push(c, base_orig);
                return;
            }
        }
        self.push(m, o);
    }
}

/// After a hyphen at `k`: optional spaces, one line break, optional spaces, then a letter.
/// Returns the index of that letter, or `None` when this hyphen is not a line-break hyphen.
fn hyphen_break(chars: &[(usize, char)], k: usize) -> Option<usize> {
    let mut m = k + 1;
    let skip_spaces = |m: &mut usize| {
        while *m < chars.len() && matches!(chars[*m].1, ' ' | '\t' | '\r') {
            *m += 1;
        }
    };
    skip_spaces(&mut m);
    if m >= chars.len() || chars[m].1 != '\n' {
        return None;
    }
    m += 1;
    skip_spaces(&mut m);
    (m < chars.len() && chars[m].1.is_alphabetic()).then_some(m)
}

fn digit(d: u32) -> char {
    char::from_digit(d, 10).unwrap_or('0')
}

/// The zero of every run of ten decimal digits (Unicode `Nd`) other than ASCII's: fullwidth,
/// Arabic-Indic, Devanagari, Bengali…, and the mathematical bold/double-struck/sans/monospace
/// digits. A model reads "१०००…" or "𝟏𝟎𝟎…" as the number it is, so the masker must too.
const DIGIT_ZEROS: [u32; 66] = [
    0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0DE6,
    0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0,
    0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10, 0x104A0, 0x10D30, 0x11066,
    0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650, 0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50,
    0x11D50, 0x11DA0, 0x16A60, 0x16AC0, 0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0,
    0x1E4F0, 0x1E950, 0x1FBF0,
];

/// The value of a non-ASCII decimal digit.
fn decimal(c: char) -> Option<u32> {
    let cp = c as u32;
    if cp < 0x0660 {
        return None;
    }
    DIGIT_ZEROS.iter().find(|&&z| (z..z + 10).contains(&cp)).map(|z| cp - z)
}

fn compose(base: char, mark: char) -> Option<char> {
    Some(match (base, mark) {
        ('I', '\u{0307}') => 'İ',
        ('i', '\u{0307}') => 'i',
        ('g', '\u{0306}') => 'ğ',
        ('G', '\u{0306}') => 'Ğ',
        ('s', '\u{0327}') => 'ş',
        ('S', '\u{0327}') => 'Ş',
        ('c', '\u{0327}') => 'ç',
        ('C', '\u{0327}') => 'Ç',
        ('u', '\u{0308}') => 'ü',
        ('U', '\u{0308}') => 'Ü',
        ('o', '\u{0308}') => 'ö',
        ('O', '\u{0308}') => 'Ö',
        ('a', '\u{0302}') => 'â',
        ('A', '\u{0302}') => 'Â',
        ('i' | 'ı', '\u{0302}') => 'î',
        ('I', '\u{0302}') => 'Î',
        ('u', '\u{0302}') => 'û',
        ('U', '\u{0302}') => 'Û',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_joins_and_maps_back() {
        let orig = "I\u{0307}SMAI\u{0307}L YIL-\n  MAZ\u{200B}'ın";
        let v = View::new(orig);
        assert_eq!(v.text, "İSMAİL YILMAZ'ın");
        // "YILMAZ" in the view maps back onto "YIL-\n  MAZ\u{200B}" in the original.
        let s = v.text.find("YILMAZ").unwrap();
        let e = s + "YILMAZ".len();
        assert_eq!(&orig[v.orig(s)..v.orig(e)], "YIL-\n  MAZ\u{200B}");
        assert_eq!(&orig[v.orig(0)..v.orig("İ".len())], "I\u{0307}");
    }

    #[test]
    fn a_spaced_dash_is_not_a_line_break_hyphen() {
        assert_eq!(View::new("YILMAZ -\nKızılay").text, "YILMAZ -\nKızılay");
        assert_eq!(View::new("a\r\nb\u{00A0}c\u{2019}d").text, "a\nb c'd");
    }
}
