//! Turkish case folding with a way back to the original text.
//!
//! Every rule in this crate matches on a FOLDED copy of the text and reports spans in the
//! ORIGINAL. Folding is char-for-char (each original char becomes exactly one folded char), so a
//! byte offset in the folded copy maps back through [`Folded::orig`].
//!
//! Why not `to_lowercase`: Turkish has two i's. `İ` folds to `i` and `I` to `ı`; a generic
//! lowercase turns `IĞDIR` into `iğdir` and `İ` into `i̇` (two chars). Circumflexes are folded
//! away as well (`HÂKİM`, `Kâtip`), and typographic apostrophes become `'`.

/// A text folded for matching, with the byte map back to the text it came from.
pub(crate) struct Folded {
    pub(crate) s: String,
    /// `map[b]` = the original byte offset of the char whose folded form starts at folded byte
    /// `b` (filled for every byte of that folded char). One extra entry maps the end.
    map: Vec<usize>,
}

impl Folded {
    pub(crate) fn new(orig: &str) -> Self {
        let mut s = String::with_capacity(orig.len() + orig.len() / 8);
        let mut map = Vec::with_capacity(orig.len() + orig.len() / 8 + 1);
        for (at, c) in orig.char_indices() {
            let f = fold_char(c);
            for _ in 0..f.len_utf8() {
                map.push(at);
            }
            s.push(f);
        }
        map.push(orig.len());
        Self { s, map }
    }

    /// The original byte offset of folded byte offset `folded`.
    pub(crate) fn orig(&self, folded: usize) -> usize {
        self.map[folded.min(self.map.len() - 1)]
    }

    /// The original byte range of a folded byte range.
    pub(crate) fn span(&self, start: usize, end: usize) -> crate::Span {
        crate::Span {
            start: self.orig(start),
            end: self.orig(end),
        }
    }
}

/// One char, folded. Never changes the number of chars.
pub(crate) fn fold_char(c: char) -> char {
    match c {
        'İ' => 'i',
        'I' => 'ı',
        'Â' | 'â' => 'a',
        'Î' | 'î' => 'i',
        'Û' | 'û' => 'u',
        '\u{2019}' | '\u{2018}' | '\u{02BC}' | '`' | '\u{00B4}' => '\'',
        '\u{2013}' | '\u{2014}' | '\u{2212}' => '-',
        '\u{00A0}' | '\u{202F}' | '\u{2007}' => ' ',
        c if c.is_ascii() => c.to_ascii_lowercase(),
        c => {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(l), None) => l,
                _ => c,
            }
        }
    }
}

/// A whole string, folded (no map). For tests and short comparisons.
pub(crate) fn fold(s: &str) -> String {
    s.chars().map(fold_char).collect()
}

/// Turkish uppercase of one char (`i` → `İ`, `ı` → `I`).
fn upper_char(c: char) -> char {
    match c {
        'i' => 'İ',
        'ı' => 'I',
        c => {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        }
    }
}

/// Turkish lowercase of one char, keeping circumflexes (this is for display, not matching).
fn lower_char(c: char) -> char {
    match c {
        'İ' => 'i',
        'I' => 'ı',
        c => {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(l), None) => l,
                _ => c,
            }
        }
    }
}

/// Title case the Turkish way: `İSTANBUL ANADOLU` → `İstanbul Anadolu`, `IĞDIR` → `Iğdır`,
/// `İŞ MAHKEMESİ` → `İş Mahkemesi`. Whitespace runs collapse to one space.
pub(crate) fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for word in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut first = true;
        for c in word.chars() {
            if first && c.is_alphabetic() {
                out.push(upper_char(c));
                first = false;
            } else {
                out.push(lower_char(c));
            }
        }
    }
    out
}

/// A regex fragment for a label written in folded Turkish: every space may be any run of
/// whitespace (a label broken across lines), and each letter that an ASCII-fied text or a
/// font without the dotted capital might spell differently matches both spellings.
pub(crate) fn label(folded_words: &str) -> String {
    let mut out = String::new();
    for c in folded_words.chars() {
        match c {
            ' ' => out.push_str(r"\s+"),
            'i' | 'ı' => out.push_str("[iı]"),
            'ş' | 's' => out.push_str("[şs]"),
            'ğ' | 'g' => out.push_str("[ğg]"),
            'ü' | 'u' => out.push_str("[üu]"),
            'ö' | 'o' => out.push_str("[öo]"),
            'ç' | 'c' => out.push_str("[çc]"),
            '.' => out.push_str(r"\."),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turkish_i_folds_both_ways() {
        assert_eq!(fold("IĞDIR"), "ığdır");
        assert_eq!(fold("İSTANBUL"), "istanbul");
        assert_eq!(fold("HÂKİM Kâtip"), "hakim katip");
        assert_eq!(fold("YILMAZ’ın"), "yılmaz'ın");
    }

    #[test]
    fn folding_keeps_a_map_back_to_the_original() {
        let orig = "İŞ Iİ";
        let f = Folded::new(orig);
        assert_eq!(f.s, "iş ıi");
        let at = f.s.find('ı').unwrap();
        assert_eq!(&orig[f.orig(at)..], "Iİ");
        assert_eq!(f.orig(f.s.len()), orig.len());
    }

    #[test]
    fn title_case_is_turkish() {
        assert_eq!(title_case("İSTANBUL  ANADOLU"), "İstanbul Anadolu");
        assert_eq!(title_case("IĞDIR"), "Iğdır");
        assert_eq!(title_case("İŞ MAHKEMESİ"), "İş Mahkemesi");
        assert_eq!(title_case("ağır ceza"), "Ağır Ceza");
    }

    #[test]
    fn a_label_matches_across_a_line_break_and_ascii_spelling() {
        let re = regex::Regex::new(&label("duruşma tarihi")).unwrap();
        assert!(re.is_match("duruşma\ntarihi"));
        assert!(re.is_match("durusma tarıhı"));
    }
}
