//! Words and digit groups of the normalized view, with their lines and matching keys.

use core::ops::Range;

use crate::fold::{self, Case};
use crate::norm::View;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Letters (a combining mark stays inside its word).
    Word,
    /// ASCII digits.
    Num,
}

#[derive(Clone, Debug)]
pub struct Tok {
    /// Byte range in the view.
    pub s: usize,
    pub e: usize,
    pub kind: Kind,
    pub line: usize,
    pub case: Case,
    /// [`fold::key`] of a word; the digits of a number.
    pub key: String,
    /// Letters (or digits) in the token.
    pub chars: usize,
    /// A word glued to the previous token by an apostrophe: the `ın` of `YILMAZ'ın`.
    pub suffix: bool,
}

pub struct Doc {
    pub view: View,
    pub toks: Vec<Tok>,
    /// Index of the first token of each line.
    line_first: Vec<usize>,
}

impl Doc {
    pub fn new(orig: &str) -> Doc {
        Doc::from_view(View::new(orig))
    }

    pub fn from_view(view: View) -> Doc {
        let mut toks: Vec<Tok> = Vec::new();
        let mut line_first = vec![0];
        let mut line = 0;
        let mut cur: Option<(usize, Kind)> = None;
        let text = view.text.as_str();
        for (i, c) in text.char_indices() {
            let k = if c.is_ascii_digit() {
                Some(Kind::Num)
            } else if c.is_alphabetic() || (fold::is_mark(c) && matches!(cur, Some((_, Kind::Word)))) {
                Some(Kind::Word)
            } else {
                None
            };
            let same = matches!((cur, k), (Some((_, a)), Some(b)) if a == b);
            if !same {
                if let Some((s, kind)) = cur.take() {
                    toks.push(make(text, s, i, kind, line));
                }
                cur = k.map(|kind| (i, kind));
            }
            if c == '\n' {
                line += 1;
                line_first.push(toks.len());
            }
        }
        if let Some((s, kind)) = cur {
            toks.push(make(text, s, text.len(), kind, line));
        }
        for i in 1..toks.len() {
            if toks[i].kind == Kind::Word && &text[toks[i - 1].e..toks[i].s] == "'" {
                toks[i].suffix = true;
            }
        }
        Doc { view, toks, line_first }
    }

    pub fn text(&self) -> &str {
        &self.view.text
    }

    /// The text of token `i`.
    pub fn t(&self, i: usize) -> &str {
        &self.view.text[self.toks[i].s..self.toks[i].e]
    }

    /// The text between token `i` and the next one (or the end).
    pub fn gap(&self, i: usize) -> &str {
        let e = self.toks.get(i + 1).map_or(self.view.text.len(), |t| t.s);
        &self.view.text[self.toks[i].e..e]
    }

    /// The text between the previous token (or the start) and token `i`.
    pub fn gap_before(&self, i: usize) -> &str {
        let s = if i == 0 { 0 } else { self.toks[i - 1].e };
        &self.view.text[s..self.toks[i].s]
    }

    pub fn n_lines(&self) -> usize {
        self.line_first.len()
    }

    /// The token indices on line `line`.
    pub fn line_toks(&self, line: usize) -> Range<usize> {
        let s = self.line_first.get(line).copied().unwrap_or(self.toks.len());
        let e = self.line_first.get(line + 1).copied().unwrap_or(self.toks.len());
        s..e
    }

    /// Is token `i` a word with this key?
    pub fn is(&self, i: usize, key: &str) -> bool {
        self.toks.get(i).is_some_and(|t| t.kind == Kind::Word && t.key == key)
    }

    /// The character right after token `i`, if any.
    pub fn next_char(&self, i: usize) -> Option<char> {
        self.view.text[self.toks[i].e..].chars().next()
    }

    /// The character right before token `i`, if any.
    pub fn prev_char(&self, i: usize) -> Option<char> {
        self.view.text[..self.toks[i].s].chars().next_back()
    }
}

fn make(text: &str, s: usize, e: usize, kind: Kind, line: usize) -> Tok {
    let t = &text[s..e];
    let (key, case) = match kind {
        Kind::Word => (fold::key(t), fold::case_of(t)),
        Kind::Num => (t.to_string(), Case::Mixed),
    };
    let chars = key.chars().count();
    Tok { s, e, kind, line, case, key, chars, suffix: false }
}

/// Spaces only, with at most one line break: how the words of one name may be separated.
pub fn ws_gap(g: &str) -> bool {
    !g.is_empty() && g.chars().all(|c| c == ' ' || c == '\n') && g.matches('\n').count() <= 1
}

/// Spaces only, on one line.
pub fn space_gap(g: &str) -> bool {
    !g.is_empty() && g.chars().all(|c| c == ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_lines_and_suffixes() {
        let d = Doc::new("DAVACI : AHMET YILMAZ'ın\n2024/123 Esas");
        let words: Vec<&str> = (0..d.toks.len()).map(|i| d.t(i)).collect();
        assert_eq!(words, ["DAVACI", "AHMET", "YILMAZ", "ın", "2024", "123", "Esas"]);
        assert!(d.toks[3].suffix);
        assert_eq!(d.line_toks(1), 4..7);
        assert_eq!(d.toks[0].key, "davaci");
        assert_eq!(d.gap(4), "/");
    }
}
