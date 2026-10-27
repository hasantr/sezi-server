//! Turkish-aware case folding (§4.2). A plain `to_lowercase` gets "IĞDIR" wrong (`I` is the
//! capital of `ı`, `İ` the capital of `i`), and `'İ'.to_lowercase()` is two characters.

/// Lowercases one character the Turkish way.
pub fn lower(c: char) -> char {
    match c {
        'I' => 'ı',
        'İ' => 'i',
        _ => single(c.to_lowercase(), c),
    }
}

/// Uppercases one character the Turkish way.
pub fn upper(c: char) -> char {
    match c {
        'i' => 'İ',
        'ı' => 'I',
        _ => single(c.to_uppercase(), c),
    }
}

fn single(mut it: impl Iterator<Item = char>, fallback: char) -> char {
    match (it.next(), it.next()) {
        (Some(a), None) => a,
        _ => fallback,
    }
}

/// A combining diacritic (the block decomposed text from a PDF uses).
pub fn is_mark(c: char) -> bool {
    ('\u{0300}'..='\u{036F}').contains(&c)
}

/// The matching key of one character: Turkish-lowercased, then with the dotted/dotless and the
/// diacritic distinctions dropped (`ı`→`i`, `ş`→`s`, `ğ`→`g`…). Matching is deliberately looser
/// than spelling: "YILMAZ", "Yılmaz", "Yilmaz" and "yılmaz" are one name, and a text typed on a
/// keyboard without Turkish letters still matches. Over-matching only over-masks.
pub fn key_char(c: char) -> Option<char> {
    if is_mark(c) {
        return None;
    }
    Some(match lower(c) {
        'ı' | 'î' | 'ì' | 'í' | 'ï' => 'i',
        'ş' => 's',
        'ğ' => 'g',
        'ü' | 'û' | 'ù' | 'ú' => 'u',
        'ö' | 'ô' | 'ò' | 'ó' => 'o',
        'ç' => 'c',
        'â' | 'à' | 'á' | 'ä' => 'a',
        'é' | 'è' | 'ê' | 'ë' => 'e',
        x => latin_lookalike(x).unwrap_or(x),
    })
}

/// The Latin letter a lowercase Cyrillic or Greek letter is drawn like ("а" U+0430 is "a"): a
/// reader and a model take "Fаtma" for Fatma, so the gazetteer, the vocabulary and propagation
/// must too. Only the letters that look the same; a real Cyrillic word just gets an odd key.
fn latin_lookalike(c: char) -> Option<char> {
    Some(match c {
        'а' | 'α' => 'a',
        'в' | 'β' => 'b',
        'с' | 'ϲ' => 'c',
        'ԁ' => 'd',
        'е' | 'ε' => 'e',
        'һ' | 'η' => 'h',
        'і' | 'ι' | 'ї' => 'i',
        'ј' => 'j',
        'к' | 'κ' => 'k',
        'м' | 'μ' => 'm',
        'н' | 'ν' => 'n',
        'о' | 'ο' => 'o',
        'р' | 'ρ' => 'p',
        'ѕ' => 's',
        'т' | 'τ' => 't',
        'у' | 'υ' => 'y',
        'х' | 'χ' => 'x',
        'ζ' => 'z',
        _ => return None,
    })
}

/// The matching key of a string (see [`key_char`]).
pub fn key(s: &str) -> String {
    s.chars().filter_map(key_char).collect()
}

/// The case shape of a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    /// Every letter uppercase ("YILMAZ", and a lone capital "A").
    Upper,
    /// First letter uppercase, the rest lowercase ("Yılmaz").
    Cap,
    /// Every letter lowercase.
    Lower,
    /// Anything else, or no cased letter.
    Mixed,
}

pub fn case_of(word: &str) -> Case {
    let mut it = word.chars().filter(|c| c.is_alphabetic());
    let Some(first) = it.next() else {
        return Case::Mixed;
    };
    let (mut any_up, mut any_low) = (false, false);
    for c in it {
        if c.is_uppercase() {
            any_up = true;
        } else if c.is_lowercase() {
            any_low = true;
        }
    }
    match (first.is_uppercase(), any_up, any_low) {
        (true, _, false) => Case::Upper,
        (true, false, true) => Case::Cap,
        (false, false, _) if first.is_lowercase() => Case::Lower,
        _ => Case::Mixed,
    }
}

/// "ASLİYE HUKUK" → "Asliye Hukuk", the Turkish way.
pub fn title(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut start = true;
    for c in s.chars() {
        if c.is_whitespace() {
            start = true;
            out.push(' ');
        } else if start {
            out.push(upper(c));
            start = false;
        } else {
            out.push(lower(c));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turkish_case_is_not_ascii_case() {
        assert_eq!("IĞDIR".chars().map(lower).collect::<String>(), "ığdır");
        assert_eq!("İSMAİL".chars().map(lower).collect::<String>(), "ismail");
        assert_eq!("istanbul".chars().map(upper).collect::<String>(), "İSTANBUL");
        assert_eq!(title("ASLİYE HUKUK"), "Asliye Hukuk");
        assert_eq!(title("İŞ"), "İş");
    }

    #[test]
    fn keys_join_the_spellings_of_one_name() {
        for v in ["YILMAZ", "Yılmaz", "Yilmaz", "yılmaz", "YİLMAZ"] {
            assert_eq!(key(v), "yilmaz", "{v}");
        }
        assert_eq!(key("ÇAĞLAR ŞENÖZ"), "caglar senoz");
        assert_eq!(case_of("YILMAZ"), Case::Upper);
        assert_eq!(case_of("Yılmaz"), Case::Cap);
        assert_eq!(case_of("yılmaz"), Case::Lower);
        assert_eq!(case_of("McKay"), Case::Mixed);
        assert_eq!(case_of("İ"), Case::Upper);
    }
}
