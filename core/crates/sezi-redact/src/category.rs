//! What a masked value was, and the ASCII placeholder that stands for it (§4.6).

use core::fmt;
use core::ops::Range;

/// The kind of a masked value. Its [`tag`](Category::tag) is the placeholder's name: ASCII on
/// purpose, so a model cannot "correct" `KİŞİ` into `Kişi` and break the round trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// A person, anchored on a legal role or harvested from one (`[KISI_n]`).
    Kisi,
    /// A company, cooperative, foundation or association (`[SIRKET_n]`).
    Sirket,
    /// T.C. kimlik no, checksum-valid (`[TCKN_n]`).
    Tckn,
    /// Vergi kimlik no: GİB checksum, or any 10 digits beside "VKN"/"vergi" (`[VKN_n]`).
    Vkn,
    /// A Turkish IBAN (`[IBAN_n]`).
    Iban,
    /// A payment card number, Luhn-valid (`[KART_n]`).
    Kart,
    /// A Turkish phone number (`[TEL_n]`).
    Tel,
    /// An e-mail or KEP address (`[EPOSTA_n]`).
    Eposta,
    /// A vehicle plate (`[PLAKA_n]`).
    Plaka,
    /// A date of birth (`[DOGUM_n]`).
    Dogum,
    /// Another file's number: esas, karar, talimat, soruşturma… (`[DOSYA_n]`).
    Dosya,
    /// A UYAP verification or barcode code — it can fetch the document (`[KOD_n]`).
    Kod,
    /// A judge's, clerk's, prosecutor's or lawyer's registry number (`[SICIL_n]`).
    Sicil,
    /// A postal address (`[ADRES_n]`).
    Adres,
    /// Residual net: an all-caps run that is not court vocabulary (`[AD_n]`).
    Ad,
    /// Residual net: a long digit run that is not a date or an amount (`[NUMARA_n]`).
    Numara,
    /// The record's own esas no (`[ESAS]`, never numbered).
    Esas,
    /// The record's court city and number (`[MAHKEME]`, never numbered; the type stays).
    Mahkeme,
}

impl Category {
    /// Every category, in placeholder-table order.
    pub const ALL: [Category; 18] = [
        Category::Kisi,
        Category::Sirket,
        Category::Tckn,
        Category::Vkn,
        Category::Iban,
        Category::Kart,
        Category::Tel,
        Category::Eposta,
        Category::Plaka,
        Category::Dogum,
        Category::Dosya,
        Category::Kod,
        Category::Sicil,
        Category::Adres,
        Category::Ad,
        Category::Numara,
        Category::Esas,
        Category::Mahkeme,
    ];

    /// The placeholder name, e.g. `KISI`.
    pub const fn tag(self) -> &'static str {
        match self {
            Category::Kisi => "KISI",
            Category::Sirket => "SIRKET",
            Category::Tckn => "TCKN",
            Category::Vkn => "VKN",
            Category::Iban => "IBAN",
            Category::Kart => "KART",
            Category::Tel => "TEL",
            Category::Eposta => "EPOSTA",
            Category::Plaka => "PLAKA",
            Category::Dogum => "DOGUM",
            Category::Dosya => "DOSYA",
            Category::Kod => "KOD",
            Category::Sicil => "SICIL",
            Category::Adres => "ADRES",
            Category::Ad => "AD",
            Category::Numara => "NUMARA",
            Category::Esas => "ESAS",
            Category::Mahkeme => "MAHKEME",
        }
    }

    /// The category whose [`tag`](Category::tag) this is.
    pub fn from_tag(tag: &str) -> Option<Category> {
        Category::ALL.iter().copied().find(|c| c.tag() == tag)
    }

    /// `[ESAS]` and `[MAHKEME]` carry no number: a record has one of each.
    pub const fn is_numbered(self) -> bool {
        !matches!(self, Category::Esas | Category::Mahkeme)
    }

    /// The recognizer tier (§4.3): 1 checksum, 2 pattern, 3 anchored name, 4 residual net.
    pub const fn tier(self) -> u8 {
        match self {
            Category::Tckn | Category::Vkn | Category::Iban | Category::Kart => 1,
            Category::Kisi | Category::Sirket => 3,
            Category::Ad | Category::Numara => 4,
            _ => 2,
        }
    }

    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

/// One placeholder: `[KISI_3]`, or `[ESAS]` (`n == 0` for the unnumbered two).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Placeholder {
    pub category: Category,
    pub n: u16,
}

/// The largest number a placeholder may carry (`\d{1,3}` in §4.6).
pub const MAX_PLACEHOLDER_N: u16 = 999;

impl Placeholder {
    pub const fn new(category: Category, n: u16) -> Placeholder {
        Placeholder { category, n }
    }

    /// Reads `s` as exactly one placeholder.
    pub fn parse(s: &str) -> Option<Placeholder> {
        match parse_at(s.as_bytes(), 0) {
            Some((p, end)) if end == s.len() => Some(p),
            _ => None,
        }
    }
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.category.is_numbered() {
            write!(f, "[{}_{}]", self.category.tag(), self.n)
        } else {
            write!(f, "[{}]", self.category.tag())
        }
    }
}

/// Every valid placeholder in `text` with its byte range, in order. The validator of a model's
/// answer (H4) uses this to check that each one exists in the vault.
pub fn placeholders_in(text: &str) -> Vec<(Range<usize>, Placeholder)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'[' {
            if let Some((p, end)) = parse_at(b, i) {
                out.push((i..end, p));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn parse_at(b: &[u8], i: usize) -> Option<(Placeholder, usize)> {
    if b.get(i) != Some(&b'[') {
        return None;
    }
    let mut j = i + 1;
    while j < b.len() && b[j].is_ascii_uppercase() {
        j += 1;
    }
    // The tag is ASCII uppercase, so this slice is valid UTF-8.
    let tag = core::str::from_utf8(&b[i + 1..j]).ok()?;
    let cat = Category::from_tag(tag)?;
    match b.get(j)? {
        b']' if !cat.is_numbered() => Some((Placeholder::new(cat, 0), j + 1)),
        b'_' if cat.is_numbered() => {
            let k = j + 1;
            let mut m = k;
            while m < b.len() && m - k < 4 && b[m].is_ascii_digit() {
                m += 1;
            }
            if m == k || m - k > 3 || b.get(m) != Some(&b']') || b[k] == b'0' {
                return None;
            }
            let n: u16 = core::str::from_utf8(&b[k..m]).ok()?.parse().ok()?;
            Some((Placeholder::new(cat, n), m + 1))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_round_trip_and_reject_lookalikes() {
        for c in Category::ALL {
            let p = Placeholder::new(c, if c.is_numbered() { 12 } else { 0 });
            assert_eq!(Placeholder::parse(&p.to_string()), Some(p));
        }
        for bad in ["[KİŞİ_1]", "[KISI]", "[ESAS_1]", "[KISI_0]", "[KISI_1000]", "[KISI_01]", "[kisi_1]"] {
            assert_eq!(Placeholder::parse(bad), None, "{bad}");
        }
        let found = placeholders_in("a [KISI_1]'ın [ESAS] [X_1] [TEL_22]");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].0, 2..10);
    }
}
