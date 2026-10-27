//! Tier-2 patterns other than phones and addresses (§4.3): e-mail/KEP, plates, birth dates,
//! case numbers, UYAP verification codes and registry (sicil) numbers.

use crate::category::Category;
use crate::court;
use crate::span::Cand;
use crate::token::{Doc, Kind};

pub fn scan(doc: &Doc, own_esas: Option<&str>, out: &mut Vec<Cand>) {
    email(doc, out);
    plate(doc, out);
    birth(doc, out);
    case_numbers(doc, own_esas, out);
    // Sicil before codes: a clerk's number beside "e-imzalıdır" is both, and the first wins a tie.
    sicil(doc, out);
    codes(doc, out);
    dashed_codes(doc, out);
}

fn email(doc: &Doc, out: &mut Vec<Cand>) {
    let text = doc.text();
    let local_ok = |c: char| c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-');
    let domain_ok = |c: char| c.is_alphanumeric() || matches!(c, '.' | '-');
    for (at, _) in text.match_indices('@') {
        // A text layer (or a hand) may set the `@` apart: "ayse.kaya @ ornek.com.tr".
        let lb = at - text[..at].bytes().rev().take(2).take_while(|&b| b == b' ').count();
        let db = at + 1 + text[at + 1..].bytes().take(2).take_while(|&b| b == b' ').count();
        let s = text[..lb].char_indices().rev().take_while(|&(_, c)| local_ok(c)).last().map_or(lb, |(i, _)| i);
        let mut e = db + text[db..].chars().take_while(|&c| domain_ok(c)).map(char::len_utf8).sum::<usize>();
        while e > db && text[..e].ends_with(['.', '-']) {
            e -= 1;
        }
        let domain = &text[db..e];
        let tld_ok = domain.rsplit('.').next().is_some_and(|t| t.chars().count() >= 2 && t.chars().all(char::is_alphabetic));
        if s < lb && domain.contains('.') && tld_ok {
            out.push(Cand::new(s, e, Category::Eposta, crate::fold::key(&text[s..e])));
        }
    }
}

/// `06 ABC 123`, `34AB1234`: a city code 01–81, 1–3 Latin capitals, 2–4 digits. Over-masking an
/// odd "50 TL 20" is accepted (§4.3).
fn plate(doc: &Doc, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let small = |g: &str| g.is_empty() || g == " ";
    for i in 0..toks.len().saturating_sub(2) {
        let (a, b, c) = (&toks[i], &toks[i + 1], &toks[i + 2]);
        if a.kind != Kind::Num || a.chars != 2 || b.kind != Kind::Word || c.kind != Kind::Num {
            continue;
        }
        let code: u32 = a.key.parse().unwrap_or(0);
        let letters = doc.t(i + 1);
        if !(1..=81).contains(&code)
            || !(1..=3).contains(&letters.len())
            || !letters.bytes().all(|x| x.is_ascii_uppercase())
            || !(2..=4).contains(&c.chars)
            || !small(doc.gap(i))
            || !small(doc.gap(i + 1))
        {
            continue;
        }
        if doc.prev_char(i).is_some_and(|p| matches!(p, '.' | ',' | '/')) || doc.next_char(i + 2).is_some_and(|n| matches!(n, '/')) {
            continue;
        }
        if doc.gap(i + 2).starts_with([',', '.']) && toks.get(i + 3).is_some_and(|t| t.kind == Kind::Num) && doc.gap(i + 2).len() == 1 {
            continue;
        }
        let ident = format!("{}{}{}", a.key, letters, c.key);
        out.push(Cand::new(a.s, c.e, Category::Plaka, ident));
    }
}

/// A date within 40 characters of "doğum", "doğumlu", "D.T." (§4.3 says 30; "Doğum Yeri ve
/// Tarihi : Ankara 01/01/1990" needs a little more). A bare year counts only right next to it
/// ("1985 doğumlu").
fn birth(doc: &Doc, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let text = doc.text();
    // "çocuk Ela Sönmezer'in (02/07/2018)": a full date in parentheses right after a name.
    for j in 1..toks.len() {
        let Some((s, e, ident)) = date_at(doc, j) else { continue };
        if !ident.contains('.') || !doc.gap_before(j).ends_with('(') || !text[e..].starts_with(')') {
            continue;
        }
        let p = j - 1;
        let name = |k: usize| {
            let t = &toks[k];
            t.kind == Kind::Word && matches!(t.case, crate::fold::Case::Cap | crate::fold::Case::Upper) && !crate::vocab::is_vocab(&t.key)
        };
        if name(p) || (toks[p].suffix && p > 0 && name(p - 1)) {
            out.push(Cand::new(s, e, Category::Dogum, ident));
        }
    }
    for i in 0..toks.len() {
        let t = &toks[i];
        let kw = t.kind == Kind::Word
            && (t.key.starts_with("dogum") || (t.key == "d" && doc.gap(i).starts_with('.') && doc.is(i + 1, "t") && doc.gap(i + 1).starts_with('.')));
        if !kw {
            continue;
        }
        let (ks, ke) = (t.s, if t.key == "d" { toks[i + 1].e } else { t.e });
        for j in i.saturating_sub(12)..(i + 14).min(toks.len()) {
            let Some((s, e, ident)) = date_at(doc, j) else { continue };
            let dist = if e <= ks { text[e..ks].chars().count() } else if s >= ke { text[ke..s].chars().count() } else { 0 };
            let year_only = !ident.contains('.');
            if dist <= 40 && (!year_only || dist <= 3) {
                out.push(Cand::new(s, e, Category::Dogum, ident));
            }
        }
    }
}

const MONTHS: &[&str] = &[
    "ocak", "subat", "mart", "nisan", "mayis", "haziran", "temmuz", "agustos", "eylul", "ekim", "kasim", "aralik",
];

/// A date starting at token `j`: d.m.yyyy or d.m.yy (`.`, `/` or `-`), d Month yyyy, or a year
/// 1900–2039.
fn date_at(doc: &Doc, j: usize) -> Option<(usize, usize, String)> {
    let toks = &doc.toks;
    let a = toks.get(j)?;
    if a.kind != Kind::Num {
        return None;
    }
    if (1..=2).contains(&a.chars) {
        let (b, c) = (toks.get(j + 1)?, toks.get(j + 2)?);
        let (g1, g2) = (doc.gap(j), doc.gap(j + 1));
        // A two-digit year ("01.01.90") too: only a birth's context reads this function.
        let year = c.chars == 4 || (c.chars == 2 && !doc.gap(j + 2).starts_with(['.', '/', '-', ':', ',']));
        if b.kind == Kind::Num && c.kind == Kind::Num && b.chars <= 2 && year && g1 == g2 && matches!(g1, "." | "/" | "-") {
            return Some((a.s, c.e, format!("{}.{}.{}", a.key, b.key, c.key)));
        }
        if b.kind == Kind::Word && MONTHS.contains(&b.key.as_str()) && c.kind == Kind::Num && c.chars == 4 && g1 == " " && g2 == " " {
            return Some((a.s, c.e, format!("{}.{}.{}", a.key, b.key, c.key)));
        }
    }
    let y: u32 = a.key.parse().ok()?;
    let lone = !doc.gap_before(j).ends_with(['.', '/', '-']) && !doc.gap(j).starts_with(['.', '/', '-']);
    (a.chars == 4 && (1900..2040).contains(&y) && lone).then(|| (a.s, a.e, a.key.clone()))
}

/// `yyyy/n`: the record's own esas no → `[ESAS]`, any other → `[DOSYA_n]`. Every such number is
/// masked, not only those followed by "Esas/Karar/…" (§4.3): nothing else in a zabıt is written
/// that way, and a dd/mm/yyyy date never matches (its 4-digit group is not before a slash).
fn case_numbers(doc: &Doc, own: Option<&str>, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    for i in 0..toks.len().saturating_sub(1) {
        let Some(v) = court::esas_at(doc, i) else { continue };
        if doc.gap_before(i).ends_with(['/', '.']) || doc.gap(i + 1).starts_with('/') {
            continue;
        }
        let (s, e) = (toks[i].s, toks[i + 1].e);
        if own == Some(v.as_str()) {
            out.push(Cand::new(s, e, Category::Esas, "esas"));
        } else {
            out.push(Cand::new(s, e, Category::Dosya, v));
        }
    }
}

const CODE_KEYWORDS: &[&str] = &[
    "dogrulama", "barkod", "barkodu", "imza", "imzali", "imzalidir", "imzalanmistir", "kod", "kodu", "kodunu",
    "erisebilirsiniz", "sorgulama",
];

/// Anything that looks like a code within 40 characters of "doğrulama", "barkod", "e-imza"… —
/// mixed letters and digits, six or more digits, or letters in mixed case. It can fetch the
/// document, so it never leaves (§4.3).
fn codes(doc: &Doc, out: &mut Vec<Cand>) {
    let text = doc.text();
    let code_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-');
    for (i, t) in doc.toks.iter().enumerate() {
        if t.kind != Kind::Word || !CODE_KEYWORDS.contains(&t.key.as_str()) {
            continue;
        }
        let ws = back_chars(text, t.s, 40);
        let we = fwd_chars(text, doc.toks[i].e, 40);
        let mut k = ws;
        while k < we {
            let run_len: usize = text[k..].chars().take_while(|&c| code_char(c)).map(char::len_utf8).sum();
            if run_len == 0 {
                k += text[k..].chars().next().map_or(1, char::len_utf8);
                continue;
            }
            let (s, mut e) = (k, k + run_len);
            // A run glued to a non-ASCII letter is a word ("e-imzalıdır"), not a code.
            let glued = text[..s].chars().next_back().is_some_and(char::is_alphabetic) || text[e..].chars().next().is_some_and(char::is_alphabetic);
            while e > s && text[..e].ends_with(['-', '/']) {
                e -= 1;
            }
            if !glued && looks_like_code(&text[s..e]) {
                out.push(Cand::new(s, e, Category::Kod, text[s..e].to_string()));
            }
            k += run_len;
        }
    }
}

/// UYAP's e-signature footer writes a document's access code as groups joined by " - "
/// ("qT4mWx9 - Lp2vRnc - 8hYdKs3 - TbW0qe="), and the code fetches the document. Three or more
/// such groups — 4 to 12 code characters each, at least two of them code-like — are one
/// `[KOD_n]` wherever they stand: the keyword window alone missed a group far from
/// "erişebilirsiniz", and one of lowercase letters only.
fn dashed_codes(doc: &Doc, out: &mut Vec<Cand>) {
    let text = doc.text();
    let group_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=');
    // Maximal runs of group characters, not glued to another letter.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut k = 0;
    while k < text.len() {
        let len: usize = text[k..].chars().take_while(|&c| group_char(c)).map(char::len_utf8).sum();
        if len == 0 {
            k += text[k..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        let glued = text[..k].chars().next_back().is_some_and(char::is_alphabetic) || text[k + len..].chars().next().is_some_and(char::is_alphabetic);
        if !glued && (4..=12).contains(&len) {
            runs.push((k, k + len));
        }
        k += len;
    }
    let joined = |a: (usize, usize), b: (usize, usize)| {
        let g = &text[a.1..b.0];
        g.chars().count() <= 6 && g.matches('-').count() == 1 && g.chars().all(|c| matches!(c, ' ' | '\n' | '-')) && g.matches('\n').count() <= 1
    };
    let mut i = 0;
    while i < runs.len() {
        let mut j = i;
        while j + 1 < runs.len() && joined(runs[j], runs[j + 1]) {
            j += 1;
        }
        let coded = runs[i..=j].iter().filter(|&&(s, e)| looks_like_code(&text[s..e]) || has_mixed_case(&text[s..e])).count();
        if j - i >= 2 && coded >= 2 {
            let (s, e) = (runs[i].0, runs[j].1);
            out.push(Cand::new(s, e, Category::Kod, text[s..e].split_whitespace().collect::<String>()));
        }
        i = j + 1;
    }
}

fn has_mixed_case(r: &str) -> bool {
    r.bytes().any(|b| b.is_ascii_uppercase()) && r.bytes().any(|b| b.is_ascii_lowercase()) && r.bytes().skip(1).any(|b| b.is_ascii_uppercase())
}

fn looks_like_code(r: &str) -> bool {
    let n = r.len();
    if !(6..=64).contains(&n) {
        return false;
    }
    let digit = r.bytes().any(|b| b.is_ascii_digit());
    let letter = r.bytes().any(|b| b.is_ascii_alphabetic());
    let all_digits = r.bytes().all(|b| b.is_ascii_digit());
    let inner_upper = r.bytes().skip(1).any(|b| b.is_ascii_uppercase());
    let lower = r.bytes().any(|b| b.is_ascii_lowercase());
    (digit && letter) || (all_digits && n <= 30) || (!digit && inner_upper && lower)
}

fn back_chars(text: &str, at: usize, n: usize) -> usize {
    text[..at].char_indices().rev().take(n).last().map_or(at, |(i, _)| i)
}

fn fwd_chars(text: &str, at: usize, n: usize) -> usize {
    at + text[at..].chars().take(n).map(char::len_utf8).sum::<usize>()
}

const SICIL_ROLES: &[&str] = &[
    "hakim", "hakimi", "katip", "katibi", "savci", "savcisi", "uye", "baskan", "baskani", "zabit",
];

/// On a judge's, clerk's or prosecutor's line, a standalone 5–7 digit number; after "sicil", the
/// next 3–8 digit number (a lawyer's bar registry number too).
fn sicil(doc: &Doc, out: &mut Vec<Cand>) {
    let toks = &doc.toks;
    let has_role = |line: usize| doc.line_toks(line).any(|i| toks[i].kind == Kind::Word && SICIL_ROLES.contains(&toks[i].key.as_str()));
    for line in 0..doc.n_lines() {
        let r = doc.line_toks(line);
        // "HAKİM⏎: MEHMET DEMİR 123456" — the label on the line above (pdftotext without -layout).
        let line_head = |i: usize| doc.gap_before(i).rsplit('\n').next().unwrap_or("").trim_start().starts_with(':');
        let continued = line > 0 && !r.is_empty() && line_head(r.start) && has_role(line - 1);
        if !(has_role(line) || continued) {
            continue;
        }
        for i in r {
            let t = &toks[i];
            if t.kind != Kind::Num || !(5..=7).contains(&t.chars) {
                continue;
            }
            // Part of a date, a time or an amount: glued to another number by one . , / or :
            let glued = |g: &str, other: Option<&crate::token::Tok>| {
                matches!(g, "." | "," | "/" | ":") && other.is_some_and(|o| o.kind == Kind::Num)
            };
            let prev = i.checked_sub(1).and_then(|p| toks.get(p));
            if glued(doc.gap_before(i), prev) || glued(doc.gap(i), toks.get(i + 1)) {
                continue;
            }
            if toks.get(i + 1).is_some_and(|n| matches!(n.key.as_str(), "tl" | "lira" | "try" | "usd" | "eur" | "euro" | "avro")) {
                continue;
            }
            out.push(Cand::new(t.s, t.e, Category::Sicil, t.key.clone()));
        }
    }
    for i in 0..toks.len() {
        // "Sicil No: 12345", and the bar's own way of writing it: "(Antalya Barosu 4127)".
        if !matches!(toks[i].key.as_str(), "sicil" | "barosu" | "baro") {
            continue;
        }
        // The number follows directly, or after "Sicil No :" — on the same line, nothing else
        // between (a masked value in between must not hand the label to the next number).
        let mut j = i + 1;
        while j < toks.len() && j <= i + 4 {
            let g = doc.gap(j - 1);
            if g.contains('\n') || !g.chars().all(|c| matches!(c, ' ' | ':' | '.' | '\'')) {
                break;
            }
            let t = &toks[j];
            if t.kind == Kind::Num {
                if (3..=8).contains(&t.chars) {
                    out.push(Cand::new(t.s, t.e, Category::Sicil, t.key.clone()));
                }
                break;
            }
            if !matches!(t.key.as_str(), "sicil" | "no" | "numarasi" | "nosu" | "sicili" | "nolu") {
                break;
            }
            j += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<(Category, String)> {
        let d = Doc::new(text);
        let mut v = Vec::new();
        scan(&d, Some("2024/123"), &mut v);
        v.into_iter().map(|c| (c.cat, d.text()[c.s..c.e].to_string())).collect()
    }

    #[test]
    fn a_label_on_the_line_above_counts_only_for_its_own_value() {
        // pdftotext: "HAKİM⏎: NAME 123456" — and not the rest of a previous label's line.
        assert!(hits("HAKİM\n: MEHMET DEMİR 123456").contains(&(Category::Sicil, "123456".into())));
        assert!(hits("ÜYE    : ######## ####\nC. SA####VCISI   : #### 635241").is_empty());
    }

    #[test]
    fn patterns() {
        assert!(hits("KEP: ayse.kaya@hs01.kep.tr.").contains(&(Category::Eposta, "ayse.kaya@hs01.kep.tr".into())));
        assert!(hits("plakalı 06 ABC 123 araç").contains(&(Category::Plaka, "06 ABC 123".into())));
        assert!(hits("Ali oğlu, 01/02/1980 doğumlu").contains(&(Category::Dogum, "01/02/1980".into())));
        assert!(hits("1985 doğumlu").contains(&(Category::Dogum, "1985".into())));
        let h = hits("2024/123 Esas, 2023/45 Karar, 14/10/2026");
        assert_eq!(h, [(Category::Esas, "2024/123".into()), (Category::Dosya, "2023/45".into())]);
        assert!(hits("Doğrulama Kodu: aB3+dE9= ile").iter().any(|h| h.0 == Category::Kod && h.1 == "aB3+dE9="));
        assert!(!hits("5070 sayılı Kanun gereği e-imzalıdır").iter().any(|h| h.0 == Category::Kod));
        assert!(hits("HAKİM : MEHMET DEMİR 123456").contains(&(Category::Sicil, "123456".into())));
        assert!(hits("Ankara Barosu Sicil No: 12345").contains(&(Category::Sicil, "12345".into())));
        assert!(!hits("Hakim 14.10.2026 tarihinde 3.000,00").iter().any(|h| h.0 == Category::Sicil));
    }
}
