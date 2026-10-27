//! The golden set (docs/HEARINGS_BOT_PLAN.md §9): hand-written FAKE minutes in UYAP's layout.
//! Every name is invented, every number is generated (checksum-valid, made up). No real client
//! data ever enters this directory.
//!
//! Each `tests/golden/NN_kind.zabit` marks what must be masked (`{{KISI:…}}`, `{{TCKN:@a}}`…, see
//! `common::parse`). From the marks the test derives the must-never-appear list. Beside it sit
//! `NN_kind.masked.txt` and `NN_kind.vault.json`, the reviewed snapshots
//! (`SEZI_REDACT_BLESS=1 cargo test -p sezi-redact --test golden` rewrites them — read the diff).
//!
//! Merge gates: 100 % recall on every gated mark (tier 1–2 categories and anchored names), the
//! never-appear list holds, restore is the identity outside placeholders, and every masked value
//! put back into the masked text is caught by the leak check. Precision is printed, not gated:
//! `cargo test -p sezi-redact --test golden -- --nocapture`.

mod common;

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use sezi_redact::{leak_check, leak_check_with, redact, restore, Category, Policy, Redacted};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// `SEZI_REDACT_GOLDEN_DIR=/some/dir` runs the same gates over fixtures kept outside the repo
/// (a held-out set someone else wrote), without snapshots.
fn held_out_dir() -> Option<PathBuf> {
    std::env::var_os("SEZI_REDACT_GOLDEN_DIR").map(PathBuf::from)
}

fn seed_of(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}

#[derive(Default)]
struct Tally {
    marks: u32,
    covered: u32,
    same_category: u32,
}

#[test]
fn golden_set() {
    let held_out = held_out_dir();
    let mut files: Vec<PathBuf> = fs::read_dir(held_out.clone().unwrap_or_else(golden_dir))
        .expect("tests/golden")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "zabit"))
        .collect();
    files.sort();
    assert!(held_out.is_some() || files.len() >= 30, "the golden set needs 30+ minutes, has {}", files.len());
    let bless = std::env::var_os("SEZI_REDACT_BLESS").is_some();

    let mut failures = Vec::new();
    let mut by_tag: BTreeMap<String, Tally> = BTreeMap::new();
    let mut ungated: BTreeMap<String, Tally> = BTreeMap::new();
    let (mut masked_bytes, mut masked_bytes_on_marks) = (0usize, 0usize);
    let mut spans_total = 0u32;
    let mut spans_on_marks = 0u32;
    let mut extra_by_cat: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut leaky_tried = 0u32;

    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let fx = common::parse(&fs::read_to_string(path).unwrap(), seed_of(&name));
        let red = match redact(&fx.raw, &Policy::default()) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!("{name}: refused: {e}"));
                continue;
            }
        };

        // Recall.
        for it in &fx.items {
            let hit = common::covered(&red, &fx.raw, &it.range);
            let tally = if it.gated { by_tag.entry(it.tag.clone()).or_default() } else { ungated.entry(it.tag.clone()).or_default() };
            tally.marks += 1;
            if hit {
                tally.covered += 1;
                if common::covering_tag(&red, &it.range) == Some(it.tag.as_str()) {
                    tally.same_category += 1;
                }
            } else if it.gated {
                failures.push(format!("{name}: {} not masked: {:?}", it.tag, it.text));
            } else {
                println!("{name}: not gated, not masked: {} {:?}", it.tag, it.text);
            }
        }

        // Must never appear: every gated value; every word of 3+ letters of a gated person.
        let masked_words: HashSet<String> = common::words(&red.masked).into_iter().collect();
        for it in fx.items.iter().filter(|i| i.gated) {
            if it.text.chars().count() >= 4 && red.masked.contains(&it.text) {
                failures.push(format!("{name}: {:?} appears in the masked text", it.text));
            }
            if it.tag == "KISI" {
                for w in common::words(&it.text).into_iter().filter(|w| w.chars().count() >= 3) {
                    if masked_words.contains(&w) {
                        failures.push(format!("{name}: the word {w:?} of a person appears in the masked text"));
                    }
                }
            }
        }

        // Precision: spans touching no mark.
        for s in &red.spans {
            spans_total += 1;
            for (i, c) in fx.raw[s.original.clone()].char_indices() {
                if c.is_whitespace() {
                    continue;
                }
                let b = s.original.start + i;
                masked_bytes += 1;
                if fx.items.iter().any(|it| it.range.start <= b && b < it.range.end) {
                    masked_bytes_on_marks += 1;
                }
            }
            if fx.items.iter().any(|it| it.range.start < s.original.end && s.original.start < it.range.end) {
                spans_on_marks += 1;
            } else {
                *extra_by_cat.entry(s.placeholder.category.tag()).or_default() += 1;
                if std::env::var_os("SEZI_REDACT_SHOW_EXTRA").is_some() {
                    println!("{name}: extra {} {:?}", s.placeholder, &fx.raw[s.original.clone()]);
                }
            }
        }

        check_restore(&name, &fx.raw, &red, &mut failures);
        leaky_tried += check_leaky(&name, &fx.raw, &red, &mut failures);
        if held_out.is_none() {
            snapshot(&name, &red, bless, &mut failures);
        }
    }

    println!("\nsezi-redact golden set: {} minutes", files.len());
    println!("{:<8} {:>6} {:>8} {:>8} {:>10}", "category", "marks", "masked", "recall", "same-cat");
    for (tag, t) in &by_tag {
        println!(
            "{tag:<8} {:>6} {:>8} {:>7.1}% {:>9.1}%",
            t.marks,
            t.covered,
            100.0 * f64::from(t.covered) / f64::from(t.marks.max(1)),
            100.0 * f64::from(t.same_category) / f64::from(t.marks.max(1))
        );
    }
    for (tag, t) in &ungated {
        println!(
            "{:<8} {:>6} {:>8} {:>7.1}%   (not anchored — reported, not gated)",
            format!("{tag}?"),
            t.marks,
            t.covered,
            100.0 * f64::from(t.covered) / f64::from(t.marks.max(1))
        );
    }
    println!(
        "precision by span: {spans_on_marks}/{spans_total} masked spans touch a mark ({:.1}%); spans touching none, by category: {extra_by_cat:?}",
        100.0 * f64::from(spans_on_marks) / f64::from(spans_total.max(1))
    );
    println!(
        "precision by character: {masked_bytes_on_marks}/{masked_bytes} masked characters lie inside a mark ({:.1}%)",
        100.0 * masked_bytes_on_marks as f64 / masked_bytes.max(1) as f64
    );
    println!("leak check: {leaky_tried} deliberately leaky variants, all refused\n");
    assert!(failures.is_empty(), "{} golden failures:\n{}", failures.len(), failures.join("\n"));
}

/// Outside the placeholders, restore(masked) is the original byte for byte; each placeholder
/// becomes its vault value.
fn check_restore(name: &str, raw: &str, red: &Redacted, failures: &mut Vec<String>) {
    let mut want = String::new();
    let (mut po, mut pm) = (0, 0);
    for s in &red.spans {
        if red.masked[pm..s.masked.start] != raw[po..s.original.start] {
            failures.push(format!("{name}: text outside placeholders changed near byte {po}"));
            return;
        }
        want.push_str(&raw[po..s.original.start]);
        want.push_str(red.vault.get(&s.placeholder).unwrap_or("<missing>"));
        po = s.original.end;
        pm = s.masked.end;
    }
    want.push_str(&raw[po..]);
    if restore(&red.masked, &red.vault) != want {
        failures.push(format!("{name}: restore is not the identity outside placeholders"));
    }
}

/// Put each masked value back, one at a time: the leak check must refuse every variant.
fn check_leaky(name: &str, raw: &str, red: &Redacted, failures: &mut Vec<String>) -> u32 {
    let mut tried = 0;
    let mut seen = HashSet::new();
    for s in &red.spans {
        let original = &raw[s.original.clone()];
        if !seen.insert(original.to_string()) {
            continue;
        }
        let leaky = format!("{}{}{}", &red.masked[..s.masked.start], original, &red.masked[s.masked.end..]);
        tried += 1;
        if leak_check_with(&leaky, &red.vault).is_ok() && !trivially_kept(s.placeholder.category, original) {
            failures.push(format!("{name}: leak check passed with {} put back: {original:?}", s.placeholder));
        }
        // Without the vault, only what needs no context is certain to be seen again: a sicil
        // needs its label line, a birth date its "doğumlu", a code its "doğrulama" — and the label
        // beside it may itself be masked now.
        let context_free = matches!(
            s.placeholder.category,
            Category::Tckn | Category::Iban | Category::Kart | Category::Tel | Category::Eposta | Category::Plaka | Category::Dosya | Category::Esas
        );
        if context_free && leak_check(&leaky).is_ok() && !trivially_kept(s.placeholder.category, original) {
            failures.push(format!("{name}: tier-1/2 leak check passed with {} put back: {original:?}", s.placeholder));
        }
    }
    tried
}

/// Values too short to look for on their own (a bare birth year, a 2-letter word): the vault check
/// skips them by design, and the recognizer that masked them needs context the variant may lack.
fn trivially_kept(cat: Category, original: &str) -> bool {
    let compact: String = original.chars().filter(|c| c.is_alphanumeric()).collect();
    (cat == Category::Dogum && compact.len() == 4) || compact.chars().count() < 3
}

fn snapshot(name: &str, red: &Redacted, bless: bool, failures: &mut Vec<String>) {
    let dir = golden_dir();
    let masked_path = dir.join(format!("{name}.masked.txt"));
    let vault_path = dir.join(format!("{name}.vault.json"));
    let vault: BTreeMap<String, &str> = red.vault.iter().map(|(p, v)| (p.to_string(), v)).collect();
    let vault_json = serde_json::to_string_pretty(&vault).unwrap() + "\n";
    if bless {
        fs::write(&masked_path, &red.masked).unwrap();
        fs::write(&vault_path, &vault_json).unwrap();
        return;
    }
    match (fs::read_to_string(&masked_path), fs::read_to_string(&vault_path)) {
        (Ok(m), Ok(v)) => {
            if m != red.masked {
                failures.push(format!("{name}: masked text differs from {name}.masked.txt"));
            }
            if v != vault_json {
                failures.push(format!("{name}: vault differs from {name}.vault.json"));
            }
        }
        _ => failures.push(format!("{name}: no snapshot (run with SEZI_REDACT_BLESS=1 and review)")),
    }
}
