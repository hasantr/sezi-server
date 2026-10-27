//! The probe prints STRUCTURE ONLY (docs/HEARINGS_BOT_PLAN.md §3.2). Over every fixture, as text
//! and as PDF: no word of the record appears in its report, nor any of its numbers or dates; and
//! the report's verdict is the bot's.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sezi_hearings::{probe, read_file, Limits};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn fixtures() -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = std::fs::read_dir(dir())
        .expect("fixtures")
        .map(|e| e.expect("entry").path())
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("txt" | "pdf")))
        .collect();
    all.sort();
    all
}

/// Turkish-aware lower case, enough to compare words.
fn lower(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'I' => 'ı',
            'İ' => 'i',
            c => c.to_lowercase().next().unwrap_or(c),
        })
        .collect()
}

fn words(s: &str, min: usize) -> BTreeSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= min)
        .map(lower)
        .collect()
}

#[test]
fn the_report_carries_no_word_of_the_record() {
    let limits = Limits::default();
    let mut checked = 0;
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        // The words of the record: from the text fixture of the same stem (a PDF's text is that).
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let source = dir().join(format!("{stem}.txt"));
        let source = if source.exists() { source } else { dir().join("civil_asliye_hukuk.txt") };
        let text = std::fs::read_to_string(&source).unwrap();

        let report = probe::report(&std::fs::read(&path).unwrap(), &limits).to_string();
        let report_words = words(&report, 1);
        // Every letter word of 3+ characters, and every number of 4+ digits (years, file and sicil
        // numbers). Shorter numbers are left out only because the report's own counts would
        // collide with them by chance; the dates and file numbers are covered by their years.
        let leaked: Vec<String> = words(&text, 3)
            .into_iter()
            .filter(|w| {
                let numeric = w.chars().all(|c| c.is_ascii_digit());
                (!numeric || w.len() >= 4) && report_words.contains(w)
            })
            .collect();
        assert!(leaked.is_empty(), "{name}: the probe printed {leaked:?}\n{report}");
        checked += 1;
    }
    assert!(checked >= 15, "only {checked} fixtures");
}

#[test]
fn the_reports_verdict_is_the_bots() {
    let limits = Limits::default();
    for path in fixtures() {
        let bytes = std::fs::read(&path).unwrap();
        let bot = read_file(&bytes, &limits).err();
        assert_eq!(probe::report(&bytes, &limits).refusal(), bot, "{}", path.display());
    }
}

#[test]
fn a_report_reads_like_this() {
    let bytes = std::fs::read(dir().join("civil_asliye_hukuk.pdf")).unwrap();
    let report = probe::report(&bytes, &Limits::default()).to_string();
    for line in [
        "verdict: usable",
        "input: pdf",
        "pages: 1",
        "case_no: yes · Label · NNNN/NNN",
        "court: yes · CivilGeneral · place yes · number yes",
        "hearing: yes · Slash · time yes",
        "next_hearing: yes · Slash · time yes",
        "sets_next_hearing: 1",
        "missing: []",
    ] {
        assert!(report.lines().any(|l| l == line), "no {line:?} in\n{report}");
    }
    assert!(report.lines().any(|l| l.starts_with("decisions: 4 ")), "{report}");
    // A refused PDF still shows its structure.
    let scan = probe::report(&std::fs::read(dir().join("no_tounicode.pdf")).unwrap(), &Limits::default()).to_string();
    assert!(scan.contains("verdict: refused hearings/no-text-layer"), "{scan}");
    assert!(scan.contains("fonts: 1 (to_unicode 0, unmappable 1)"), "{scan}");
}
