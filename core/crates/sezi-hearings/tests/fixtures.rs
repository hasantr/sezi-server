//! The fake records in `fixtures/` (invented names and numbers, UYAP layout), read as pasted
//! text AND as the PDFs LibreOffice made of them, against `<name>.parse.json`.
//!
//! The expected files are the rule-only summary. They were generated, then read line by line
//! against the fixture; regenerate with `SEZI_HEARINGS_BLESS=1 cargo test -p sezi-hearings --test
//! fixtures` and READ the diff — a changed expectation is a changed parser.

use std::path::{Path, PathBuf};

use sezi_hearings::{read_file, read_pdf, read_text, Limits, RuleSummary};

pub const RECORDS: [&str; 7] = [
    "civil_asliye_hukuk",
    "labour_is",
    "family_aile",
    "enforcement_icra_hukuk",
    "criminal_agir_ceza",
    "civil_split_labels",
    "consumer_mixed_case",
];

/// Records with no PDF: the held-out ones (`tests/accuracy.rs`) and the 5- and 20-page ones.
pub const TEXT_ONLY: [&str; 5] = [
    "heldout_commercial",
    "heldout_criminal_asliye",
    "heldout_pasted",
    "long_5p",
    "long_20p",
];

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn summary_json(s: &RuleSummary) -> String {
    serde_json::to_string_pretty(s).expect("summary serialises") + "\n"
}

fn expected(name: &str, got: &str) -> String {
    let path = dir().join(format!("{name}.parse.json"));
    if std::env::var_os("SEZI_HEARINGS_BLESS").is_some() {
        std::fs::write(&path, got).expect("write expectation");
    }
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{} missing — bless it", path.display()))
}

#[test]
fn every_text_fixture_parses_as_expected() {
    for name in RECORDS.iter().chain(&TEXT_ONLY) {
        let text = std::fs::read_to_string(dir().join(format!("{name}.txt"))).expect("fixture");
        let h = read_text(&text, &Limits::default()).unwrap_or_else(|r| panic!("{name}: {r}"));
        let got = summary_json(&h.summary());
        assert_eq!(got, expected(name, &got), "{name}");
    }
}

#[test]
fn every_pdf_fixture_reads_like_its_text() {
    for name in RECORDS {
        let bytes = std::fs::read(dir().join(format!("{name}.pdf"))).expect("pdf fixture");
        let h = read_pdf(&bytes, &Limits::default()).unwrap_or_else(|r| panic!("{name}: {r}"));
        let got = summary_json(&h.summary());
        let want = std::fs::read_to_string(dir().join(format!("{name}.parse.json"))).expect("expectation");
        assert_eq!(got, want, "{name}: the PDF read differently from its text");
        // `read_file` sniffs the same bytes to the same answer.
        assert_eq!(read_file(&bytes, &Limits::default()).unwrap().summary(), h.summary());
    }
}
