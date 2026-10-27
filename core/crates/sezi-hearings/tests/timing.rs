//! A CPU sanity check, natively, for 1, 5 and 20 pages: the whole read (lopdf extraction,
//! normalising, the usability check, parsing). It prints the figures and fails only on a
//! regression of an order of magnitude — the bound is for an unoptimised test build.
//!
//! The figure that decides the Workers plan (10 ms of CPU per invocation on Free) is the WASM
//! one on workerd, which needs the lab: see docs/HEARINGS_BOT_PLAN.md §3.1 and "What it costs" in
//! this crate's `lib.rs`. For the release-build native figure run the probe:
//! `cargo run --release -q -p sezi-hearings --example probe -- crates/sezi-hearings/fixtures/long_20p.pdf`.

use std::path::Path;
use std::time::Instant;

use sezi_hearings::{read_pdf, Limits, Source};

#[test]
fn reading_cost_per_page_count() {
    let limits = Limits::default();
    for (name, pages) in [("civil_asliye_hukuk.pdf", 1), ("long_5p.pdf", 5), ("long_20p.pdf", 20)] {
        let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)).unwrap();
        let first = read_pdf(&bytes, &limits).expect("reads");
        match &first.source {
            Source::Pdf(p) => assert_eq!(p.pages, pages, "{name}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(first.record.decisions.len(), 4, "{name}");
        let mut ms: Vec<f64> = (0..5)
            .map(|_| {
                let t = Instant::now();
                let h = read_pdf(&bytes, &limits).expect("reads");
                let elapsed = t.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(h.summary(), first.summary());
                elapsed
            })
            .collect();
        ms.sort_by(|a, b| a.total_cmp(b));
        eprintln!("{pages:>2} pages: median {:.2} ms (min {:.2}, max {:.2})", ms[2], ms[0], ms[4]);
        assert!(ms[2] < 150.0 * pages as f64, "{name}: {:.1} ms", ms[2]);
    }
}
