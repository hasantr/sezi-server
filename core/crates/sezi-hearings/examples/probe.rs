//! The H0 probe (docs/HEARINGS_BOT_PLAN.md §3.2). Run it on a real hearing record on the
//! machine where the record already is:
//!
//! ```text
//! cd core
//! cargo run --release -q -p sezi-hearings --example probe -- path/to/zabit.pdf [more.pdf …]
//! ```
//!
//! It prints the record's STRUCTURE ONLY — pages, characters per page, fonts and ToUnicode, the
//! usability verdict, which fields were found and their shapes (`NNNN/NNN`), the number of
//! decisions, role counts — and the CPU time it took. It never prints a word of the record, and it
//! sends nothing anywhere. The output is safe to paste into an issue.

use std::time::Instant;

use sezi_hearings::{probe, Limits};

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: probe <file.pdf|file.txt> [more …]");
        std::process::exit(2);
    }
    let limits = Limits::default();
    for (i, path) in paths.iter().enumerate() {
        // The file's NAME can be personal ("Ahmet Yılmaz zabıt.pdf"), so it is not printed either.
        println!("── file {} of {}", i + 1, paths.len());
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                println!("unreadable: {:?}", e.kind());
                continue;
            }
        };
        // One warm-up run, then the median of five, so the figure is the parser's and not the
        // first page fault's.
        let report = probe::report(&bytes, &limits);
        let mut times: Vec<f64> = (0..5)
            .map(|_| {
                let t = Instant::now();
                let r = sezi_hearings::read_file(&bytes, &limits);
                let ms = t.elapsed().as_secs_f64() * 1000.0;
                drop(r);
                ms
            })
            .collect();
        times.sort_by(|a, b| a.total_cmp(b));
        print!("{report}");
        println!("cpu_ms_median: {:.2}", times[2]);
    }
}
