//! A source-level guard (docs/HEARINGS_BOT_PLAN.md §8.1 "Leaks through logs"): every log line in
//! the hearings bot's files may carry codes and counts only. Each `console_log!` /
//! `console_warn!` / `console_error!` is read from the source; every value it formats — inline
//! `{x}` or a trailing argument — must be one of [`ALLOWED`], and none may be `{:?}` (a `Debug`
//! of a record, a request or an answer would print its words). A new log line that prints
//! anything else fails here, before it can print a name in a relay's log.

/// The hearings bot's own files (not their tests).
const SOURCES: [(&str, &str); 7] = [
    ("builtin_hearings.rs", include_str!("builtin_hearings.rs")),
    ("hearings_pipeline.rs", include_str!("hearings_pipeline.rs")),
    ("hearings_prompt.rs", include_str!("hearings_prompt.rs")),
    ("hearings_validate.rs", include_str!("hearings_validate.rs")),
    ("hearings_answer.rs", include_str!("hearings_answer.rs")),
    ("hearings_audit.rs", include_str!("hearings_audit.rs")),
    ("hearings_sample.rs", include_str!("hearings_sample.rs")),
];

/// What a hearings log line may print: a refusal or outcome code, or a count.
const ALLOWED: [&str; 8] = ["code", "outcome", "NEEDS_PAID_PLAN", "audit.outcome", "n", "pages", "chars", "count"];

const MACROS: [&str; 3] = ["console_log!(", "console_warn!(", "console_error!("];

/// The text between a macro's parentheses, strings respected.
fn args_of(src: &str, open: usize) -> &str {
    let b = src.as_bytes();
    let (mut depth, mut i, mut in_str) = (1, open, false);
    while i < b.len() {
        match (in_str, b[i]) {
            (true, b'\\') => i += 1,
            (true, b'"') => in_str = false,
            (false, b'"') => in_str = true,
            (false, b'(') => depth += 1,
            (false, b')') => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unclosed log macro");
}

/// The format string, and the arguments after it.
fn split(args: &str) -> (&str, Vec<&str>) {
    let a = args.trim();
    assert!(a.starts_with('"'), "a log line's first argument is a literal: {a}");
    let end = a[1..].find('"').map(|i| i + 1).expect("closing quote");
    let fmt = &a[1..end];
    let rest: Vec<&str> = a[end + 1..].split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    (fmt, rest)
}

fn placeholders(fmt: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = fmt;
    while let Some(i) = rest.find('{') {
        if rest[i + 1..].starts_with('{') {
            rest = &rest[i + 2..];
            continue;
        }
        let j = rest[i..].find('}').expect("closing brace") + i;
        out.push(&rest[i + 1..j]);
        rest = &rest[j + 1..];
    }
    out
}

#[test]
fn hearings_log_lines_carry_codes_and_counts_only() {
    let mut seen = 0;
    for (file, src) in SOURCES {
        for m in MACROS {
            for (at, _) in src.match_indices(m) {
                let (fmt, args) = split(args_of(src, at + m.len()));
                seen += 1;
                for p in placeholders(fmt) {
                    let (name, spec) = p.split_once(':').unwrap_or((p, ""));
                    assert!(!spec.contains('?'), "{file}: `{{{p}}}` is a Debug print in {fmt:?}");
                    if !name.is_empty() {
                        assert!(ALLOWED.contains(&name), "{file}: `{{{name}}}` may print content in {fmt:?}");
                    }
                }
                for a in args {
                    assert!(ALLOWED.contains(&a), "{file}: argument `{a}` may print content in {fmt:?}");
                }
            }
        }
    }
    assert!(seen >= 3, "the guard found the log lines it guards ({seen})");
}

#[test]
fn the_guard_catches_what_it_is_for() {
    let bad = r#"console_log!("[bot] hearings {text} {code}"); console_log!("[bot] x {:?}", hearing);"#;
    let first = bad.find(MACROS[0]).unwrap() + MACROS[0].len();
    let (fmt, _) = split(args_of(bad, first));
    assert!(placeholders(fmt).iter().any(|p| !ALLOWED.contains(p)), "a {{text}} is caught");
    let second = bad[first..].find(MACROS[0]).unwrap() + first + MACROS[0].len();
    let (fmt, args) = split(args_of(bad, second));
    assert_eq!((placeholders(fmt), args), (vec![":?"], vec!["hearing"]));
}
