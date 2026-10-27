//! Every way an input is refused is a code, never a panic: scans, a text layer without
//! ToUnicode, passwords, bombs, deep nesting, too many pages, too much text, and damaged files.

use std::path::{Path, PathBuf};

use lopdf::{dictionary, Document, Object, Stream};
use sezi_hearings::{read_file, read_pdf, read_text, Limits, Refusal};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("{}", path.display()))
}

fn refusal(bytes: &[u8]) -> Refusal {
    read_file(bytes, &Limits::default()).expect_err("should be refused")
}

#[test]
fn a_scan_has_no_text_layer() {
    assert_eq!(refusal(&fixture("scan.pdf")), Refusal::NoTextLayer);
}

#[test]
fn a_text_layer_without_to_unicode_is_no_text_layer() {
    assert_eq!(refusal(&fixture("no_tounicode.pdf")), Refusal::NoTextLayer);
}

#[test]
fn a_password_is_refused_but_an_owner_only_lock_is_read() {
    assert_eq!(refusal(&fixture("encrypted_user.pdf")), Refusal::PdfEncrypted);
    let h = read_file(&fixture("encrypted_owner.pdf"), &Limits::default()).expect("opens without a password");
    assert_eq!(h.summary().case_no.as_deref(), Some("2024/123"));
    match &h.source {
        sezi_hearings::Source::Pdf(p) => assert!(p.encrypted_open),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_decompression_bomb_stops_at_the_page_cap() {
    let bomb = fixture("bomb.pdf");
    assert!(bomb.len() < 64 * 1024, "the fixture is small");
    assert_eq!(refusal(&bomb), Refusal::PdfContentLimit);
}

#[test]
fn not_a_record() {
    assert_eq!(refusal(&fixture("not_a_record.txt")), Refusal::NotARecord);
    assert_eq!(refusal(b"\x00\x01\x02PK\x03\x04binary"), Refusal::UnsupportedType);
    // Pasted text is never told to "send the UYAP PDF".
    assert_eq!(read_text("", &Limits::default()).unwrap_err(), Refusal::NotARecord);
    assert_eq!(read_text("\u{E000}\u{E001} ".repeat(40).as_str(), &Limits::default()).unwrap_err(), Refusal::NotARecord);
}

#[test]
fn size_caps() {
    let limits = Limits::default();
    let big = vec![b'a'; limits.max_input_bytes + 1];
    assert_eq!(refusal(&big), Refusal::TooLarge);
    let long: String = "DURUŞMA ESAS MAHKEME ".repeat(limits.max_chars / 10);
    assert_eq!(read_text(&long, &limits).unwrap_err(), Refusal::TooMuchText);
    // A PDF's extracted text is counted too: a cap below the 20-page record's length.
    let tight = Limits { max_chars: 20_000, ..limits };
    assert_eq!(read_pdf(&fixture("long_20p.pdf"), &tight).unwrap_err(), Refusal::TooMuchText);
}

fn blank_pages(n: usize) -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let mut kids: Vec<Object> = Vec::new();
    for _ in 0..n {
        let content = doc.add_object(Stream::new(dictionary! {}, b"BT ET".to_vec()));
        let page = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        });
        kids.push(page.into());
    }
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => n as i64 }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out).expect("save");
    out
}

#[test]
fn too_many_pages_is_refused_before_any_page_is_read() {
    assert_eq!(refusal(&blank_pages(41)), Refusal::TooManyPages);
    // Forty blank pages are within the cap, and simply have no text.
    assert_eq!(refusal(&blank_pages(40)), Refusal::NoTextLayer);
}

/// A PDF whose page resources nest `depth` dictionaries deep.
fn nested(depth: usize) -> Vec<u8> {
    let deep = "<< /A ".repeat(depth) + &">> ".repeat(depth);
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources {deep} >>"),
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1).as_bytes(),
    );
    out
}

#[test]
fn deep_nesting_is_refused_not_a_stack_overflow() {
    for depth in [50, 500, 50_000] {
        let r = refusal(&nested(depth));
        assert!(
            matches!(r, Refusal::PdfUnreadable | Refusal::NoTextLayer),
            "depth {depth}: {r:?}"
        );
    }
}

/// A tiny deterministic generator: the same mutations on every run and every machine.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

#[test]
fn damaged_pdfs_never_panic() {
    let base = fixture("civil_asliye_hukuk.pdf");
    let mut rng = Lcg(0x5e21);
    let mut panics = Vec::new();
    for round in 0..400 {
        let mut bytes = base.clone();
        match round % 4 {
            0 => bytes.truncate(rng.next() as usize % base.len()),
            1 => {
                for _ in 0..1 + rng.next() % 8 {
                    let at = rng.next() as usize % bytes.len();
                    bytes[at] = rng.next() as u8;
                }
            }
            2 => {
                // Damage the xref and trailer, where offsets live.
                let tail = bytes.len().saturating_sub(600);
                for _ in 0..4 {
                    let at = tail + rng.next() as usize % (bytes.len() - tail);
                    bytes[at] = b"0123456789 /<>[]"[rng.next() as usize % 16];
                }
            }
            _ => {
                let at = rng.next() as usize % bytes.len();
                let len = (rng.next() as usize % 2048).min(bytes.len() - at);
                bytes.drain(at..at + len);
            }
        }
        let caught = std::panic::catch_unwind(|| {
            let _ = read_file(&bytes, &Limits::default());
        });
        if caught.is_err() {
            panics.push(round);
        }
    }
    assert!(panics.is_empty(), "panicked on rounds {panics:?}");
}
