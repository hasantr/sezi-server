//! Text out of a PDF's text layer, with lopdf, under caps (docs/HEARINGS_BOT_PLAN.md §3.1).
//!
//! Every limit is checked before the work it bounds: the input's size before parsing, each
//! object stream's inflated size while loading (`LoadOptions::max_decompressed_size`), the page
//! count before any page is read, each page's inflated content while extracting
//! (`extract_text_chunks_with_limit`), and the running character count after each page. Object
//! nesting is bounded by lopdf itself (`MAX_NESTING_DEPTH`, 100, for the page tree, outlines and
//! the reconstruction of a broken xref).

use lopdf::{Document, LoadOptions};
use serde::Serialize;

use crate::refusal::{Limits, Refusal};

/// What the PDF is, as numbers. Never any of its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfFacts {
    pub pages: u32,
    /// Extracted characters per page (whitespace included).
    pub chars_per_page: Vec<u32>,
    /// Fonts per page (by resource name, summed over pages).
    pub fonts: u32,
    /// Of those, how many carry a `/ToUnicode` map.
    pub fonts_with_to_unicode: u32,
    /// Fonts without ToUnicode whose encoding is not a standard one lopdf can map by itself
    /// (`WinAnsiEncoding`, `MacRomanEncoding`, `StandardEncoding`).
    pub fonts_unmappable: u32,
    /// Pages that draw at least one image.
    pub image_pages: u32,
    /// Pages whose text could not be extracted (a font lopdf could not read, a broken stream).
    pub page_errors: u32,
    /// The PDF was encrypted with an empty user password and opened without one.
    pub encrypted_open: bool,
}

/// A PDF's magic bytes: `%PDF-` within the first kilobyte (some writers put junk before it).
pub fn is_pdf(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(1024)].windows(5).any(|w| w == b"%PDF-")
}

/// The text layer of `bytes`, page by page joined with a form feed, and the facts about it.
pub fn extract(bytes: &[u8], limits: &Limits) -> Result<(String, PdfFacts), Refusal> {
    if bytes.len() > limits.max_input_bytes {
        return Err(Refusal::TooLarge);
    }
    if !is_pdf(bytes) {
        return Err(Refusal::UnsupportedType);
    }
    let options = LoadOptions { max_decompressed_size: Some(limits.max_stream_bytes), ..Default::default() };
    let doc = Document::load_mem_with_options(bytes, options).map_err(load_refusal)?;
    // lopdf loads an encrypted PDF it cannot authenticate as an empty shell (no objects) rather
    // than failing; `was_encrypted` says it did decrypt.
    let has_encrypt = doc.trailer.get(b"Encrypt").is_ok();
    if has_encrypt && !doc.was_encrypted() {
        return Err(Refusal::PdfEncrypted);
    }
    let pages = doc.get_pages();
    if pages.len() > limits.max_pages {
        return Err(Refusal::TooManyPages);
    }
    if pages.is_empty() {
        return Err(Refusal::PdfUnreadable);
    }

    let mut facts = PdfFacts {
        pages: pages.len() as u32,
        chars_per_page: Vec::with_capacity(pages.len()),
        fonts: 0,
        fonts_with_to_unicode: 0,
        fonts_unmappable: 0,
        image_pages: 0,
        page_errors: 0,
        encrypted_open: doc.was_encrypted(),
    };
    let mut text = String::new();
    let mut total_chars = 0usize;
    for (&number, &page_id) in &pages {
        if let Ok(fonts) = doc.get_page_fonts(page_id) {
            for font in fonts.values() {
                facts.fonts += 1;
                if font.has(b"ToUnicode") {
                    facts.fonts_with_to_unicode += 1;
                } else if !standard_encoding(&doc, font) {
                    facts.fonts_unmappable += 1;
                }
            }
        }
        if doc.get_page_images(page_id).is_ok_and(|i| !i.is_empty()) {
            facts.image_pages += 1;
        }
        let mut page_text = String::new();
        let mut failed = false;
        for chunk in doc.extract_text_chunks_with_limit(&[number], limits.max_page_bytes) {
            match chunk {
                Ok(s) => page_text.push_str(&s),
                Err(lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. })) => {
                    return Err(Refusal::PdfContentLimit);
                }
                Err(_) => failed = true,
            }
        }
        if failed {
            facts.page_errors += 1;
        }
        let n = page_text.chars().count();
        total_chars += n;
        if total_chars > limits.max_chars {
            return Err(Refusal::TooMuchText);
        }
        facts.chars_per_page.push(n as u32);
        if !text.is_empty() {
            text.push('\u{000C}');
        }
        text.push_str(&page_text);
    }
    Ok((text, facts))
}

fn load_refusal(e: lopdf::Error) -> Refusal {
    match e {
        lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. }) => Refusal::PdfContentLimit,
        lopdf::Error::Decryption(_) | lopdf::Error::InvalidPassword | lopdf::Error::AlreadyEncrypted => {
            Refusal::PdfEncrypted
        }
        _ => Refusal::PdfUnreadable,
    }
}

/// A simple font lopdf can map without ToUnicode: one of the standard 14 with no encoding, or a
/// named standard encoding (possibly with `Differences` over it).
fn standard_encoding(doc: &Document, font: &lopdf::Dictionary) -> bool {
    let subtype = font.get(b"Subtype").and_then(|o| o.as_name()).unwrap_or(b"");
    if subtype == b"Type0" || subtype == b"Type3" {
        return false;
    }
    let encoding = match font.get(b"Encoding") {
        Ok(lopdf::Object::Reference(id)) => doc.get_object(*id).ok(),
        Ok(o) => Some(o),
        Err(_) => None,
    };
    let base = match encoding {
        None => return true,
        Some(lopdf::Object::Name(n)) => Some(n.as_slice()),
        Some(lopdf::Object::Dictionary(d)) => d.get(b"BaseEncoding").and_then(|o| o.as_name()).ok(),
        Some(_) => None,
    };
    matches!(base, Some(b"WinAnsiEncoding" | b"MacRomanEncoding" | b"StandardEncoding"))
}
