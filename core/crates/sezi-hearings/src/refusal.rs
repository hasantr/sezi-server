//! Why an input was not read. Every refusal is a code; the runner says the sentence.

use serde::Serialize;

/// An input this crate will not read, as a typed code. [`Refusal::code`] is the wire string
/// (`hearings/…`), the same family as the plan's other `hearings/` codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Larger than [`crate::Limits::max_input_bytes`].
    TooLarge,
    /// Neither a PDF (by its magic bytes) nor text.
    UnsupportedType,
    /// A PDF that needs a password to open.
    PdfEncrypted,
    /// A PDF lopdf cannot parse.
    PdfUnreadable,
    /// More pages than [`crate::Limits::max_pages`].
    TooManyPages,
    /// A page (or an object stream) would decompress past the cap: a decompression bomb, or a
    /// page far denser than any hearing record.
    PdfContentLimit,
    /// More extracted characters than [`crate::Limits::max_chars`].
    TooMuchText,
    /// A PDF with no usable text: a scan, an image-only PDF, a text layer without ToUnicode
    /// (mojibake). The runner answers "send the UYAP PDF".
    NoTextLayer,
    /// Readable text, but none of the anchors of a hearing record (`ESAS`, `MAHKEME`,
    /// `DURUŞMA`); and any pasted text that is empty or garbled.
    NotARecord,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "hearings/too-large",
            Self::UnsupportedType => "hearings/unsupported-type",
            Self::PdfEncrypted => "hearings/pdf-encrypted",
            Self::PdfUnreadable => "hearings/pdf-unreadable",
            Self::TooManyPages => "hearings/too-many-pages",
            Self::PdfContentLimit => "hearings/pdf-content-limit",
            Self::TooMuchText => "hearings/too-much-text",
            Self::NoTextLayer => "hearings/no-text-layer",
            Self::NotARecord => "hearings/not-a-record",
        }
    }

    /// Every refusal, for tests and for the runner's copy table.
    pub const ALL: [Refusal; 9] = [
        Self::TooLarge,
        Self::UnsupportedType,
        Self::PdfEncrypted,
        Self::PdfUnreadable,
        Self::TooManyPages,
        Self::PdfContentLimit,
        Self::TooMuchText,
        Self::NoTextLayer,
        Self::NotARecord,
    ];
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Refusal {}

/// The caps on what one input may cost (docs/HEARINGS_BOT_PLAN.md §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The whole input, PDF or text: 10 MiB.
    pub max_input_bytes: usize,
    /// Pages of a PDF: 40.
    pub max_pages: usize,
    /// Characters of text, extracted or pasted: 200,000.
    pub max_chars: usize,
    /// What one stream may decompress to while the PDF loads (object and xref streams): 8 MiB.
    pub max_stream_bytes: usize,
    /// What one page's content (and its fonts' ToUnicode maps) may decompress to: 4 MiB. A text
    /// page of a hearing record is tens of kilobytes.
    pub max_page_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 10 * 1024 * 1024,
            max_pages: 40,
            max_chars: 200_000,
            max_stream_bytes: 8 * 1024 * 1024,
            max_page_bytes: 4 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct_and_namespaced() {
        let mut codes: Vec<&str> = Refusal::ALL.iter().map(|r| r.code()).collect();
        assert!(codes.iter().all(|c| c.starts_with("hearings/")));
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), Refusal::ALL.len());
    }
}
