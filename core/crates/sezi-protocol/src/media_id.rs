//! What a `FileManifest::media_id` may be before a device uses it as a FILE NAME.
//!
//! A downloaded or restored attachment lands at `{media_dir}/{media_id}`, and the id comes from
//! the sender's manifest (or a backup file's), not from this device. `Path::join` with `../x`
//! climbs out of the media directory, and with `/home/me/.bashrc` replaces the whole path — so an
//! id that is not one plain file name would let whoever wrote the manifest choose where the
//! decrypted bytes are written. The relay mints UUIDs (`worker-rs/src/media/handlers.rs`); this
//! accepts that alphabet and nothing that could name a directory.

/// A media id longer than this is not one (a UUID is 36).
pub const MAX_MEDIA_ID_LEN: usize = 128;

/// Is `id` safe to use as a single file name inside the media directory: non-empty, at most
/// [`MAX_MEDIA_ID_LEN`] bytes, ASCII letters, digits, `-` and `_` only? No separator, no dot, so
/// no `..`, no absolute path, no drive letter.
pub fn is_safe_media_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_MEDIA_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_id_is_a_file_name_and_a_path_is_not() {
        assert!(is_safe_media_id("3f2b6c1e-8a4d-4f8e-9b7a-1c2d3e4f5a6b"));
        assert!(is_safe_media_id("media-1"));
        for bad in [
            "",
            "..",
            "../escaped.bin",
            "a/b",
            "/home/me/.bashrc",
            "C:\\Windows\\x",
            "x.y",
            "a\0b",
            &"a".repeat(MAX_MEDIA_ID_LEN + 1),
        ] {
            assert!(!is_safe_media_id(bad), "{bad:?}");
        }
    }
}
