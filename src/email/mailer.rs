use worker::{console_log, Env, Result};

/// The verification-code mailer. Without a real SES/SendGrid integration the code is
/// written to the CF Worker tail with `console_log!` — a developer runs `wrangler tail`
/// and reads it there.
///
/// PII protection: the email is always masked (first 2 chars + `***` + @domain). The
/// code itself stays visible, but access is limited to whoever holds the worker log
/// (developer/admin).
///
/// It is NOT withheld from HTTP clients in every configuration, so do not rely on that.
/// `redeem` returns `dev_code` whenever ENV is not prod OR the server is `invite_only`
/// (`auth/invite.rs`), and invite_only is the schema default. That is deliberate and argued
/// there: in invite_only the invite itself is the registration authority, and the onboarding
/// client registers a synthetic `@sezgi.local` address that no inbox will ever receive. Open
/// mode in prod is the case where the code only travels by mail.
///
/// TODO (#1-mailer-sprint): a real SES or SendGrid HTTPS POST. Logging it is an
/// adequate stopgap for solo use for now.
pub async fn send_verification_code(env: &Env, email: &str, code: &str) -> Result<()> {
    // TEMPLATE DIET: ENV falls back to "prod" when unset (fail-secure), so the log
    // label stays consistent with how redeem/verify actually behave.
    let env_name = crate::utils::var_or(env, "ENV", "prod");
    console_log!(
        "[verify-mailer env={}] code for {}: {}",
        env_name,
        mask_email(email),
        code
    );
    Ok(())
}

/// Partially mask an email address for logging: first 2 chars + *** + @domain.
/// "first.last@example.com" → "fi***@example.com".
///
/// Counted in CHARACTERS, not bytes. It used to guard with `local.len() <= 2` (a byte length)
/// and then slice `&local[..2]` (a char boundary), so any local part whose first character is
/// multi-byte — `{"email":"あ@x.com"}` — sliced through the middle of a UTF-8 sequence and
/// PANICKED, which on wasm is a trap that kills the whole request. It is reachable
/// unauthenticated through `POST /auth/redeem`, and in invite mode the invite has already been
/// flipped to `used=1` by the time the log line runs, so the panic burned the invite. ASCII
/// input is unaffected: for ASCII the character count and the byte length are the same number.
fn mask_email(email: &str) -> String {
    if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at + 1..];
        // `take(2)` then "is there more?" answers "longer than 2 characters" without ever
        // constructing a byte index of its own.
        let mut chars = local.chars();
        let head: String = chars.by_ref().take(2).collect();
        let local_masked = if chars.next().is_none() {
            "**".to_string()
        } else {
            format!("{head}***")
        };
        format!("{}@{}", local_masked, domain)
    } else {
        "***".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::mask_email;

    /// The ASCII shapes are the contract this masking has always had; the char-safety fix must
    /// not move any of them.
    #[test]
    fn ascii_masking_is_unchanged() {
        assert_eq!(mask_email("first.last@example.com"), "fi***@example.com");
        assert_eq!(mask_email("ab@example.com"), "**@example.com");
        assert_eq!(mask_email("a@example.com"), "**@example.com");
        assert_eq!(mask_email("abc@example.com"), "ab***@example.com");
        assert_eq!(mask_email("@example.com"), "**@example.com");
        assert_eq!(mask_email("no-at-sign"), "***");
    }

    /// The regression itself: every one of these panicked on `&local[..2]`. A panic here is a
    /// wasm trap on an UNAUTHENTICATED path, and in invite mode it burns the invite.
    #[test]
    fn a_multibyte_local_part_does_not_panic() {
        assert_eq!(mask_email("あ@x.com"), "**@x.com");
        assert_eq!(mask_email("あい@x.com"), "**@x.com");
        assert_eq!(mask_email("あいう@x.com"), "あい***@x.com");
        assert_eq!(mask_email("é@x.com"), "**@x.com");
        // Mixed width: the guard and the slice must agree on the same unit.
        assert_eq!(mask_email("aé@x.com"), "**@x.com");
        assert_eq!(mask_email("aéb@x.com"), "aé***@x.com");
        // An emoji outside the BMP is 4 bytes in UTF-8.
        assert_eq!(mask_email("🙂@x.com"), "**@x.com");
    }
}
