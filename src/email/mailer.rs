use worker::{console_log, Env, Result};

/// The verification-code mailer. Without a real SES/SendGrid integration the code is
/// written to the CF Worker tail with `console_log!` — a developer runs `wrangler tail`
/// and reads it there.
///
/// PII protection: the email is always masked (first 2 chars + `***` + @domain). The
/// code itself stays visible, but access is limited to whoever holds the worker log
/// (developer/admin). It is never visible to an HTTP client — at this point the
/// `redeem` endpoint does not put the `dev_code` field in the response when ENV=prod.
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
fn mask_email(email: &str) -> String {
    if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at + 1..];
        let local_masked = if local.len() <= 2 {
            "**".to_string()
        } else {
            format!("{}***", &local[..2])
        };
        format!("{}@{}", local_masked, domain)
    } else {
        "***".to_string()
    }
}
