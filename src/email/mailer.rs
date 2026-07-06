use worker::{console_log, Env, Result};

/// Doğrulama kodu mailer'ı. Gerçek SES/SendGrid entegrasyonu yoksa
/// `console_log!` ile CF Worker tail'ine yazılır — geliştirici
/// `wrangler tail` çekip kodu okur.
///
/// PII koruma: email her zaman maskelenir (ilk 2 char + `***` + @domain).
/// Code görünür kalır; access yalnız worker log'una sahip olanlar
/// (geliştirici/admin). HTTP istemcide görünmez — bu noktada `redeem`
/// endpoint'i ENV=prod'da `dev_code` field'ını response'a koymaz.
///
/// TODO (#1-mailer-sprint): gerçek SES veya SendGrid HTTPS POST. Şu
/// an log'a düşmesi solo kullanım için yeterli geçici çare.
pub async fn send_verification_code(env: &Env, email: &str, code: &str) -> Result<()> {
    let env_name = env
        .var("ENV")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unknown".into());
    console_log!(
        "[verify-mailer env={}] {} için kod: {}",
        env_name,
        mask_email(email),
        code
    );
    Ok(())
}

/// Email adresini log için kısmen maskele: ilk 2 char + *** + @domain.
/// "hsn.salihoglu@gmail.com" → "hs***@gmail.com".
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
