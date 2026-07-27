use crate::auth::me::me_response;
use crate::auth::middleware::require_active_auth;
use crate::d1util::{d1_int, d1_text};
use crate::respond::json_err;
use crate::utils::now_secs;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize, Default)]
struct ProfileBody {
    display_name: String,
}

/// The single validation source for the server-visible display name. Leading and
/// trailing Unicode whitespace is trimmed; invisible bidi/zero-width characters and
/// control characters are rejected. The length bound counts Unicode scalars, not
/// bytes.
pub(crate) fn validate_display_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let len = trimmed.chars().count();
    if !(1..=64).contains(&len) {
        return None;
    }
    if trimmed.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\u{00ad}'
                    | '\u{034f}'
                    | '\u{061c}'
                    | '\u{180e}'
                    | '\u{200b}'
                    | '\u{200c}'
                    | '\u{200d}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{2064}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{206a}'..='\u{206f}'
                    | '\u{feff}'
                    | '\u{fff9}'..='\u{fffb}'
                    | '\u{e0000}'..='\u{e007f}'
            )
    }) {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Change the user's server-wide display name. Local per-contact nicknames are a
/// separate axis; this endpoint only advances the server-side profile_revision.
pub async fn update(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth,
        Err(resp) => return Ok(resp),
    };
    // A profile revision also advances the contact feed of every counterpart account,
    // so bound how many revisions a buggy or automated client can generate.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("profile:update:{}", auth.user_id),
        30,
        3600,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }
    let body: ProfileBody = match req.json().await {
        Ok(body) => body,
        Err(_) => return json_err(400, "bad_request"),
    };
    let Some(display_name) = validate_display_name(&body.display_name) else {
        return json_err(400, "invalid_display_name");
    };

    let db = ctx.env.d1("DB")?;
    #[derive(Deserialize)]
    struct CurrentName {
        display_name: Option<String>,
    }
    let current: Option<CurrentName> = db
        .prepare("SELECT display_name FROM users WHERE id=? LIMIT 1")
        .bind(&[d1_text(&auth.user_id)])?
        .first(None)
        .await?;
    if current.and_then(|r| r.display_name).as_deref() == Some(display_name.as_str()) {
        return me_response(&ctx.env, &auth.user_id).await;
    }
    let now = now_secs() as i64;
    db.batch(vec![
        db.prepare(
            "UPDATE users
                SET display_name = ?, profile_revision = profile_revision + 1
              WHERE id = ? AND COALESCE(display_name, '') != ?",
        )
        .bind(&[
            d1_text(&display_name),
            d1_text(&auth.user_id),
            d1_text(&display_name),
        ])?,
        db.prepare(
            "INSERT OR IGNORE INTO directory_revisions
               (event_id,user_id,change_type,profile_revision,created_at)
             SELECT 'profile:' || id || ':' || profile_revision,
                    id,'upsert',profile_revision,?
               FROM users WHERE id=? AND display_name=?",
        )
        .bind(&[d1_int(now), d1_text(&auth.user_id), d1_text(&display_name)])?,
        db.prepare(
            "INSERT OR IGNORE INTO contact_revisions
               (event_id,account_id,peer_id,entity,entity_id,action,created_at)
             SELECT 'profile:' || u.id || ':' || u.profile_revision || ':' ||
                    CASE WHEN g.user_low=u.id THEN g.user_high ELSE g.user_low END,
                    CASE WHEN g.user_low=u.id THEN g.user_high ELSE g.user_low END,
                    u.id,'authorization','profile:' || u.id,'upsert',?
               FROM users u JOIN contact_grants g
                 ON (g.user_low=u.id OR g.user_high=u.id) AND g.revoked_at IS NULL
              WHERE u.id=? AND u.display_name=?",
        )
        .bind(&[d1_int(now), d1_text(&auth.user_id), d1_text(&display_name)])?,
    ])
    .await?;

    crate::realtime::nudge_grant_counterparts_best_effort(&ctx.env, &auth.user_id).await;
    me_response(&ctx.env, &auth.user_id).await
}

#[cfg(test)]
mod tests {
    use super::validate_display_name;

    #[test]
    fn name_is_trimmed_and_unicode_scalar_limited() {
        assert_eq!(
            validate_display_name("  İpek 🌿  ").as_deref(),
            Some("İpek 🌿")
        );
        assert!(validate_display_name("").is_none());
        assert!(validate_display_name(&"a".repeat(65)).is_none());
        assert!(validate_display_name(&"界".repeat(64)).is_some());
    }

    #[test]
    fn invisible_and_direction_controls_are_rejected() {
        for bad in [
            "Ha\u{00ad}san",
            "Ha\u{200b}san",
            "Ha\u{202e}san",
            "Ha\u{2067}san",
            "Ha\nsan",
        ] {
            assert!(validate_display_name(bad).is_none(), "accepted {bad:?}");
        }
    }
}
