//! Non-authoritative live nudges sent to a UserInbox.
//!
//! D1 is always the source of truth. `contact_update` only wakes the client into a
//! revision pull; losing one costs neither security nor durability.

use crate::d1util::d1_text;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct RevisionRow {
    revision: i64,
}

#[derive(Deserialize)]
struct PeerRow {
    peer_id: String,
    revision: i64,
}

const COUNTERPART_NUDGE_LIMIT: i64 = 24;

async fn send_control(env: &Env, user_id: &str, path: &str, body: String) -> Result<()> {
    let namespace = env.durable_object("USER_INBOX")?;
    let stub = namespace.id_from_name(user_id)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    init.with_headers(headers);
    let req = Request::new_with_init(&format!("https://do.sezgi{path}"), &init)?;
    let resp = stub.fetch_with_request(req).await?;
    if !(200..300).contains(&resp.status_code()) {
        return Err(Error::RustError(format!(
            "inbox_control_status_{}",
            resp.status_code()
        )));
    }
    Ok(())
}

pub(crate) async fn nudge_contact_update_at(env: &Env, user_id: &str, revision: i64) -> Result<()> {
    send_control(
        env,
        user_id,
        "/contact-update",
        serde_json::json!({"revision": revision}).to_string(),
    )
    .await
}

/// A live nudge that carries no group-membership or epoch authority — it only wakes
/// `RefreshGroups`. Offline devices do the same pull on boot/resume.
pub(crate) async fn nudge_group_update(env: &Env, user_id: &str) -> Result<()> {
    send_control(env, user_id, "/group-update", "{}".into()).await
}

/// A best-effort WS nudge carrying that account's latest revision.
pub(crate) async fn nudge_contact_update(env: &Env, user_id: &str) -> Result<()> {
    let db = env.d1("DB")?;
    let row: Option<RevisionRow> = db
        .prepare(
            "SELECT COALESCE(MAX(revision), 0) AS revision
               FROM contact_revisions WHERE account_id = ?",
        )
        .bind(&[d1_text(user_id)])?
        .first(None)
        .await?;
    let revision = row.map(|r| r.revision).unwrap_or(0);
    nudge_contact_update_at(env, user_id, revision).await
}

/// Permanently closes a member's inbox after their row is deleted from D1.
pub(crate) async fn purge_account_inbox(env: &Env, user_id: &str) -> Result<()> {
    send_control(env, user_id, "/purge-account", "{}".into()).await
}

/// Live nudges are not authoritative: log them visibly without affecting handler success.
pub(crate) async fn nudge_contact_update_best_effort(env: &Env, user_id: &str) {
    if let Err(error) = nudge_contact_update(env, user_id).await {
        console_warn!("contact_update nudge failed user={user_id}: {error:?}");
    }
}

/// Wakes an account's active contact-grant counterparties so they pull the new profile
/// and device-list material. The grant list is derived from D1; the frame itself
/// carries no data.
pub(crate) async fn nudge_grant_counterparts_best_effort(env: &Env, user_id: &str) {
    let Ok(db) = env.d1("DB") else { return };
    let peers: Vec<PeerRow> = match db
        .prepare(
            "SELECT peers.peer_id,COALESCE((SELECT MAX(revision) FROM contact_revisions
                                      WHERE account_id=peers.peer_id),0) AS revision
               FROM (SELECT CASE WHEN user_low=?1 THEN user_high ELSE user_low END AS peer_id
                       FROM contact_grants
                      WHERE (user_low=?1 OR user_high=?1) AND revoked_at IS NULL) AS peers
              ORDER BY peers.peer_id LIMIT ?2",
        )
        .bind(&[
            d1_text(user_id),
            crate::d1util::d1_int(COUNTERPART_NUDGE_LIMIT),
        ]) {
        Ok(stmt) => match stmt.all().await.and_then(|r| r.results()) {
            Ok(rows) => rows,
            Err(error) => {
                console_warn!("contact counterpart lookup failed user={user_id}: {error:?}");
                return;
            }
        },
        Err(error) => {
            console_warn!("contact counterpart bind failed user={user_id}: {error:?}");
            return;
        }
    };
    for peer in peers {
        if let Err(error) = nudge_contact_update_at(env, &peer.peer_id, peer.revision).await {
            console_warn!(
                "contact_update nudge failed user={}: {error:?}",
                peer.peer_id
            );
        }
    }
}
