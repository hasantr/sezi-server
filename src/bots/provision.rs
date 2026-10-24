//! A bot's D1 rows: its account, its one device and keys, and a contact grant to every human
//! (docs/BOTS_BUILD.md §2.1–§2.2).
//!
//! The account is written with the same row shapes registration and the device-list PUT use
//! (`auth/verify.rs`, `devices/handlers.rs`), so every existing read — the bundle, the signed
//! list, `DIRECT_AUTHZ_SQL`, the 1:1 send's device check — serves a bot without knowing it is
//! one. What a bot never gets is a `refresh_tokens` row or a JWT.
//!
//! Grants are `source='manual'`, `trust='server_asserted'`: both already pass the CHECK of
//! `0032_contacts_directory_v2.sql`, and a grant is what lets a member reach the bot under a
//! strict `dm_policy`. Each statement is `INSERT OR IGNORE`, so a revoked grant (a member who
//! removed the bot) or a block is never overridden. Only the HUMAN side gets a revision: the bot
//! never pulls its contact feed.

use crate::contact_grant::{contact_pair_block_guard_sql, contact_pair_order_sql};
use crate::d1util::{d1_blob, d1_int, d1_opt_text, d1_prekey_id, d1_text};
use crate::utils::b64_decode;
use sezi_bot_engine::Registration;
use worker::*;

/// One-time keys made at creation. Every member device claims one when it first fetches the
/// bot's bundle (§2.1: 80 members × 2 devices ≈ 160), and the tick tops the pool back up.
pub(crate) const OTK_POOL_TARGET: usize = 200;
/// Below this many unconsumed keys the tick tops the pool up to [`OTK_POOL_TARGET`].
pub(crate) const OTK_LOW_WATER: i64 = 100;
/// How many bots one server may hold (deleted ones not counted).
pub(crate) const MAX_BOTS: i64 = 50;
/// Members nudged live when a bot appears or goes; the rest pull on boot/resume.
pub(crate) const NUDGE_LIMIT: i64 = 12;

/// Bind: id, email, identity_pubkey, identity_ed_pub, display_name, device_list_rev, now.
pub(crate) const INSERT_BOT_USER_SQL: &str = "INSERT INTO users
       (id, email, identity_pubkey, identity_ed_pub, display_name, fcm_token, role, kind,
        directory_visibility, device_list_rev, created_at, last_seen_at)
     VALUES (?1, ?2, ?3, ?4, ?5, NULL, 'member', 'bot', 'hidden', ?6, ?7, NULL)";

/// Bind: bot_id, name, about, created_by, now.
pub(crate) const INSERT_BOT_SQL: &str = "INSERT INTO bots
       (bot_id, name, about, builtin, created_by, created_at)
     VALUES (?1, ?2, ?3, NULL, ?4, ?5)";

/// Bind: user_id, rev, doc_json, sig_b64, now.
pub(crate) const INSERT_DEVICE_LIST_SQL: &str = "INSERT INTO device_lists
       (user_id, rev, doc_json, sig_b64, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)";

/// Bind: user_id, device_id, ed_pub, x_pub, label, added_at_ms.
pub(crate) const INSERT_DEVICE_SQL: &str = "INSERT INTO devices
       (user_id, device_id, role, ed_pub, x_pub, label, added_at, revoked_at)
     VALUES (?1, ?2, 'primary', ?3, ?4, ?5, ?6, NULL)";

/// Bind: user_id, prekey_id (53-bit masked), prekey_pub, signature, now, device_id.
pub(crate) const INSERT_SPK_SQL: &str = "INSERT INTO signed_prekeys
       (user_id, prekey_id, prekey_pub, signature, created_at, device_id)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

/// A grant between the new bot and every human. Bind: bot_id, now.
pub(crate) const GRANT_ALL_HUMANS_SQL: &str = concat!(
    "INSERT OR IGNORE INTO contact_grants
       (grant_id, user_low, user_high, source, trust, accepted_request_id,
        created_at, revoked_at, revoked_by)
     SELECT 'bot:' || ?1 || ':' || u.id, ",
    contact_pair_order_sql!("u.id", "?1"),
    ", 'manual', 'server_asserted', NULL, ?2, NULL, NULL
       FROM users u
      WHERE u.kind = 'human' AND u.id != ?1 AND ",
    contact_pair_block_guard_sql!("u.id", "?1")
);

/// The human side's revision for each of the bot's active grants. Bind: bot_id, now.
pub(crate) const GRANT_REVISIONS_FOR_BOT_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id, account_id, peer_id, entity, entity_id, action, created_at)
     SELECT g.grant_id || ':upsert',
            CASE WHEN g.user_low = ?1 THEN g.user_high ELSE g.user_low END,
            ?1, 'grant', g.grant_id, 'upsert', ?2
       FROM contact_grants g
      WHERE (g.user_low = ?1 OR g.user_high = ?1) AND g.revoked_at IS NULL";

/// A joiner gets a grant to every bot not deleted — a DISABLED one too: it stays every older
/// member's contact while it is off, and the joiner should not differ from them when it comes
/// back on. Runs in `auth/verify.rs`'s batch, after the joiner's `users` row. Bind: joiner, now.
pub(crate) const GRANT_BOTS_TO_JOINER_SQL: &str = concat!(
    "INSERT OR IGNORE INTO contact_grants
       (grant_id, user_low, user_high, source, trust, accepted_request_id,
        created_at, revoked_at, revoked_by)
     SELECT 'bot:' || b.bot_id || ':' || ?1, ",
    contact_pair_order_sql!("b.bot_id", "?1"),
    ", 'manual', 'server_asserted', NULL, ?2, NULL, NULL
       FROM bots b
      WHERE b.deleted_at IS NULL AND b.bot_id != ?1
        AND EXISTS (SELECT 1 FROM users j WHERE j.id = ?1 AND j.kind = 'human')
        AND ",
    contact_pair_block_guard_sql!("b.bot_id", "?1")
);

/// The joiner's revision for each bot grant it now holds. Bind: joiner, now.
pub(crate) const GRANT_REVISIONS_FOR_JOINER_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id, account_id, peer_id, entity, entity_id, action, created_at)
     SELECT g.grant_id || ':upsert', ?1, b.bot_id, 'grant', g.grant_id, 'upsert', ?2
       FROM contact_grants g
       JOIN bots b ON b.bot_id = CASE WHEN g.user_low = ?1 THEN g.user_high ELSE g.user_low END
      WHERE (g.user_low = ?1 OR g.user_high = ?1) AND g.revoked_at IS NULL
        AND b.deleted_at IS NULL";

/// Delete, step 1: mark it. Bind: bot_id, now.
pub(crate) const MARK_DELETED_SQL: &str =
    "UPDATE bots SET deleted_at = ?2 WHERE bot_id = ?1 AND deleted_at IS NULL";

/// Delete, step 2: a tombstone revision on the human side of every active grant, so the
/// members' grant sync removes the bot as a contact. Bind: bot_id, now.
pub(crate) const TOMBSTONE_REVISIONS_SQL: &str = "INSERT OR IGNORE INTO contact_revisions
       (event_id, account_id, peer_id, entity, entity_id, action, created_at)
     SELECT g.grant_id || ':tombstone',
            CASE WHEN g.user_low = ?1 THEN g.user_high ELSE g.user_low END,
            ?1, 'grant', g.grant_id, 'tombstone', ?2
       FROM contact_grants g
      WHERE (g.user_low = ?1 OR g.user_high = ?1) AND g.revoked_at IS NULL";

/// Delete, step 3: the `contact_tombstones` rows `contacts/grants.rs::revoke_grant` also writes.
/// Bind: bot_id, now.
pub(crate) const TOMBSTONES_SQL: &str = "INSERT INTO contact_tombstones
       (account_id, entity, entity_id, peer_id, revision, deleted_at)
     SELECT r.account_id, 'grant', r.entity_id, r.peer_id, r.revision, ?2
       FROM contact_revisions r
       JOIN contact_grants g ON g.grant_id = r.entity_id
      WHERE r.event_id = g.grant_id || ':tombstone'
        AND (g.user_low = ?1 OR g.user_high = ?1) AND g.revoked_at IS NULL
     ON CONFLICT(account_id, entity, entity_id) DO UPDATE SET
       peer_id = excluded.peer_id, revision = excluded.revision, deleted_at = excluded.deleted_at";

/// Delete, step 4: revoke the grants themselves. Bind: bot_id, now, revoked_by.
pub(crate) const REVOKE_GRANTS_SQL: &str = "UPDATE contact_grants SET revoked_at = ?2, revoked_by = ?3
      WHERE (user_low = ?1 OR user_high = ?1) AND revoked_at IS NULL";

/// The humans worth a live nudge: the most recently seen. Bind: limit.
pub(crate) const NUDGE_TARGETS_SQL: &str = "SELECT id FROM users WHERE kind = 'human'
      ORDER BY COALESCE(last_seen_at, 0) DESC, id LIMIT ?1";

/// The bot's unconsumed one-time keys on its device. Bind: bot_id, device_id.
pub(crate) const OTK_POOL_SQL: &str = "SELECT COUNT(*) AS n FROM one_time_prekeys
      WHERE user_id = ?1 AND device_id = ?2 AND consumed = 0";

/// `INSERT OR IGNORE` of `n` one-time keys, four binds each: user_id, prekey_id, pub, device_id.
pub(crate) fn otk_insert_sql(n: usize) -> String {
    let rows = vec!["(?, ?, ?, 0, ?)"; n].join(",");
    format!(
        "INSERT OR IGNORE INTO one_time_prekeys (user_id, prekey_id, prekey_pub, consumed, device_id) VALUES {rows}"
    )
}

/// The OTK inserts, 20 keys per statement to stay under D1's placeholder limit.
pub(crate) fn otk_statements(
    db: &D1Database,
    user_id: &str,
    device_id: &str,
    otks: &[(u64, String)],
) -> Result<Vec<D1PreparedStatement>> {
    let mut out = Vec::new();
    for chunk in otks.chunks(20) {
        let mut binds = Vec::with_capacity(chunk.len() * 4);
        for (id, pub_b64) in chunk {
            let p = b64_decode(pub_b64).map_err(|_| Error::RustError("bad otk pub".into()))?;
            binds.push(d1_text(user_id));
            binds.push(d1_prekey_id(*id));
            binds.push(d1_blob(&p));
            binds.push(d1_text(device_id));
        }
        out.push(db.prepare(otk_insert_sql(chunk.len())).bind(&binds)?);
    }
    Ok(out)
}

/// The synthetic, never-deliverable address a bot's `users.email` (UNIQUE NOT NULL) holds.
pub(crate) fn bot_email(bot_id: &str) -> String {
    format!("bot-{bot_id}@bots.invalid")
}

/// What one creation writes.
pub(crate) struct NewBot<'a> {
    pub(crate) bot_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) about: Option<&'a str>,
    pub(crate) owner: &'a str,
    pub(crate) token_hash: &'a str,
    pub(crate) now_s: i64,
    pub(crate) reg: &'a Registration,
}

/// Every statement of a creation, for ONE D1 batch (an implicit transaction): a half-written
/// bot — an account with no device, a device with no grants — is never visible.
pub(crate) fn creation_statements(
    db: &D1Database,
    nb: &NewBot<'_>,
) -> Result<Vec<D1PreparedStatement>> {
    let reg = nb.reg;
    let bad = |what: &str| Error::RustError(format!("bot registration: bad {what}"));
    let doc: crate::devices::handlers::DeviceListDoc =
        serde_json::from_str(&reg.doc_json).map_err(|_| bad("doc_json"))?;
    let entry = doc
        .devices
        .iter()
        .find(|d| d.device_id == reg.device_id)
        .ok_or_else(|| bad("device list"))?;
    let x_pub = b64_decode(&reg.x_pub_b64).map_err(|_| bad("x_pub"))?;
    let ed_pub = b64_decode(&reg.ed_pub_b64).map_err(|_| bad("ed_pub"))?;
    let (spk_id, spk_pub_b64, spk_sig_b64) = &reg.spk;
    let spk_pub = b64_decode(spk_pub_b64).map_err(|_| bad("spk"))?;
    let spk_sig = b64_decode(spk_sig_b64).map_err(|_| bad("spk signature"))?;
    let (id, now) = (nb.bot_id, d1_int(nb.now_s));

    let mut out = vec![
        db.prepare(INSERT_BOT_USER_SQL).bind(&[
            d1_text(id),
            d1_text(&bot_email(id)),
            d1_blob(&x_pub),
            d1_blob(&ed_pub),
            d1_text(nb.name),
            d1_int(doc.rev),
            now.clone(),
        ])?,
        db.prepare(INSERT_BOT_SQL).bind(&[
            d1_text(id),
            d1_text(nb.name),
            d1_opt_text(nb.about),
            d1_text(nb.owner),
            now.clone(),
        ])?,
        db.prepare(INSERT_DEVICE_LIST_SQL).bind(&[
            d1_text(id),
            d1_int(doc.rev),
            d1_text(&reg.doc_json),
            d1_text(&reg.sig_b64),
            now.clone(),
        ])?,
        db.prepare(INSERT_DEVICE_SQL).bind(&[
            d1_text(id),
            d1_text(&reg.device_id),
            d1_blob(&ed_pub),
            d1_blob(&x_pub),
            d1_opt_text(entry.label.as_deref()),
            d1_int(entry.added_at_ms),
        ])?,
        db.prepare(INSERT_SPK_SQL).bind(&[
            d1_text(id),
            d1_prekey_id(*spk_id),
            d1_blob(&spk_pub),
            d1_blob(&spk_sig),
            now.clone(),
            d1_text(&reg.device_id),
        ])?,
    ];
    out.extend(otk_statements(db, id, &reg.device_id, &reg.otks)?);
    out.push(
        db.prepare(super::token::INSERT_TOKEN_SQL)
            .bind(&[d1_text(nb.token_hash), d1_text(id), now.clone()])?,
    );
    out.push(db.prepare(GRANT_ALL_HUMANS_SQL).bind(&[d1_text(id), now.clone()])?);
    out.push(db.prepare(GRANT_REVISIONS_FOR_BOT_SQL).bind(&[d1_text(id), now])?);
    Ok(out)
}

/// Every statement of a soft delete, for one batch. The `users` row and its name stay, so past
/// messages keep their sender (R9 decision 1).
pub(crate) fn deletion_statements(
    db: &D1Database,
    bot_id: &str,
    owner: &str,
    now_s: i64,
) -> Result<Vec<D1PreparedStatement>> {
    let (id, now) = (d1_text(bot_id), d1_int(now_s));
    Ok(vec![
        db.prepare(MARK_DELETED_SQL).bind(&[id.clone(), now.clone()])?,
        db.prepare(super::token::REVOKE_TOKENS_SQL).bind(&[id.clone(), now.clone()])?,
        db.prepare(TOMBSTONE_REVISIONS_SQL).bind(&[id.clone(), now.clone()])?,
        db.prepare(TOMBSTONES_SQL).bind(&[id.clone(), now.clone()])?,
        db.prepare(REVOKE_GRANTS_SQL).bind(&[id, now, d1_text(owner)])?,
    ])
}

/// Live `contact_update` nudges to the most recently seen humans. Best effort.
pub(crate) async fn nudge_humans(env: &Env, db: &D1Database) {
    #[derive(serde::Deserialize)]
    struct Row {
        id: String,
    }
    let rows: Vec<Row> = match db.prepare(NUDGE_TARGETS_SQL).bind(&[d1_int(NUDGE_LIMIT)]) {
        Ok(stmt) => stmt
            .all()
            .await
            .and_then(|r| r.results())
            .unwrap_or_default(),
        Err(_) => return,
    };
    for r in rows {
        crate::realtime::nudge_contact_update_best_effort(env, &r.id).await;
    }
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod tests;
