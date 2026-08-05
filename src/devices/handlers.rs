//! `PUT /devices/list` + `GET /devices/list/:user_id` — the M1 device list.
//!
//! ## The JWS byte-signature model (CRITICAL)
//! `doc_json` is a JSON STRING field in the outer body whose value is EXACTLY the inner JSON
//! text the client signed. Once serde has parsed the outer body, `body.doc_json` holds that
//! text's verbatim UTF-8 bytes, so the signature is verified over `body.doc_json.as_bytes()`.
//! We NEVER re-serialize the inner document: no canonicalization is required, and the whole
//! class of serialization-difference bugs simply cannot occur. The inner parse exists ONLY to
//! read the fields verification needs (user_id, rev, the primary's ed_pub/x_pub).
//!
//! ## The identity binding chain (the relogin.rs pattern — CRITICAL)
//! The list is signed with the primary device's **Ed25519** key. We cannot validate that Ed
//! key DIRECTLY against `users.identity_pubkey`, because that blob is a Curve25519/DH key —
//! register sends `id.diffie_pubkey()` — and NOT an Ed25519 signing key. So we apply the
//! binding pattern from relogin.rs:
//!   1) Build a `VerifyingKey` from the primary's `ed_pub_b64` in the doc (malformed → 400).
//!   2) **Binding:** fetch the user's NEWEST `signed_prekeys` row. The SPK public key was
//!      signed at registration time by the real identity via `account.sign(spk_pub)`, so if
//!      the claimed Ed key can verify that signature it is CRYPTOGRAPHICALLY bound to the
//!      registered identity (missing row or failed verification → 403).
//!   3) **List signature:** the same Ed key verifies the verbatim bytes of doc_json.
//!   4) **Consistency:** the decoded primary `x_pub_b64` == `users.identity_pubkey`.
//!
//! ## Shared validate-and-store path (M2-S3.2 B6)
//! `put_list` and `link-approve` (see `link.rs`) both go through the SAME
//! `validate_and_store_signed_list`, so there is a single source of verification. The
//! `device_lists` write is **atomically rev-conditional** (`WHERE excluded.rev >
//! device_lists.rev` plus RETURNING): two concurrent writers (link-approve and put_list)
//! cannot fall into a read-then-write race, and the loser gets a 409.

use crate::auth::middleware::{device_revoked, require_active_auth, require_existing_account_auth};
use crate::d1util::{d1_blob, d1_int, d1_opt_text, d1_text};
use crate::respond::json_err;
use crate::utils::{b64_decode, now_ms, now_secs};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::Deserialize;
use worker::*;

const MAX_DEVICES: usize = 5; // 1 primary + ≤4 linked
const MAX_DOC_BYTES: usize = 16 * 1024; // ceiling on the signed document (DoS guard)

/// device_id derivation — at PARITY with core's `devices::device_id_from_ed25519_b64`:
/// `hex(blake3(ed_pub_bytes)[..8])`, i.e. 16 lowercase hex chars. `ed_pub_32` must be 32
/// bytes; the caller checks that. Item 2: on every list write the worker re-derives this for
/// each device, so an entry with a forged device_id cannot leak into the routing state —
/// the ids are self-certifying.
fn derive_device_id(ed_pub_32: &[u8]) -> String {
    let hash = blake3::hash(ed_pub_32);
    hex::encode(&hash.as_bytes()[..8])
}

#[derive(Deserialize)]
struct PutBody {
    doc_json: String,
    sig_b64: String,
}

/// The inner document — parsed ONLY to read fields, never to re-serialize.
#[derive(Deserialize)]
pub(crate) struct DeviceListDoc {
    pub(crate) v: u32,
    pub(crate) user_id: String,
    pub(crate) rev: i64,
    pub(crate) devices: Vec<DeviceEntry>,
    /// Model-B Layer-1: signed tombstones for removed devices. Older docs do not carry the
    /// field, hence the serde default (empty). Because the signature covers the whole doc,
    /// the server cannot add entries here.
    #[serde(default)]
    pub(crate) removed_devices: Vec<DeviceEntry>,
}

#[derive(Deserialize)]
pub(crate) struct DeviceEntry {
    pub(crate) device_id: String,
    pub(crate) role: String,
    pub(crate) ed_pub_b64: String,
    pub(crate) x_pub_b64: String,
    #[serde(default)]
    pub(crate) label: Option<String>,
    pub(crate) added_at_ms: i64,
}

#[derive(Deserialize)]
struct UserRow {
    identity_pubkey: Vec<u8>,
    /// Model-B Layer-1 BLOCKER fix: the device-list rev HIGH-WATER mark. Even if the
    /// `device_lists` row is lost to D1 churn, this one on `users` SURVIVES, so a stale
    /// re-PUT (rev < high_water) is rejected and a revoked device cannot be resurrected.
    #[serde(default)]
    device_list_rev: i64,
}

#[derive(Deserialize)]
struct ListRow {
    doc_json: String,
    sig_b64: String,
    rev: i64,
}

/// Own-list reads are the bootstrap exception; peer-list reads require an
/// already-active device plus the normal direct-contact policy.
fn list_read_requires_active_device(caller: &str, target: &str) -> bool {
    caller != target
}

/// `PUT /devices/list` — upload the primary-signed device list.
/// A thin wrapper: auth + rate-limit + body → `validate_and_store_signed_list`.
pub async fn put_list(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // This is the endpoint that DECIDES which devices exist and which are revoked, and it used
    // to gate on the bare stateless JWT alone — neither account existence nor device revocation.
    // Its siblings (`messages::handlers::send`, `plugin_blob::gate`, `push::register`) all check
    // both, and here the gap mattered most: a revoked device's access token stays valid for its
    // 15-minute TTL, and this is the one call that could publish a list reinstating it.
    //
    // It deliberately does NOT use `require_active_auth`. A fresh registration must publish
    // rev=1 BEFORE any `devices` row exists — registration writes `users`, `signed_prekeys` and
    // the OTK pool, but the first `devices` rows are created by THIS handler — so demanding an
    // active-device proof would deadlock the bootstrap in exactly the way described for the
    // self-read in `get_list` below. The two halves are therefore taken separately:
    //   * `require_existing_account_auth` — the account must still exist (so a kicked user's
    //     15-minute token cannot rewrite a device list), which is the same narrow exception
    //     `get_list` already relies on at bootstrap.
    //   * `device_revoked` — fail-closed for a device explicitly carrying `revoked_at`, and
    //     false for a device with no row yet (the bootstrap). That is precisely the shape the
    //     bootstrap needs: a device that has never been listed cannot have been revoked from a
    //     list.
    let auth = match require_existing_account_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let auth_user = auth.user_id;
    if device_revoked(&ctx.env, &auth_user, &auth.device_id).await? {
        return json_err(401, "device_revoked");
    }

    // Rate-limit: a rarely called endpoint, so this is cheap protection built on the existing
    // KV sliding window. The KV binding is OPTIONAL (template diet): with none we continue
    // unlimited — see ratelimit::check_rate_limit_env.
    if !crate::ratelimit::check_rate_limit_env(
        &ctx.env,
        &format!("devices:list:{auth_user}"),
        20,
        60,
    )
    .await
    {
        return json_err(429, "rate_limited");
    }

    let body: PutBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };

    let db = ctx.env.d1("DB")?;
    let rev = match validate_and_store_signed_list(&db, &auth_user, &body.doc_json, &body.sig_b64)
        .await?
    {
        Ok(rev) => rev,
        Err(resp) => return Ok(resp),
    };
    // The invite grant is created during verify, but the first device list only arrives
    // afterwards. If the inviter's first pull hit a 404, this post-commit second nudge
    // restarts the authoritative sync — no app restart needed.
    crate::realtime::nudge_grant_counterparts_best_effort(&ctx.env, &auth_user).await;
    Response::from_json(&serde_json::json!({ "rev": rev }))
}

/// Verify a signed device list and store it ATOMICALLY. The shared path of `put_list` and
/// `link-approve`, so verification lives in exactly one place. Every check is fail-closed.
/// Success → `Ok(rev)`; rejection → `Err(Response)`, which the caller returns as `Ok(resp)`.
///
/// Error codes (machine-readable): 400 bad_doc / doc_too_large / unsupported_version /
///   user_mismatch / no_primary / multiple_primary / primary_key_mismatch /
///   bad_pubkey / too_many_devices / bad_signature / device_id_mismatch /
///   tombstone_device_id_mismatch / device_active_and_removed · 401 user_not_found ·
///   403 identity_mismatch / sig_invalid · 409 rev_conflict · 500 bad_spk_sig.
///
/// The last three 400s were missing from this list, which matters more than a normal doc gap: a list
/// that presents itself as MACHINE-READABLE invites a client to switch on it exhaustively, and a client
/// that did would have treated three real rejections as unknown. Every `reject!` in this function is
/// accounted for above — checked by enumerating them, not by reading.
///
/// **B6 atomicity:** the `device_lists` write is `ON CONFLICT DO UPDATE ... WHERE
/// excluded.rev > device_lists.rev RETURNING rev`, so among concurrent writers only the one
/// advancing rev wins; the loser sees an empty RETURNING and gets a 409. No read-then-write
/// race exists.
pub(crate) async fn validate_and_store_signed_list(
    db: &D1Database,
    auth_user: &str,
    doc_json: &str,
    sig_b64: &str,
) -> Result<std::result::Result<i64, Response>> {
    macro_rules! reject {
        ($code:expr, $msg:expr) => {
            return Ok(Err(json_err($code, $msg)?))
        };
    }

    if doc_json.len() > MAX_DOC_BYTES {
        reject!(400, "doc_too_large");
    }

    // (a) Parse doc_json to READ its fields; the signature is still checked over raw bytes.
    let doc: DeviceListDoc = match serde_json::from_str(doc_json) {
        Ok(d) => d,
        Err(_) => reject!(400, "bad_doc"),
    };
    if doc.v != 1 {
        reject!(400, "unsupported_version");
    }

    // (b) doc.user_id must equal the authenticated user_id.
    if doc.user_id != auth_user {
        reject!(400, "user_mismatch");
    }

    // (e) Device count ≤ 5 (1 primary + ≤4 linked); an empty list is rejected here too.
    if doc.devices.is_empty() || doc.devices.len() > MAX_DEVICES {
        reject!(400, "too_many_devices");
    }

    // (c) EXACTLY ONE entry with role == "primary".
    let primaries: Vec<&DeviceEntry> = doc.devices.iter().filter(|d| d.role == "primary").collect();
    let primary = match primaries.as_slice() {
        [] => reject!(400, "no_primary"),
        [p] => *p,
        _ => reject!(400, "multiple_primary"),
    };

    let user: Option<UserRow> = db
        .prepare("SELECT identity_pubkey, device_list_rev FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(auth_user)])?
        .first(None)
        .await?;
    let user = match user {
        Some(u) => u,
        None => reject!(401, "user_not_found"),
    };

    // (1) Build a VerifyingKey from the primary entry's Ed25519 signing key.
    let primary_ed = match b64_decode(&primary.ed_pub_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => reject!(400, "bad_pubkey"),
    };
    let ed_arr: [u8; 32] = primary_ed.as_slice().try_into().unwrap();
    let verifying = match VerifyingKey::from_bytes(&ed_arr) {
        Ok(v) => v,
        Err(_) => reject!(400, "bad_pubkey"),
    };

    // (2) Binding: is the claimed Ed key the one belonging to the identity that signed this
    //     user's stored SPK? (The relogin.rs pattern.) No SPK → fail-closed 403.
    #[derive(Deserialize)]
    struct SpkRow {
        prekey_pub: Vec<u8>,
        signature: Vec<u8>,
    }
    // M2-S3.2 (review HIGH): scope the SPK selection by the PRIMARY device's device_id.
    // When a linked device onboards it appends its OWN SPK, so a device-id-agnostic "newest
    // row" selection would check the primary's list-signature binding against the LINKED
    // device's SPK → identity_mismatch → the primary could no longer publish lists or remove
    // devices, breaking S3.5 revoke. Prefer the row matching the primary entry's device_id.
    // EXACTLY the primary's slot: the `device_id IS NULL OR device_id = ''` widening is gone with
    // the device-less write that filled it, so the primary can no longer be verified against a
    // key that landed in an unscoped slot.
    let primary_dev = primary.device_id.as_str();
    let spk: Option<SpkRow> = db
        .prepare(
            "SELECT prekey_pub, signature FROM signed_prekeys
             WHERE user_id = ? AND device_id = ?
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&[d1_text(auth_user), d1_text(primary_dev)])?
        .first(None)
        .await?;
    let spk = match spk {
        Some(s) => s,
        None => reject!(403, "identity_mismatch"),
    };
    if spk.signature.len() != 64 {
        reject!(500, "bad_spk_sig");
    }
    let spk_sig_arr: [u8; 64] = spk.signature.as_slice().try_into().unwrap();
    let spk_sig = ed25519_dalek::Signature::from_bytes(&spk_sig_arr);
    if verifying.verify(&spk.prekey_pub, &spk_sig).is_err() {
        reject!(403, "identity_mismatch");
    }

    // (3) List signature: the same Ed key verifies the EXACT incoming UTF-8 bytes of
    //     doc_json. Re-serializing is FORBIDDEN.
    let sig_bytes = match b64_decode(sig_b64) {
        Ok(b) if b.len() == 64 => b,
        _ => reject!(400, "bad_signature"),
    };
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    if verifying.verify(doc_json.as_bytes(), &sig).is_err() {
        reject!(403, "sig_invalid");
    }

    // (4) Consistency: decoded primary.x_pub_b64 == users.identity_pubkey (the DH root).
    let primary_x = match b64_decode(&primary.x_pub_b64) {
        Ok(b) => b,
        Err(_) => reject!(400, "bad_pubkey"),
    };
    if primary_x != user.identity_pubkey {
        reject!(400, "primary_key_mismatch");
    }

    // (f) rev fresh-insert guard (>= 1). The conflict case is handled by the atomic WHERE.
    if doc.rev < 1 {
        reject!(409, "rev_conflict");
    }

    // Model-B Layer-1 BLOCKER fix (revoke resurrection): the rev HIGH-WATER gate. If the
    // `device_lists` row was lost to D1 churn, an old doc — from before the removal, with no
    // tombstone — was accepted as a fresh insert, and the active-device upsert with
    // revoked_at=NULL RESURRECTED the removed device. `users.device_list_rev` is INDEPENDENT
    // of device_lists and survives that row loss, so rev < high_water means stale and is
    // rejected. An EQUAL rev (== high_water) is allowed so a RESTORE can work: the signature
    // has already been verified, making it a genuine, current primary doc. The winning writer
    // advances high_water with MAX inside the batch.
    if doc.rev < user.device_list_rev {
        reject!(409, "rev_conflict");
    }

    // Decode every device pubkey up front: any violation rejects the whole request, which is
    // what keeps the write atomic.
    struct DecodedEntry<'a> {
        device_id: &'a str,
        role: &'a str,
        ed_pub: Vec<u8>,
        x_pub: Vec<u8>,
        label: Option<&'a str>,
        added_at_ms: i64,
    }
    let mut decoded: Vec<DecodedEntry> = Vec::with_capacity(doc.devices.len());
    for d in &doc.devices {
        let ed = match b64_decode(&d.ed_pub_b64) {
            Ok(b) if b.len() == 32 => b,
            _ => reject!(400, "bad_pubkey"),
        };
        let xk = match b64_decode(&d.x_pub_b64) {
            Ok(b) => b,
            Err(_) => reject!(400, "bad_pubkey"),
        };
        // Item 2 (Codex): EVERY device's device_id must equal the value derived from its
        // ed_pub (parity with core verify §5). The worker used to check only the primary
        // binding, so a linked entry with a forged device_id could leak into the `devices`
        // routing state — core rejected it while the worker accepted it, an asymmetry. This
        // gate makes the ids self-certifying.
        if derive_device_id(&ed) != d.device_id {
            reject!(400, "device_id_mismatch");
        }
        decoded.push(DecodedEntry {
            device_id: &d.device_id,
            role: &d.role,
            ed_pub: ed,
            x_pub: xk,
            label: d.label.as_deref(),
            added_at_ms: d.added_at_ms,
        });
    }

    // Item 1w (Model-B tombstones): validate removed_devices — every tombstone must be
    // self-consistent (device_id derived from ed_pub) and DISJOINT from the active devices,
    // because a device cannot be active and tombstoned at once (parity with core verify
    // §6/§7). Remove-wins is ENFORCED implicitly: a tombstoned device is absent from the
    // active `devices` array, so the omission-revoke below already sets `revoked_at=now`,
    // and a stale re-PUT cannot resurrect it.
    for r in &doc.removed_devices {
        let red = match b64_decode(&r.ed_pub_b64) {
            Ok(b) if b.len() == 32 => b,
            _ => reject!(400, "bad_pubkey"),
        };
        if derive_device_id(&red) != r.device_id {
            reject!(400, "tombstone_device_id_mismatch");
        }
        if decoded.iter().any(|a| a.device_id == r.device_id) {
            reject!(400, "device_active_and_removed");
        }
    }

    // ---- Success: ONE ATOMIC D1 BATCH (Item 4 — revoke safety). ----
    // How it used to be: the device_lists rev bump, then the devices sync and the token
    // delete, as SEPARATE queries. A failure in between meant rev had advanced but the tokens
    // had not been deleted, so a removed device KEPT its token while the retry also got a 409
    // — a revoked device could retain access. That was a serious revoke-security hole.
    // Now everything runs in ONE transaction (`db.batch`, all-or-nothing).
    //
    // Concurrent-writer race: the device_lists bump is CONDITIONAL (`excluded.rev > rev`), so
    // the loser's bump is a no-op. Every derived mutation (devices upsert, omission-revoke,
    // token delete) is gated on `device_lists.doc_json == MY doc`, so the LOSER mutates
    // nothing: a stale list can neither resurrect a device nor revoke the wrong one. The bump
    // statement comes FIRST, so later statements in the same transaction observe the
    // post-bump doc_json.
    let now_s = now_secs() as i64;
    let now_ms_v = now_ms() as i64;
    let placeholders: String = (0..decoded.len())
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");

    let mut stmts: Vec<D1PreparedStatement> = Vec::with_capacity(4 + decoded.len());

    // 1) Conditional device_lists rev bump — FIRST, since the gated derived statements read
    //    its outcome.
    stmts.push(
        db.prepare(
            "INSERT INTO device_lists (user_id, rev, doc_json, sig_b64, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET
               rev = excluded.rev, doc_json = excluded.doc_json,
               sig_b64 = excluded.sig_b64, updated_at = excluded.updated_at
             WHERE excluded.rev > device_lists.rev",
        )
        .bind(&[
            d1_text(auth_user),
            d1_int(doc.rev),
            d1_text(doc_json),
            d1_text(sig_b64),
            d1_int(now_s),
        ])?,
    );

    // 2) devices sync: insert-or-update every active entry with revoked_at=NULL. Only the
    //    WINNER mutates, via the doc_json gate (INSERT ... SELECT ... WHERE).
    for e in &decoded {
        stmts.push(
            db.prepare(
                "INSERT INTO devices
                   (user_id, device_id, role, ed_pub, x_pub, label, added_at, revoked_at)
                 SELECT ?, ?, ?, ?, ?, ?, ?, NULL
                 WHERE (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?
                 ON CONFLICT(user_id, device_id) DO UPDATE SET
                   role = excluded.role, ed_pub = excluded.ed_pub, x_pub = excluded.x_pub,
                   label = excluded.label, added_at = excluded.added_at, revoked_at = NULL",
            )
            .bind(&[
                d1_text(auth_user),
                d1_text(e.device_id),
                d1_text(e.role),
                d1_blob(&e.ed_pub),
                d1_blob(&e.x_pub),
                d1_opt_text(e.label),
                d1_int(e.added_at_ms),
                d1_text(auth_user),
                d1_text(doc_json),
            ])?,
        );
    }

    // 3) omission-revoke: existing rows ABSENT from the list get revoked_at=now (gated).
    let revoke_sql = format!(
        "UPDATE devices SET revoked_at = ?
         WHERE user_id = ? AND revoked_at IS NULL AND device_id NOT IN ({placeholders})
           AND (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?"
    );
    let mut revoke_binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(4 + decoded.len());
    revoke_binds.push(d1_int(now_ms_v));
    revoke_binds.push(d1_text(auth_user));
    for e in &decoded {
        revoke_binds.push(d1_text(e.device_id));
    }
    revoke_binds.push(d1_text(auth_user));
    revoke_binds.push(d1_text(doc_json));
    stmts.push(db.prepare(&revoke_sql).bind(&revoke_binds)?);

    // 4) M2-S3.5 B4 (device removal): DELETE the refresh tokens of every real device_id ABSENT
    //    from the new list, so a removed device cannot renew its token — its session dies once
    //    the 15-minute access-token TTL expires — and relogin rejects it as revoked. The
    //    `device_id IS NOT NULL AND device_id != ''` carve-out that preserved rows belonging to
    //    no device is gone: every refresh row names a device now, so it exempted nothing.
    let del_sql = format!(
        "DELETE FROM refresh_tokens
         WHERE user_id = ? AND device_id NOT IN ({placeholders})
           AND (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?"
    );
    let mut del_binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(3 + decoded.len());
    del_binds.push(d1_text(auth_user));
    for e in &decoded {
        del_binds.push(d1_text(e.device_id));
    }
    del_binds.push(d1_text(auth_user));
    del_binds.push(d1_text(doc_json));
    stmts.push(db.prepare(&del_sql).bind(&del_binds)?);

    // 4b) A removed device's UNCONSUMED one-time keys are dead the moment it goes: nothing will
    //     ever hold their private halves again, and only that device's own replenish would have
    //     replaced them — which will never run. Measured 2026-07-27 on the live server: a device
    //     revoked the day before still had 46 published OTKs waiting to be handed out. They are
    //     device-scoped so the bundle handler does not serve them for the live device, which is
    //     why this was a hygiene leak rather than a fault; it still means public keys for a dead
    //     account sitting in the pool indefinitely. consumed=1 rows STAY: they are the record
    //     that stops a key ever being issued twice.
    let del_otk_sql = format!(
        "DELETE FROM one_time_prekeys
         WHERE user_id = ? AND consumed = 0
           AND device_id NOT IN ({placeholders})
           AND (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?"
    );
    let mut del_otk_binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(3 + decoded.len());
    del_otk_binds.push(d1_text(auth_user));
    for e in &decoded {
        del_otk_binds.push(d1_text(e.device_id));
    }
    del_otk_binds.push(d1_text(auth_user));
    del_otk_binds.push(d1_text(doc_json));
    stmts.push(db.prepare(&del_otk_sql).bind(&del_otk_binds)?);

    // 5) Model-B Layer-1 BLOCKER fix: advance the rev HIGH-WATER mark. MAX keeps it monotonic
    //    so it can never go backwards. Even if the device_lists row is lost later, this value
    //    stays on `users`, so a stale re-PUT is rejected by the pre-check above. Only the
    //    WINNING writer advances it (doc_json gate), so the loser cannot corrupt high_water.
    stmts.push(
        db.prepare(
            "UPDATE users SET device_list_rev = MAX(device_list_rev, ?)
             WHERE id = ? AND (SELECT doc_json FROM device_lists WHERE user_id = ?) = ?",
        )
        .bind(&[
            d1_int(doc.rev),
            d1_text(auth_user),
            d1_text(auth_user),
            d1_text(doc_json),
        ])?,
    );

    // Run atomically (all-or-nothing): if a single statement fails, everything rolls back.
    db.batch(stmts).await?;

    // Did I win — does device_lists now hold MY doc? Read it back SEPARATELY rather than
    // relying on D1's batch+RETURNING behaviour, so 409 detection stays robust across
    // versions.
    let stored: Option<ListRow> = db
        .prepare("SELECT doc_json, sig_b64, rev FROM device_lists WHERE user_id = ? LIMIT 1")
        .bind(&[d1_text(auth_user)])?
        .first(None)
        .await?;
    match stored {
        Some(r) if r.doc_json == doc_json => Ok(Ok(r.rev)),
        // The bump was lost — a concurrent higher-rev writer, or an older rev. Because the
        // derived mutations are gated too, none of them ran, so a 409 is consistent. On a 409
        // the caller re-GETs a fresh list before retrying.
        _ => Ok(Err(json_err(409, "rev_conflict")?)),
    }
}

/// `GET /devices/list/:user_id` — a user's current signed list.
/// 200 `{doc_json, sig_b64, rev}` | 404 not_found.
pub async fn get_list(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let target = match ctx.param("user_id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };
    let caller = match crate::auth::middleware::require_existing_account_auth(&req, &ctx.env).await
    {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };

    // Fresh-registration bootstrap is intentionally GET-first: the client reads
    // its own signed list and, on 404, publishes rev=1 with PUT /devices/list.
    // At that point `devices` is still empty, so requiring an active device for
    // the self-read creates a permanent deadlock (GET 401 => PUT never runs).
    // A signed device list is public key material and PUT still verifies the
    // primary signature/high-water; therefore a valid account token may read
    // only its OWN list before activation. Reading another user's list keeps
    // the active-device and direct-contact gates below.
    let peer_read = list_read_requires_active_device(&caller, &target);
    if peer_read {
        let active = match require_active_auth(&req, &ctx.env).await {
            Ok(auth) => auth,
            Err(resp) => return Ok(resp),
        };
        debug_assert_eq!(active.user_id, caller);
    }

    let db = ctx.env.d1("DB")?;
    if peer_read {
        if let Err(resp) = crate::contacts::require_direct(&db, &caller, &target).await {
            return Ok(resp);
        }
    }
    let row: Option<ListRow> = db
        .prepare("SELECT doc_json, sig_b64, rev FROM device_lists WHERE user_id = ? LIMIT 1")
        .bind(&[d1_text(&target)])?
        .first(None)
        .await?;
    match row {
        Some(r) => Response::from_json(&serde_json::json!({
            "doc_json": r.doc_json,
            "sig_b64": r.sig_b64,
            "rev": r.rev,
        })),
        None => json_err(404, "not_found"),
    }
}

#[cfg(test)]
mod tests {
    use super::list_read_requires_active_device;

    #[test]
    fn fresh_registration_can_read_own_missing_list_before_device_activation() {
        assert!(!list_read_requires_active_device(
            "fresh-owner",
            "fresh-owner"
        ));
    }

    #[test]
    fn peer_device_list_reads_still_require_an_active_device() {
        assert!(list_read_requires_active_device("alice", "bob"));
    }
}
