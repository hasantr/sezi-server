//! `PUT /devices/list` + `GET /devices/list/:user_id` — the M1 device list.
//!
//! ## The JWS byte-signature model (CRITICAL)
//! `doc_json` is a JSON STRING field whose value is EXACTLY the inner JSON text the client
//! signed, so the signature is verified over `body.doc_json.as_bytes()` — verbatim. The inner
//! document is NEVER re-serialized: no canonicalization, and no serialization-difference bugs.
//! The inner parse exists only to read the fields verification needs.
//!
//! ## The identity binding chain (CRITICAL)
//! The list is signed with the primary's **Ed25519** key, which cannot be checked directly
//! against `users.identity_pubkey` — that blob is the Curve25519/DH key register sends, not a
//! signing key. So, the same binding relogin.rs uses:
//!   1) Build a `VerifyingKey` from the doc's primary `ed_pub_b64` (malformed → 400).
//!   2) **Binding:** the user's NEWEST `signed_prekeys` row was signed at registration by the
//!      real identity (`account.sign(spk_pub)`), so an Ed key that verifies it is
//!      cryptographically bound to the registered identity (missing or failing → 403).
//!   3) **List signature:** that same Ed key over the verbatim doc_json bytes.
//!   4) **Consistency:** the decoded primary `x_pub_b64` == `users.identity_pubkey`.
//!
//! ## One validate-and-store path
//! `put_list` and `link-approve` (`link.rs`) share `validate_and_store_signed_list`, so
//! verification has a single source. That write is atomically rev-conditional (`WHERE
//! excluded.rev > device_lists.rev` plus RETURNING), so concurrent writers cannot race
//! read-then-write and the loser gets a 409.

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
/// `hex(blake3(ed_pub_bytes)[..8])`, 16 lowercase hex chars (`ed_pub_32` is checked by the
/// caller). Re-derived for every entry on every list write, which is what makes the ids
/// self-certifying: a forged device_id cannot reach the routing state.
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
    /// Signed tombstones for removed devices; older docs omit the field, hence the default.
    /// The signature covers the whole doc, so the server cannot add entries here.
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
    /// The device-list rev HIGH-WATER mark. It lives on `users` so it survives the loss of the
    /// `device_lists` row, which is what stops a stale re-PUT resurrecting a revoked device.
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
    // This endpoint DECIDES which devices exist and which are revoked, and a revoked device's
    // access token stays valid for its 15-minute TTL — so the bare stateless JWT is not enough
    // here: this is the one call that could publish a list reinstating that device.
    //
    // It deliberately does NOT use `require_active_auth`, which would deadlock the bootstrap: a
    // fresh registration must publish rev=1 before any `devices` row exists, and THIS handler is
    // what creates the first ones. So the two halves are taken separately —
    //   * `require_existing_account_auth`: the account must still exist, so a kicked user's
    //     15-minute token cannot rewrite a device list.
    //   * `device_revoked`: fail-closed on an explicit `revoked_at`, false for a device with no
    //     row yet — a device that was never listed cannot have been revoked from a list.
    let auth = match require_existing_account_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    let auth_user = auth.user_id;
    if device_revoked(&ctx.env, &auth_user, &auth.device_id).await? {
        return json_err(401, "device_revoked");
    }

    // A rarely called endpoint, so the KV sliding window is cheap protection. The KV binding is
    // OPTIONAL: with none, `check_rate_limit_env` continues unlimited.
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
/// Error codes (machine-readable, and EXHAUSTIVE — a client may switch on them, so every
/// `reject!` below must appear here): 400 bad_doc / doc_too_large / unsupported_version /
///   user_mismatch / no_primary / multiple_primary / primary_key_mismatch /
///   bad_pubkey / too_many_devices / bad_signature / device_id_mismatch /
///   tombstone_device_id_mismatch / device_active_and_removed · 401 user_not_found ·
///   403 identity_mismatch / sig_invalid · 409 rev_conflict · 500 bad_spk_sig.
///
/// **Atomicity:** the write is `ON CONFLICT DO UPDATE … WHERE excluded.rev > device_lists.rev
/// RETURNING rev`, so only the writer advancing rev wins; the loser sees an empty RETURNING and
/// gets a 409.
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
    // EXACTLY the primary's slot. A device-id-agnostic "newest row" would check the primary's
    // binding against a LINKED device's SPK once that device onboards → identity_mismatch → the
    // primary can no longer publish lists or revoke anyone. No `device_id IS NULL OR = ''`
    // widening either: the primary must not be verifiable against a key from an unscoped slot.
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

    // The rev HIGH-WATER gate against revoke resurrection: with the `device_lists` row lost to D1
    // churn, an old pre-removal doc looks like a fresh insert and the upsert's `revoked_at=NULL`
    // brings the removed device back. `users.device_list_rev` survives that loss independently,
    // so rev < high_water is stale. EQUAL is allowed so a restore works — the signature is
    // already verified, so it is a genuine current doc. The winner advances high_water with MAX
    // inside the batch.
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
        // EVERY device_id must equal the value derived from its ed_pub, at parity with core's
        // verify. Checking only the primary lets a forged linked entry into the `devices`
        // routing state that core would reject — the two sides must not disagree.
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

    // Every tombstone must be self-consistent (device_id derived from ed_pub) and DISJOINT from
    // the active devices — a device cannot be both at once. Remove-wins needs no extra step: a
    // tombstoned device is absent from `devices`, so the omission-revoke below already sets
    // `revoked_at=now`.
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

    // ---- Success: ONE ATOMIC D1 BATCH — this is revoke safety. ----
    // Split into separate queries, a failure between the rev bump and the token delete leaves rev
    // advanced while a removed device KEEPS its token, and the retry 409s: a revoked device with
    // retained access.
    //
    // Concurrent writers: the bump is conditional (`excluded.rev > rev`), so the loser's is a
    // no-op, and every derived mutation (devices upsert, omission-revoke, token delete) is gated
    // on `device_lists.doc_json == MY doc` — so the loser mutates nothing and a stale list can
    // neither resurrect a device nor revoke the wrong one. The bump comes FIRST so the rest of
    // the transaction sees the post-bump doc_json.
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

    // 4) DELETE the refresh tokens of every device_id ABSENT from the new list: a removed device
    //    cannot renew, so its session dies with the 15-minute access-token TTL and relogin
    //    rejects it as revoked. No `device_id IS NOT NULL` carve-out — every refresh row names a
    //    device, so it would exempt nothing.
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

    // 4b) A removed device's UNCONSUMED one-time keys are dead the moment it goes: nobody holds
    //     their private halves any more, and only that device's own replenish would replace them.
    //     Hygiene rather than a fault — they are device-scoped, so the bundle handler never
    //     serves them for a live device. consumed=1 rows STAY: they are the record that stops a
    //     key being issued twice.
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

    // 5) Advance the rev HIGH-WATER mark. MAX keeps it monotonic; it lives on `users` so it
    //    outlives the device_lists row; and the doc_json gate means only the WINNING writer
    //    advances it.
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

/// `GET /devices/activity` (auth) → `{devices: [{device_id, last_seen_at}]}` — when the server
/// last saw each of MY devices.
///
/// A separate route from `GET /devices/list` on purpose: that returns a document the PRIMARY
/// signed, and the server's own observation cannot go inside it — the signature would break, and
/// the primary does not know the answer. Two sources, two trust levels, two fields.
///
/// SELF ONLY: when a device last connected is presence, and the device list is readable by a
/// direct contact (they need the keys) while the activity is not.
///
/// `last_seen_at` is null for a device that has made no authenticated request since the column
/// existed. That covers both an old linked device and a genuine ghost — one whose first history
/// sync timed out, leaving a row in the signed list and nothing behind it — and the client must
/// not tell them apart, because the server cannot.
pub async fn get_activity(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let auth = match require_active_auth(&req, &ctx.env).await {
        Ok(a) => a,
        Err(resp) => return Ok(resp),
    };
    #[derive(Deserialize)]
    struct ActivityRow {
        device_id: String,
        last_seen_at: Option<i64>,
    }
    let rows: Vec<ActivityRow> = ctx
        .env
        .d1("DB")?
        .prepare(
            "SELECT device_id, last_seen_at FROM devices
              WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(&[d1_text(&auth.user_id)])?
        .all()
        .await?
        .results()?;
    Response::from_json(&serde_json::json!({
        "devices": rows
            .iter()
            .map(|r| serde_json::json!({
                "device_id": r.device_id,
                "last_seen_at": r.last_seen_at,
            }))
            .collect::<Vec<_>>(),
    }))
}

/// `GET /devices/list/:user_id` → 200 `{doc_json, sig_b64, rev}` | 404 not_found.
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

    // Bootstrap is GET-first: the client reads its own list and, on 404, publishes rev=1. With
    // `devices` still empty, requiring an active device for the SELF-read deadlocks it forever
    // (GET 401 → the PUT never runs). A signed list is public key material and the PUT still
    // verifies signature and high-water, so an account token may read its OWN list before
    // activation; another user's list keeps both gates below.
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

    /// `include_str!` binds at compile time and resolves relative to THIS file — the
    /// `groups_tests.rs` trick. Needles are split with `concat!` because this module is INLINE, so
    /// `SRC` contains the test source too and a literal needle would match itself.
    const SRC: &str = include_str!("handlers.rs");

    /// One handler's source, from its `pub async fn` line to the next one. "The file mentions it
    /// somewhere" is exactly the assertion that keeps passing after the call is deleted from the
    /// handler that needed it.
    fn handler_body<'a>(name: &str) -> &'a str {
        let needle = format!("\npub async fn {name}(");
        let start = SRC
            .find(&needle)
            .unwrap_or_else(|| panic!("no handler named {name} — re-point this guard"));
        let rest = &SRC[start + 1..];
        let end = rest.find("\npub async fn ").unwrap_or(rest.len());
        &rest[..end]
    }

    /// A signed device list names every device an account owns, so serving it to any authenticated
    /// stranger is a roster of who has how many devices, account by account. Gated exactly like
    /// `GET /keys/:user_id/bundle` — `contacts::require_direct` — which a legitimate sender
    /// already passes, since the send path makes the same decision.
    ///
    /// A SOURCE guard because the property is about which middleware the handler calls, and no
    /// behavioural test over one endpoint can see that its neighbour chose differently.
    /// `/devices/activity` needs none: it reads `auth.user_id` and can only return the caller's.
    #[test]
    fn reading_another_users_device_list_needs_a_direct_relationship() {
        let body = handler_body("get_list");
        assert!(
            body.contains(concat!("contacts::require_", "direct(&db, &caller, &target)")),
            "GET /devices/list/:user_id serves a signed device list to anyone with a token"
        );
        let gate = body
            .find(concat!("require_", "direct"))
            .expect("the contact gate is gone");
        let read = body
            .find("FROM device_lists WHERE user_id = ?")
            .expect("the device-list read moved — re-point this guard");
        assert!(gate < read, "the gate must precede the read it protects");
    }

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
