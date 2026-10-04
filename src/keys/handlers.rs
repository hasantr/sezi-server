use crate::auth::middleware::{require_active_auth, require_auth_device};
use crate::d1util::{d1_blob, d1_int, d1_prekey_id, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::{json_err, no_content};
use crate::utils::{b64_decode, b64_encode, now_secs};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::Deserialize;
use worker::*;

// The per-device bundle slot, declared here rather than in `keys/mod.rs` so the routed handlers
// stay the whole of `keys::handlers` from the outside.
#[path = "bundle_slot.rs"]
mod bundle_slot;

use bundle_slot::build_device_bundle;

#[derive(Deserialize)]
struct UserRow {
    identity_pubkey: Vec<u8>,
}

/// An active device row — the server-side projection of the verified device_lists doc. Each
/// device gets its own SPK and its own claimed OTK.
#[derive(Deserialize)]
struct DeviceRow {
    device_id: String,
}

/// `GET /keys/:user_id/bundle` (auth required, caller must be authorized to contact the target)
/// → `{user_id, identity_pubkey_b64, device_list, devices[]}`; 404 unknown user, 429 rate
/// limited, 503 `no_signed_prekey`. For every ACTIVE device it returns that device's SPK and
/// CONSUMES one of its OTKs. `device_list` is the signed doc plus its signature, verbatim, so the
/// client can verify the canonical device list itself.
pub async fn bundle(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // Against prekey-DEPLETION DoS: without a ceiling an attacker fetches the bundle over and
    // over, drains a device's OTKs and forces everyone onto the weak-forward-secrecy SPK
    // fallback. 60/min per caller is generous — first contact is rare and a live session never
    // refetches. Enforced in prod only, so field testing is unthrottled; a missing ENV var reads
    // as "prod" (fail-secure).
    let env_name = crate::utils::var_or(&ctx.env, "ENV", "prod");
    if env_name == "prod"
        && !check_rate_limit_env(&ctx.env, &format!("bundle:fetch:{caller}"), 60, 60).await
    {
        return json_err(429, "rate_limited");
    }
    let target_id = match ctx.param("user_id") {
        Some(s) => s.clone(),
        None => return json_err(400, "bad_request"),
    };

    let db = ctx.env.d1("DB")?;

    // Authorization precedes bundle construction and, critically, OTK
    // consumption. A denied/blocked lookup cannot deplete target prekeys.
    if let Err(resp) = crate::contacts::require_direct(&db, &caller, &target_id).await {
        return Ok(resp);
    }

    let user: Option<UserRow> = db
        .prepare("SELECT identity_pubkey FROM users WHERE id = ? LIMIT 1")
        .bind(&[d1_text(&target_id)])?
        .first(None)
        .await?;
    let user = match user {
        Some(u) => u,
        None => return json_err(404, "not_found"),
    };

    // The signed device list, doc and signature verbatim — the client verifies it with the
    // primary's Ed25519 key. Zero-trust: the server can neither mint nor alter it.
    #[derive(Deserialize)]
    struct DeviceListRow {
        doc_json: String,
        sig_b64: String,
        rev: i64,
    }
    let device_list: Option<DeviceListRow> = db
        .prepare("SELECT doc_json, sig_b64, rev FROM device_lists WHERE user_id = ? LIMIT 1")
        .bind(&[d1_text(&target_id)])?
        .first(None)
        .await?;
    // Wire shape: core decodes `device_list` as `{doc_json, sig_b64, rev}`. Renaming a field or
    // dropping `rev` fails the decode of the WHOLE bundle, not just this member.
    let device_list_json = match device_list {
        Some(dl) => serde_json::json!({
            "doc_json": dl.doc_json,
            "sig_b64": dl.sig_b64,
            "rev": dl.rev,
        }),
        None => serde_json::Value::Null,
    };

    // Active devices (revoked_at IS NULL). Empty is the live bootstrap window, not legacy data:
    // `auth::verify` writes `users`, the SPK and the OTK pool, while only `PUT /devices/list`
    // creates `devices` rows. The fallback below is one device-blind slot so a peer can still
    // reach them — they own exactly one device, so the unfiltered queries select its material and
    // only the reported `device_id` is unknown until the list is published.
    let devices: Vec<DeviceRow> = db
        .prepare(
            "SELECT device_id FROM devices
             WHERE user_id = ? AND revoked_at IS NULL ORDER BY device_id ASC",
        )
        .bind(&[d1_text(&target_id)])?
        .all()
        .await?
        .results()?;

    let mut device_bundles: Vec<serde_json::Value> = Vec::new();
    if devices.is_empty() {
        // Legacy/compatibility: no device list → one slot, unfiltered by device.
        if let Some(b) = build_device_bundle(&db, &target_id, None).await? {
            device_bundles.push(b);
        }
    } else {
        for d in &devices {
            if let Some(b) = build_device_bundle(&db, &target_id, Some(&d.device_id)).await? {
                device_bundles.push(b);
            }
        }
    }

    // An empty `devices[]` means no device published an SPK, so the sender can open an Olm
    // session with none of them. A hollow 200 hides that; 503 `no_signed_prekey` is transient and
    // machine-readable, so the client knows to retry once the target publishes.
    if device_bundles.is_empty() {
        return json_err(503, "no_signed_prekey");
    }

    Response::from_json(&serde_json::json!({
        "user_id": target_id,
        "identity_pubkey_b64": b64_encode(&user.identity_pubkey),
        "device_list": device_list_json,
        "devices": device_bundles,
    }))
}

/// THE BOUND on `one_time_prekeys`: the largest UNCONSUMED pool one device may hold. Past it
/// `replenish` refuses to add more (429 `otk_pool_full`).
///
/// A bound rather than a rate limit, because `check_rate_limit_env` fails OPEN when the
/// `RATE_LIMIT` KV binding is absent (ratelimit.rs) — a limit shapes bursts, it is not a ceiling.
/// Replenish appends and no GC sweeps prekeys, so nothing else stops the table growing.
///
/// 300 = 3× the client's `otk_pool_target` of 100 (`core/src/kernel/config.rs`), which a device
/// that tops UP never approaches, and far under vodozemac's `MAX_ONE_TIME_KEYS` = 5000, where the
/// device evicts its oldest private halves while the server still serves oldest-first — the
/// "unknown one-time key" wedge.
const MAX_OTK_POOL: i64 = 300;

/// THE BOUND on `signed_prekeys`: how many SPK rows one device keeps. Only the NEWEST is ever read
/// (`build_device_bundle` and `auth::relogin` both `ORDER BY created_at DESC LIMIT 1`).
///
/// 5 rather than 1 because a rotation racing a concurrent read must not leave a window with no SPK
/// at all; the rows are cheap, so the table is capped at devices × 5.
const MAX_SPK_ROWS_PER_DEVICE: i64 = 5;

#[derive(Deserialize)]
struct OtkInput {
    // u64 is MANDATORY: the client derives `otk_prekey_id` from the public key's first 8 bytes
    // (little-endian), which does not fit u32. Narrowing it fails the deserialize → 400 → an
    // empty OTK pool → no first-contact Olm session at all.
    prekey_id: u64,
    prekey_pub_b64: String,
}

#[derive(Deserialize)]
struct ReplenishBody {
    otks: Vec<OtkInput>,
    /// This device's device_id as the caller believes it to be — a claim, NOT the pool scope,
    /// which always comes from the token (as `otk_count` reads it). Present, it must agree;
    /// absent, the token still decides, so core sending `None` (it cannot always re-derive the
    /// device) still lands the keys in the pool that device is served from.
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn replenish(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, device_id) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    // `req.text()` + Rust `serde_json`, never `req.json()`: the latter goes through workerd's JS
    // `JSON.parse`, which rounds any `prekey_id` above 2^53 into an f64 — and a pubkey-derived id
    // exceeds 2^53 nearly always — so every replenish 400s and the pool stays empty. The cause is
    // PRECISION, not width; widening u32→u64 alone does not fix it.
    let raw = match req.text().await {
        Ok(t) => t,
        Err(_) => return json_err(400, "bad_request"),
    };
    let body: ReplenishBody = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    if body.otks.is_empty() || body.otks.len() > 100 {
        return json_err(400, "bad_request");
    }
    // Scoping the pool to the TOKEN's device makes poisoning a SIBLING's pool (writing your keys
    // into their slot — a decrypt DoS) impossible by construction. The body claim is still
    // rejected on mismatch, because a client naming another device is a bug worth surfacing.
    if let Some(claim) = body.device_id.as_deref() {
        if claim != device_id {
            return json_err(403, "device_mismatch");
        }
    }
    // A revoked device may not publish at all — checked on the token's device, so omitting the
    // body field cannot skip it.
    if crate::auth::middleware::device_revoked(&ctx.env, &user_id, &device_id).await? {
        return json_err(401, "device_revoked");
    }
    // A BRAKE, not the bound (see MAX_OTK_POOL). 30 calls per 5 minutes is far above the real
    // cadence — a device replenishes at attach and after consuming keys, not in a loop — while
    // stopping a script from reaching the pool ceiling instantly. Scoped per DEVICE, since the
    // pool is, and siblings must not share one budget.
    if !check_rate_limit_env(&ctx.env, &format!("otk:replenish:{user_id}:{device_id}"), 30, 300).await
    {
        return json_err(429, "rate_limited");
    }
    let db = ctx.env.d1("DB")?;
    // THE BOUND. Measured BEFORE the insert, because after it the damage is already in the table.
    // A device at or above the ceiling is told to stop rather than silently ignored, so a client
    // that has misunderstood the top-up contract shows up as 429s instead of as D1 growth. This
    // costs one extra COUNT per replenish; the `pool_after` count below stays a separate read
    // because INSERT OR IGNORE means the number of rows actually added is not knowable from here.
    let pool_before = db
        .prepare(OTK_UNCONSUMED_COUNT_SQL)
        .bind(&[d1_text(&user_id), d1_text(&device_id)])?
        .first::<i64>(Some("n"))
        .await
        .unwrap_or(None)
        .unwrap_or(0);
    if pool_before >= MAX_OTK_POOL {
        console_log!(
            "[otk] replenish REFUSED user={user_id} device={device_id} pool={pool_before} cap={MAX_OTK_POOL}"
        );
        return json_err(429, "otk_pool_full");
    }
    // REPLENISH APPENDS — it must never delete the device's unconsumed OTKs first. A client
    // uploads `target − pool` (the only correct amount to GENERATE), so replace semantics settle
    // the pool at the size of the last delta forever: measured on the live relay, 100 unconsumed
    // became 50 when a 50-key top-up wiped 72 survivors. An empty pool sends first contact to the
    // signed-prekey fallback with no forward secrecy, which is the failure this path exists for.
    //
    // The accepted cost: after an identity restore from backup, the device's OLD public keys stay
    // on the server and a peer may be handed one this device can no longer answer. That is one
    // retry through the session self-heal (OlmReinit / pair-ack), not a wedge. If it ever bites,
    // the answer is an explicit `replace: true` the client sets when it KNOWS its store was
    // rewound — not a blanket wipe on every top-up.
    //
    // The batch gives the inserts atomicity: ≤5 chunks (100 OTKs at 20) = ≤5 statements and ≤400
    // binds, inside the D1 batch limit.
    let mut stmts: Vec<D1PreparedStatement> = Vec::with_capacity(5);
    for chunk in body.otks.chunks(20) {
        let mut sql = String::from(
            // INSERT OR IGNORE keeps this idempotent: if an attach-replenish or a retry
            // republishes the same (user, device, prekey_id) we skip it silently instead of
            // failing with a UNIQUE-constraint 500 (mig 0016).
            "INSERT OR IGNORE INTO one_time_prekeys (user_id, prekey_id, prekey_pub, consumed, device_id) VALUES ",
        );
        let mut binds: Vec<wasm_bindgen::JsValue> = Vec::with_capacity(chunk.len() * 4);
        let mut pubs: Vec<Vec<u8>> = Vec::with_capacity(chunk.len());
        for k in chunk {
            let p = b64_decode(&k.prekey_pub_b64)
                .map_err(|_| Error::RustError("bad otk pub".into()))?;
            pubs.push(p);
        }
        for (i, (k, p)) in chunk.iter().zip(pubs.iter()).enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str("(?, ?, ?, 0, ?)");
            binds.push(d1_text(&user_id));
            // A pubkey-derived u64 reaches D1 only through `d1util::d1_prekey_id`'s 53-bit mask,
            // deliberately in one place: that mask is what avoids workerd's JS-Number f64 trap.
            binds.push(d1_prekey_id(k.prekey_id));
            binds.push(d1_blob(p));
            binds.push(d1_text(&device_id));
        }
        stmts.push(db.prepare(&sql).bind(&binds)?);
    }
    db.batch(stmts).await?;

    // MEASURE WHAT HAPPENED, not what the client asked for. Echoing the request size back
    // (`count: body.otks.len()`) is the same answer whether the pool grew or was wiped, which is
    // how replace-on-publish stayed invisible from both ends. `pool_after` climbing toward the
    // client's target across rounds is the pool working; `pool_after == uploaded` means replace
    // semantics have come back.
    let pool_after = db
        .prepare(OTK_UNCONSUMED_COUNT_SQL)
        .bind(&[d1_text(&user_id), d1_text(&device_id)])?
        .first::<i64>(Some("n"))
        .await
        .unwrap_or(None)
        .unwrap_or(-1);
    console_log!(
        "[otk] replenish user={user_id} device={device_id} uploaded={} pool_after={pool_after}",
        body.otks.len()
    );
    Response::from_json(&serde_json::json!({
        // Kept for older clients, which read this field.
        "count": body.otks.len(),
        // The unconsumed pool this device now has ON THE SERVER, or -1 if the count failed.
        "pool_after": pool_after,
    }))
}

/// The unconsumed pool of ONE device, the only number that says what a peer can actually be
/// handed. Shared by `replenish`'s `pool_after` and by `otk_count` so the two can never drift
/// into measuring different things.
pub(crate) const OTK_UNCONSUMED_COUNT_SQL: &str =
    "SELECT COUNT(*) AS n FROM one_time_prekeys WHERE user_id = ? AND device_id = ? AND consumed = 0";

/// `GET /keys/otks/count` (auth) → `{count, device_id}`; scoped to the TOKEN's user and device, so
/// there is no path here to another user's pool. Diagnostic only: it mutates nothing and a failed
/// count answers 200 with `-1`.
///
/// It exists because the local count and the server count are not proxies for one another —
/// `bundle` claims an OTK for every active device on every fetch, used or not, while the core
/// counts only the PreKey messages it decrypts. This is the read side of that comparison; the core
/// logs both at attach.
pub async fn otk_count(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // The device is taken from the TOKEN, never from the request — the same binding `replenish`
    // enforces, and the reason this cannot be pointed at somebody else's pool.
    let (user_id, device) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    let db = ctx.env.d1("DB")?;
    let count = db
        .prepare(OTK_UNCONSUMED_COUNT_SQL)
        .bind(&[d1_text(&user_id), d1_text(&device)])?
        .first::<i64>(Some("n"))
        .await
        .unwrap_or(None)
        .unwrap_or(-1);
    Response::from_json(&serde_json::json!({
        // Unconsumed rows for this (user, device), or -1 if the count itself failed.
        "count": count,
        // The pool that was actually counted. Echoed back because a caller comparing this with a
        // local number has to be able to see that both sides mean the same device.
        "device_id": device,
    }))
}

#[derive(Deserialize)]
struct SignedPrekeyBody {
    // u64 at parity with OtkInput — see the note there.
    prekey_id: u64,
    prekey_pub_b64: String,
    signature_b64: String,
    /// This device's device_id, as the caller believes it to be. Optional and NOT the slot the
    /// row lands in — that is the token's device. Present, it must agree.
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn rotate_signed_prekey(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // The slot is the TOKEN's device. Keeping a device-less write would reopen the `''` slot an
    // identity claim could be planted in (see `auth::relogin`'s SPK selection).
    let (user_id, device_id) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    // `req.json()` loses u64 precision through JS (see `replenish`), so text() + serde_json.
    let raw = match req.text().await {
        Ok(t) => t,
        Err(_) => return json_err(400, "bad_request"),
    };
    let body: SignedPrekeyBody = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    // The `replenish` guard's twin: the row's slot is the token's device, so overwriting a
    // sibling's SPK is structurally impossible; the body claim is still compared so a client
    // naming another device surfaces as an error rather than a silent rewrite.
    if let Some(claim) = body.device_id.as_deref() {
        if claim != device_id {
            return json_err(403, "device_mismatch");
        }
    }
    // A revoked device cannot rotate — checked on the token's device, not on a body field.
    if crate::auth::middleware::device_revoked(&ctx.env, &user_id, &device_id).await? {
        return json_err(401, "device_revoked");
    }
    // A BRAKE on rotation; the prune at the end of this handler is the bound. A caller walking
    // prekey_id appends a row each time, and this keeps it from spending signature verifications
    // and D1 writes to reach the cap. Ten per hour is far above real rotation, which happens at
    // registration and device-link finalize and is on no client timer.
    if !check_rate_limit_env(&ctx.env, &format!("spk:rotate:{user_id}:{device_id}"), 10, 3600).await
    {
        return json_err(429, "rate_limited");
    }
    let pub_bytes =
        b64_decode(&body.prekey_pub_b64).map_err(|_| Error::RustError("bad pub".into()))?;
    let sig_bytes =
        b64_decode(&body.signature_b64).map_err(|_| Error::RustError("bad sig".into()))?;
    let db = ctx.env.d1("DB")?;

    // ---- AUTHENTICITY: this row is an IDENTITY CLAIM, so it is verified before it is stored.
    //
    // `auth::relogin` treats "the presented Ed25519 key verifies the newest stored SPK row" as
    // PROOF OF IDENTITY. Storing an unverified SPK therefore lets anyone holding any access token
    // — a device revoked seconds ago still has ~15 minutes of one — store a row signed with their
    // OWN key and relogin AS the user on a 30-day renewable session.
    //
    // The anchor is `devices.ed_pub` for the WRITING device, and it is the right key: a device
    // signs its own SPK with its own Olm account, whose `ed25519_key()` the primary-signed list
    // carries. A linked device is deliberately NOT anchored to `users.identity_ed_pub` — doing so
    // rejects every legitimate linked device.
    #[derive(Deserialize)]
    struct DeviceEdRow {
        ed_pub: Vec<u8>,
    }
    let anchor: Option<Vec<u8>> = db
        .prepare("SELECT ed_pub FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
        .bind(&[d1_text(&user_id), d1_text(&device_id)])?
        .first(None)
        .await?
        .map(|r: DeviceEdRow| r.ed_pub);
    // NO ANCHOR is the remaining edge: Ed25519 has no public-key recovery and the wire carries no
    // key, so with nothing stored there is nothing to verify and the write is accepted. One
    // contained case reaches it — a device with no `devices` row yet, the registration bootstrap
    // window before the first `PUT /devices/list`. The token binding pins the write to the
    // caller's own device slot, which `auth::relogin` reads only when asked for that device and
    // then revocation-checks itself.
    if let Some(anchor_ed) = anchor {
        let ed_arr: [u8; 32] = match anchor_ed.as_slice().try_into() {
            Ok(a) => a,
            // A stored anchor of the wrong length is server-side corruption, not a client error.
            // It must fail closed rather than degrade into "then accept anything".
            Err(_) => return json_err(500, "bad_identity_key"),
        };
        let verifying = match VerifyingKey::from_bytes(&ed_arr) {
            Ok(v) => v,
            Err(_) => return json_err(500, "bad_identity_key"),
        };
        let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
            Ok(s) => s,
            Err(_) => return json_err(400, "bad_signature"),
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        // The signature covers the RAW SPK public bytes — client-side
        // `account.sign(pub_key.as_bytes())` — which is the same convention relogin documents
        // and verifies on the way back out.
        if verifying.verify(&pub_bytes, &sig).is_err() {
            return json_err(403, "spk_sig_invalid");
        }
    }

    let now = now_secs();
    // Idempotent upsert: the same (user_id, device_id, prekey_id) arriving again on a retry
    // updates rather than 500s.
    db.prepare(
        "INSERT INTO signed_prekeys (user_id, prekey_id, prekey_pub, signature, created_at, device_id)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, device_id, prekey_id) DO UPDATE SET
           prekey_pub = excluded.prekey_pub,
           signature  = excluded.signature,
           created_at = excluded.created_at",
    )
    .bind(&[
        d1_text(&user_id),
        // 53-bit masked, at parity with registration and replenish.
        d1_prekey_id(body.prekey_id),
        d1_blob(&pub_bytes),
        d1_blob(&sig_bytes),
        d1_int(now as i64),
        d1_text(&device_id),
    ])?
    .run()
    .await?;

    // THE BOUND: keep only this device's newest MAX_SPK_ROWS_PER_DEVICE rows. Safe because nothing
    // reads past the newest, and the row just written carries `created_at = now` so it can never
    // prune itself. `rowid` breaks the tie — `signed_prekeys` is a plain rowid table (its PK is
    // composite, so no column aliases rowid) and two rotations in the same second share
    // `created_at`.
    //
    // Best-effort: the rotation has already succeeded and must not be reported as failed because
    // housekeeping did not run. The next rotation retries the prune.
    if let Ok(stmt) = db
        .prepare(
            "DELETE FROM signed_prekeys
              WHERE user_id = ? AND device_id = ?
                AND rowid NOT IN (
                  SELECT rowid FROM signed_prekeys
                   WHERE user_id = ? AND device_id = ?
                   ORDER BY created_at DESC, rowid DESC
                   LIMIT ?
                )",
        )
        .bind(&[
            d1_text(&user_id),
            d1_text(&device_id),
            d1_text(&user_id),
            d1_text(&device_id),
            d1_int(MAX_SPK_ROWS_PER_DEVICE),
        ])
    {
        let _ = stmt.run().await;
    }
    no_content()
}


#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;
