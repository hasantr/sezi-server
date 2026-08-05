use crate::auth::middleware::{require_active_auth, require_auth_device};
use crate::d1util::{d1_blob, d1_int, d1_prekey_id, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::{json_err, no_content};
use crate::utils::{b64_decode, b64_encode, now_secs};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::Deserialize;
use worker::*;

// The per-device bundle slot lifted out under the 800-line ceiling, declared here rather than in
// `keys/mod.rs` so the routed handlers stay the whole of `keys::handlers` from the outside — the
// shape `groups.rs` uses for its own four lifted blocks.
#[path = "bundle_slot.rs"]
mod bundle_slot;

use bundle_slot::build_device_bundle;

#[derive(Deserialize)]
struct UserRow {
    identity_pubkey: Vec<u8>,
}

/// M2-S2.3 bundle v2: an active device row — the server-side projection of the verified
/// device_lists doc (M1 `devices`). Each device gets its own SPK and its own claimed OTK.
#[derive(Deserialize)]
struct DeviceRow {
    device_id: String,
}

/// GET /keys/:user_id/bundle — bundle v2 (M2-S2.3): for every ACTIVE device, return its
/// per-device SPK and consume one of its OTKs. `device_list` (the signed doc plus its
/// signature) is carried verbatim so the client can verify the canonical device list. With
/// N=1, `devices[]` holds a single element (the primary), matching today's single-bundle
/// flow exactly.
pub async fn bundle(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let caller = match require_active_auth(&req, &ctx.env).await {
        Ok(auth) => auth.user_id,
        Err(resp) => return Ok(resp),
    };
    // FAZ-1(C): guard against prekey-DEPLETION DoS via the SPK fallback. Once the SPK
    // fallback landed (FAZ-1a), an attacker could fetch the bundle over and over, drain a
    // device's OTKs and force everyone onto the weak-forward-secrecy SPK. Hence a ceiling of
    // 60/min per caller — first contact is rare, and once a session exists the bundle is
    // never fetched again, so 60/min is more than generous. Only enforced in prod: local dev
    // is NOT throttled, so field testing is unaffected. A 429 tells the client to back off
    // and retry.
    // TEMPLATE DIET: if the ENV var is absent, assume "prod" (FAIL-SECURE); the KV binding
    // is OPTIONAL (with none we continue unlimited — see ratelimit::check_rate_limit_env).
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
    // primary's Ed25519 key (M1 device_lists; zero-trust, so the server can neither mint nor
    // alter it).
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
    // M2-S3.5 saha-fix: core expects `BundleRes.device_list: Option<DeviceListRes{doc_json,
    // sig_b64, rev}>`. The old `{doc, sig}` shape — wrong field names and no rev — blew up
    // the ENTIRE bundle decode in core. This emits the correct shape including rev (core is
    // now tolerant as well).
    let device_list_json = match device_list {
        Some(dl) => serde_json::json!({
            "doc_json": dl.doc_json,
            "sig_b64": dl.sig_b64,
            "rev": dl.rev,
        }),
        None => serde_json::Value::Null,
    };

    // Active devices (revoked_at IS NULL). Empty means the target registered but has not run
    // its first `PUT /devices/list` yet — a live bootstrap window, NOT a legacy population:
    // `auth::verify` writes `users`, the SPK and the OTK pool, and only this handler's sibling
    // creates `devices` rows. Fall back to one device-blind slot so a peer can still reach them.
    // Their SPK and OTKs are device-scoped and they own exactly one device, so the unfiltered
    // queries below select that device's material; only the reported `device_id` is unknown, and
    // core resolves it from the device list once published.
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

    // FIX-3 (HIGH→MED — the silently empty bundle): if `devices[]` comes back COMPLETELY
    // empty (no device has published an SPK, so `build_device_bundle` returned None for all
    // of them) the sender cannot establish an Olm session with ANY device. Rather than a
    // hollow 200, return the machine-readable error that mirrors the old single-bundle
    // behaviour: 503 `no_signed_prekey`. It is transient — it resolves as soon as the target
    // publishes an SPK, so the client may retry. A non-empty `devices[]` takes the normal 200
    // path below; with N=1 and the primary having published its SPK, devices holds one
    // element and the response is identical to before.
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

/// THE BOUND on `one_time_prekeys`: the largest UNCONSUMED pool one device may hold on the
/// server. Past it `replenish` refuses to add more (429 `otk_pool_full`).
///
/// Why a bound and not just a rate limit: `check_rate_limit_env` fails OPEN when the `RATE_LIMIT`
/// KV binding is absent (ratelimit.rs), so a limit is a brake that shapes bursts and never a
/// ceiling. Nothing else stopped this table growing — replenish APPENDS (deliberately, see the
/// long note in the handler), and no GC anywhere sweeps prekeys. This count needs no KV.
///
/// 300 is three times the client's `otk_pool_target` of 100 (`core/src/kernel/config.rs`), so a
/// correctly behaving device — which tops UP to its target and therefore uploads `target − pool` —
/// never comes near it. It is also far under vodozemac's `MAX_ONE_TIME_KEYS` = 5000, where the
/// device starts evicting the OLDEST private half while the server still hands out its oldest
/// first; that is the "unknown one-time key" wedge config.rs documents, and this ceiling is a
/// second guard against walking into it from the server side.
const MAX_OTK_POOL: i64 = 300;

/// THE BOUND on `signed_prekeys`: how many SPK rows one device keeps. Only the NEWEST row is ever
/// read — `bundle`'s `build_device_bundle` and `auth::relogin` both select
/// `ORDER BY created_at DESC LIMIT 1` — so everything behind the newest is dead weight that
/// `rotate_signed_prekey` appended and nothing ever removed.
///
/// 5 rather than 1: the rows are cheap, and keeping a little history means a rotation racing a
/// concurrent read cannot leave a window with no SPK at all. Bounding at 5 caps the table at
/// devices × 5.
const MAX_SPK_ROWS_PER_DEVICE: i64 = 5;

#[derive(Deserialize)]
struct OtkInput {
    // SAHA-FIX (2026-06-27): the client derives `otk_prekey_id` from the public key as a u64
    // (its first 8 bytes, little-endian), which does not fit in u32 → JSON deserialize FAILS →
    // /keys/otks/replenish returns 400 → the OTK pool stays EMPTY → no first-contact Olm
    // session can be established → crypto wedge (self-copy MAC mismatch, broken read sync,
    // messages stuck on a single tick). u64 is MANDATORY here.
    prekey_id: u64,
    prekey_pub_b64: String,
}

#[derive(Deserialize)]
struct ReplenishBody {
    otks: Vec<OtkInput>,
    /// This device's device_id, as the caller believes it to be. Optional and NOT the pool
    /// scope — that comes from the token, exactly as `otk_count` reads it. Present, it must
    /// agree; absent, the token still decides. Core's `run_replenish_otks` sends `None` when it
    /// cannot re-derive the device from a corrupt identity blob, and those keys used to land in
    /// the `''` pool nothing serves; they now reach the pool the device is served from.
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn replenish(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let (user_id, device_id) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    // SAHA-FIX (2026-06-27): `req.json()` goes through workerd's JS `JSON.parse`, so a
    // `prekey_id` above 2^53 — and a pubkey-derived otk_prekey_id exceeds 2^53 roughly 99% of
    // the time — is ROUNDED into an f64 → serde's u64 deserialize FAILS → every replenish 400s
    // → the OTK pool stays empty → Olm wedge. Taking `req.text()` and parsing it with Rust's
    // `serde_json` reads the full u64 EXACTLY, bypassing JS number precision. Widening u32→u64
    // on its own did NOT fix this: the root cause was precision, not width.
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
    // Hardening #8: stop one device from wiping and poisoning ANOTHER device's OTK pool. A
    // same-account or stolen-token device sending body.device_id=VICTIM would write its own keys
    // into the victim's slot — a decrypt DoS. The pool is the TOKEN's device, so that is now
    // impossible by construction rather than by comparison; the body claim is still checked,
    // because a client naming a device other than its own is a bug worth surfacing.
    if let Some(claim) = body.device_id.as_deref() {
        if claim != device_id {
            return json_err(403, "device_mismatch");
        }
    }
    // A revoked device may not publish at all. This used to run only when the body named a
    // device, so a caller could skip it by omitting the field.
    if crate::auth::middleware::device_revoked(&ctx.env, &user_id, &device_id).await? {
        return json_err(401, "device_revoked");
    }
    // A BRAKE (see MAX_OTK_POOL for why it is not the bound). Nothing limited how OFTEN this could
    // be called: 100 OTKs per request × unlimited requests, appended, never swept. 30 calls per 5
    // minutes is far above the real cadence — a device replenishes at attach and after consuming
    // keys, not in a loop — while stopping a script from walking to the pool ceiling instantly and
    // then hammering the rejection path. Scoped per DEVICE, since the pool is per device and a
    // multi-device account must not have its siblings share one budget.
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
    // REPLENISH APPENDS. It used to DELETE this device's unconsumed OTKs first, so the upload was
    // a CLEAN REPLACE — and that is what kept the pool below target, permanently.
    //
    // Measured on the live relay 2026-07-29 (task #59). One device: 100 unconsumed at 21:20, 28
    // claimed by peers, then a replenish uploaded 50 → the DELETE removed the 72 survivors and the
    // insert added 50. Row totals confirm it exactly: 648 → 626 (−72 +50), unconsumed 100 → 50.
    // With a client that uploads `target − pool` (which is the only correct amount to GENERATE),
    // replace semantics make the pool settle at the size of the last delta and oscillate there. It
    // can never reach the target, and an empty pool means first contact falls back to the signed
    // prekey with no forward secrecy — the failure this whole path exists to prevent.
    //
    // The DELETE was introduced for the old `enumerate()` bug: prekey_id restarted at 1..N, collided
    // under INSERT OR IGNORE, and fresh OTKs were silently dropped while the recipient had already
    // discarded the matching private key — the "unknown one-time key" field symptom. **That was
    // fixed at the root** (task #16): `prekey_id` is now derived from the public key itself
    // (`identity::otk_prekey_id`), so two different keys cannot collide and re-publishing the SAME
    // key is a no-op under INSERT OR IGNORE. The cleanup outlived the bug it cleaned up after.
    //
    // What the DELETE also did, and this is the honest cost of removing it: after a local store
    // rewind (an identity restore from backup) the device's OLD public keys stay on the server and
    // can still be handed to a peer, whose PreKey message this device can no longer answer. That is
    // now a first-contact retry — the session self-heal (OlmReinit / pair-ack) covers it — rather
    // than a permanent wedge, and it costs one peer one round trip in a rare flow. The alternative
    // costs every peer forward secrecy in the common one. If the restore case ever bites, the fix is
    // an explicit `replace: true` flag the client sets when it KNOWS its store was rewound, not a
    // blanket wipe on every top-up.
    //
    // F10 (2026-06-28) kept the DELETE and the INSERTs in ONE atomic `db.batch` so a committed
    // DELETE plus a failing INSERT could not leave the pool empty. With no DELETE that hazard is
    // gone by construction, and the batch stays for the atomicity of the inserts themselves.
    // ≤5 INSERT chunks (100 OTKs at 20 per chunk) = ≤5 statements and ≤400 binds, inside the D1
    // batch limit.
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
            // SAHA-FIX (2026-06-27/28): prekey_id is a pubkey-derived u64, so it is bound to
            // D1 through the 53-bit mask in d1util::d1_prekey_id — deliberately one single
            // place. That mask is what avoids workerd's JS-Number f64 trap, which was the root
            // of the bundle 500s.
            binds.push(d1_prekey_id(k.prekey_id));
            binds.push(d1_blob(p));
            binds.push(d1_text(&device_id));
        }
        stmts.push(db.prepare(&sql).bind(&binds)?);
    }
    db.batch(stmts).await?;

    // MEASURE WHAT ACTUALLY HAPPENED, not what the client asked for.
    //
    // This used to answer `{"count": body.otks.len()}` — the size of the request, echoed back. So
    // the one shape that could silently destroy a pool was invisible from both ends: the client
    // uploads only the keys it just GENERATED (a delta), while the replace-on-publish above removed
    // the whole unconsumed pool. A device holding 100 keys that consumed 25 generated 25 — and this
    // endpoint then removed the 75 survivors and inserted 25, answering "count: 25" either way.
    //
    // That number is what caught it. Added 2026-07-28 to make the shrink falsifiable; the very next
    // day the D1 rows showed `pool_after == uploaded` on a pool that had held twice as much, which
    // is the shrink confirmed rather than suspected (task #59). The DELETE is gone now, so this
    // reads as the health check it should always have been: `pool_after` climbing toward the
    // client's target across rounds is the pool working, and `pool_after == uploaded` returning
    // would mean replace semantics had come back.
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

/// GET /keys/otks/count — how many UNCONSUMED one-time prekeys the SERVER still holds for the
/// CALLER's own device. Authenticated, and scoped to the token's user and device: there is no
/// path here that reads another user's pool.
///
/// Why it exists (task #53): the local count and the server count are not proxies for one
/// another. `bundle` claims an OTK for EVERY active device on every fetch, whether the caller
/// ends up using it or not, while the core only counts the PreKey messages it actually decrypts —
/// so the two numbers drift apart by construction and, until now, invisibly. This is the read
/// side of that comparison; the core logs both on one line at attach.
///
/// Diagnostic only: it mutates nothing, and a failed count answers 200 with `-1` rather than an
/// error, so a caller can never be harmed by asking.
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
    // SAHA-FIX (2026-06-27): the client's prekey_id is a u64, kept at parity with OtkInput so
    // it cannot hit the u32 parse failure.
    prekey_id: u64,
    prekey_pub_b64: String,
    signature_b64: String,
    /// This device's device_id, as the caller believes it to be. Optional and NOT the slot the
    /// row lands in — that is the token's device. Present, it must agree.
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn rotate_signed_prekey(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // The slot is the TOKEN's device. There is no longer a device-less write, and therefore no
    // longer a `''` slot for an identity claim to be planted in — see the deleted
    // `device_less_spk_write_allowed` and `auth::relogin`'s SPK selection.
    let (user_id, device_id) = match require_auth_device(&req, &ctx.env) {
        Ok(pair) => pair,
        Err(resp) => return Ok(resp),
    };
    // SAHA-FIX (2026-06-27): req.json() loses precision through JS (see replenish), so read
    // text() and parse with serde_json::from_str.
    let raw = match req.text().await {
        Ok(t) => t,
        Err(_) => return json_err(400, "bad_request"),
    };
    let body: SignedPrekeyBody = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(_) => return json_err(400, "bad_request"),
    };
    // Hardening #8 (the SPK twin): stop a device from overwriting another device's signed
    // prekey. The row's slot is the token's device, so that is structural now; the body claim is
    // still compared, because a client naming a device other than its own is a bug worth
    // surfacing rather than silently rewriting.
    if let Some(claim) = body.device_id.as_deref() {
        if claim != device_id {
            return json_err(403, "device_mismatch");
        }
    }
    // A revoked device cannot rotate. This used to run only when the body named a device.
    if crate::auth::middleware::device_revoked(&ctx.env, &user_id, &device_id).await? {
        return json_err(401, "device_revoked");
    }
    // A BRAKE on rotation. The upsert key is (user_id, device_id, prekey_id), so re-publishing the
    // SAME prekey_id updates one row — but a caller walking prekey_id APPENDS a row every time,
    // and nothing swept them. The prune at the end of this handler is the bound; this limit keeps
    // a caller from spending signature verifications and D1 writes to reach it. Ten per hour is
    // orders of magnitude above real rotation, which happens at registration and at device-link
    // finalize and is not on any timer in the client at all.
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
    // It used to be written VERBATIM with no signature check, while `auth::relogin` treats "the
    // presented Ed25519 key verifies the newest stored SPK row" as PROOF OF IDENTITY. So anyone
    // holding any access token for this user — including a device revoked seconds earlier, whose
    // access token stays valid for the rest of its 15-minute TTL — could store an SPK signed with
    // their OWN key and relogin AS the user for a 30-day renewable session. Device-less, that
    // session carried no device claim either, so `validate_active_token` never re-checked it: a
    // token meant to die in minutes became permanent.
    //
    // The claim is checked against `devices.ed_pub` for the writing device — the device list is
    // primary-signed and each device_id is `hex(blake3(ed_pub)[..8])`. It is also the RIGHT key:
    // a device signs its own SPK with its own Olm account, whose `ed25519_key()` is what the
    // list carries. A LINKED device is deliberately NOT checked against `users.identity_ed_pub`
    // — its SPK is signed by its own account, not the primary's identity, so anchoring it there
    // would reject every legitimate linked device (the trap M2-S3.2 documents for relogin's
    // per-device SPK selection).
    // The step is not new — relogin and `validate_and_store_signed_list` both do it. Doing it
    // where the row is CREATED, rather than only where it is trusted, is.
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
    // NO ANCHOR is the remaining edge. Ed25519 offers no public-key recovery and the wire carries
    // no key to check against, so with nothing stored there is nothing to verify and the write is
    // accepted. Exactly ONE case reaches it now, and it is contained: a device with no `devices`
    // row yet — the registration bootstrap window, before the first `PUT /devices/list`. The
    // token binding pins the write to the caller's own device_id, so it reaches only that
    // device's own slot, which `auth::relogin` reads only when asked for that device and then
    // applies its own revoked check to.
    //
    // The second case is GONE rather than mitigated: a device-less write on an account with no
    // device list and a NULL `users.identity_ed_pub` had no anchor AND landed in the `''` slot
    // that a device-less relogin would then read as proof of identity. Requiring a device on both
    // sides removes the slot, so there is nothing to plant and nothing that would read it.
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
    // Idempotent upsert (M2-S3.2c fix): when a linked device publishes its finalize SPK and
    // the same (user_id, device_id, prekey_id) arrives again on a retry, update rather than 500.
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
        // SAHA-FIX (2026-06-28): the SPK rotate prekey_id is 53-bit masked too, at parity
        // with registration and replenish.
        d1_prekey_id(body.prekey_id),
        d1_blob(&pub_bytes),
        d1_blob(&sig_bytes),
        d1_int(now as i64),
        d1_text(&device_id),
    ])?
    .run()
    .await?;

    // THE BOUND: keep only this device's newest MAX_SPK_ROWS_PER_DEVICE rows.
    //
    // Safe because nothing reads past the newest one: `build_device_bundle` and `auth::relogin`
    // both take `ORDER BY created_at DESC LIMIT 1` for this exact (user_id, device_id). The row
    // just written carries `created_at = now`, so it is always inside the keep-set and can never
    // prune itself. `signed_prekeys` is a plain rowid table (its PK is the composite
    // (user_id, device_id, prekey_id), so no column aliases rowid), which makes `rowid` available
    // as the tiebreaker — needed because two rotations inside the same second share `created_at`
    // and would otherwise order non-deterministically.
    //
    // Best-effort: the rotation itself has already succeeded and MUST NOT be reported as failed
    // because housekeeping did not run. A skipped prune is retried by the next rotation.
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
