use crate::auth::middleware::{require_active_auth, require_auth};
use crate::d1util::{d1_blob, d1_int, d1_prekey_id, d1_text};
use crate::ratelimit::check_rate_limit_env;
use crate::respond::{json_err, no_content};
use crate::utils::{b64_decode, b64_encode, now_secs};
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct UserRow {
    identity_pubkey: Vec<u8>,
}

#[derive(Deserialize)]
struct SpkRow {
    prekey_id: i64,
    prekey_pub: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct OtkRow {
    #[allow(dead_code)] // part of the D1 row shape: returned by the query, never read in Rust
    id: i64,
    prekey_id: i64,
    prekey_pub: Vec<u8>,
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

    // Active devices (revoked_at IS NULL). If empty — pre-M1, or no device list published
    // yet — fall back to legacy: a single "primary" slot with no device_id, preserving the
    // old single-device behaviour where SPK and OTK are claimed without a device filter.
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

/// M2-S2.3: build the bundle slot for one device (its own SPK plus an OTK claim). `device`
/// None means the legacy device-unfiltered path (old single-device compatibility). A device
/// with no SPK is skipped by returning None, so it does not appear in the bundle; if no
/// device has an SPK, `devices` ends up empty.
async fn build_device_bundle(
    db: &D1Database,
    target_id: &str,
    device: Option<&str>,
) -> Result<Option<serde_json::Value>> {
    // Newest SPK, scoped by device (a NULL device_id must still match an old/legacy SPK).
    let spk: Option<SpkRow> = match device {
        Some(d) => {
            // PREFER the row whose device_id matches, and fall back to the legacy SPK.
            // mig 0015 rewrote old NULL device_ids to '', BUT on a prod first deploy the
            // code can land BEFORE the migration (the atomic wire-cut window), so on a
            // pre-0015 schema the legacy SPK is still NULL. Tolerating `IS NULL` (parity
            // with `auth::relogin` and `devices::handlers`'s SPK selects) makes this independent of
            // deploy order; without it a legacy peer gets 503 no_signed_prekey and Olm
            // cannot be established server-wide.
            db.prepare(
                "SELECT prekey_id, prekey_pub, signature FROM signed_prekeys
                 WHERE user_id = ? AND (device_id = ? OR device_id IS NULL OR device_id = '')
                 ORDER BY CASE WHEN device_id = ? THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
            )
            .bind(&[d1_text(target_id), d1_text(d), d1_text(d)])?
            .first(None)
            .await?
        }
        None => {
            db.prepare(
                "SELECT prekey_id, prekey_pub, signature FROM signed_prekeys
                 WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&[d1_text(target_id)])?
            .first(None)
            .await?
        }
    };
    let spk = match spk {
        Some(s) => s,
        None => return Ok(None), // this device has not published an SPK yet → skip it
    };

    // M2-S3.5 SAHA-KRİTİK: core REQUIRES `DeviceBundle.identity_pubkey_b64` (the peer's
    // x_pub/Curve25519 key used for first-contact Olm). The field was MISSING, so the moment a
    // peer published a device list (making devices[] non-empty) core's BundleRes decode blew
    // up entirely ("error decoding response body") and every send died. Per-device it comes
    // from `devices.x_pub`; on the legacy (None) path from `users.identity_pubkey`, the root
    // DH key. If the device or user row is absent, skip this slot.
    let identity_pub: Vec<u8> = match device {
        Some(d) => {
            #[derive(Deserialize)]
            struct XRow {
                x_pub: Vec<u8>,
            }
            let row: Option<XRow> = db
                .prepare("SELECT x_pub FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1")
                .bind(&[d1_text(target_id), d1_text(d)])?
                .first(None)
                .await?;
            match row {
                Some(r) => r.x_pub,
                None => return Ok(None),
            }
        }
        None => {
            #[derive(Deserialize)]
            struct URow {
                identity_pubkey: Vec<u8>,
            }
            let row: Option<URow> = db
                .prepare("SELECT identity_pubkey FROM users WHERE id = ? LIMIT 1")
                .bind(&[d1_text(target_id)])?
                .first(None)
                .await?;
            match row {
                Some(r) => r.identity_pubkey,
                None => return Ok(None),
            }
        }
    };

    // Atomic per-device OTK claim in a single `UPDATE ... RETURNING`: SQLite's implicit
    // transaction guarantees that concurrent requests cannot hand the same OTK to two peers.
    // M2-S2.3 scopes the claim with `AND device_id = ?` (device None → the legacy
    // device-unfiltered pool). If the subquery yields NULL the update is a no-op and
    // RETURNING is an empty set, so the OTK comes back null: a working but not forward-secret
    // fallback prekey session, and a client retry will pick up a real OTK.
    let otk: Option<OtkRow> = match device {
        Some(d) => {
            db.prepare(
                "UPDATE one_time_prekeys SET consumed = 1
                 WHERE id = (
                   SELECT id FROM one_time_prekeys
                   WHERE user_id = ? AND device_id = ? AND consumed = 0
                   ORDER BY id ASC LIMIT 1
                 )
                 RETURNING id, prekey_id, prekey_pub",
            )
            .bind(&[d1_text(target_id), d1_text(d)])?
            .first(None)
            .await?
        }
        None => {
            db.prepare(
                "UPDATE one_time_prekeys SET consumed = 1
                 WHERE id = (
                   SELECT id FROM one_time_prekeys
                   WHERE user_id = ? AND consumed = 0
                   ORDER BY id ASC LIMIT 1
                 )
                 RETURNING id, prekey_id, prekey_pub",
            )
            .bind(&[d1_text(target_id)])?
            .first(None)
            .await?
        }
    };

    let otk_json = if let Some(o) = otk {
        serde_json::json!({
            "prekey_id": o.prekey_id,
            "prekey_pub_b64": b64_encode(&o.prekey_pub),
        })
    } else {
        serde_json::Value::Null
    };

    Ok(Some(serde_json::json!({
        "device_id": device,
        "identity_pubkey_b64": b64_encode(&identity_pub),
        "signed_prekey": {
            "prekey_id": spk.prekey_id,
            "prekey_pub_b64": b64_encode(&spk.prekey_pub),
            "signature_b64": b64_encode(&spk.signature),
        },
        "one_time_key": otk_json,
    })))
}

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
    // M2-S1 (optional): this device's device_id. When omitted, rows are written with the
    // legacy '' sentinel — mig 0016 made the column NOT NULL DEFAULT '' (see the bind below).
    // Since M2-S2.3 the bundle claims OTKs per device (`AND device_id = ?`), so the pool
    // written here is exactly the one that device is served from.
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn replenish(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
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
    // Sağlamlaştırma #8: stop one device from wiping and poisoning ANOTHER device's OTK pool. A
    // same-account or stolen-token device sending body.device_id=VICTIM would DELETE the
    // victim's OTKs and write its own into that slot — a decrypt DoS. Parity with the
    // send-path device binding: if body.device_id is present it MUST match the token, and a
    // revoked device may not publish at all. (Legacy: device_id None targets the old ''
    // single pool, which leaves modern devices untouched.)
    {
        let token_device = crate::auth::middleware::extract_bearer(&req)
            .and_then(|t| crate::auth::jwt::device_id_from_token(&ctx.env, &t).ok().flatten());
        if body.device_id.is_some() && token_device.as_deref() != body.device_id.as_deref() {
            return json_err(403, "device_mismatch");
        }
        if let Some(dev) = body.device_id.as_deref() {
            if crate::auth::middleware::device_revoked(&ctx.env, &user_id, dev).await? {
                return json_err(401, "device_revoked");
            }
        }
    }
    let device_id = body.device_id.as_deref();
    let db = ctx.env.d1("DB")?;
    // KÖK-FIX (stale-OTK cleanup; the field symptom was "unknown one-time key"): delete this
    // device's OLD unconsumed OTKs so the fresh batch is a CLEAN REPLACE. This is what clears
    // the stale public keys left behind by the old enumerate bug — prekey_id restarted at
    // 1..N, collided under INSERT OR IGNORE, and the new OTKs were silently dropped — whose
    // matching private key the recipient had already discarded, hence "unknown". Rows with
    // consumed=1 (already claimed) are NEVER touched. Scoped by device, with '' as the legacy
    // sentinel; and the delete is not load-bearing on its own — if it fails, the fresh insert
    // still runs.
    // F10 (2026-06-28): run the DELETE and the INSERTs as ONE atomic `db.batch`
    // (all-or-nothing). It used to be a best-effort DELETE — its own commit, errors swallowed
    // — followed by separate INSERTs, so a committed DELETE plus a failing INSERT could leave
    // the device's OTK pool EMPTY, pushing new first contacts onto the SPK-only fallback with
    // no forward secrecy (an FS degradation window). All-or-nothing means the pool is never
    // left half-empty.
    // ≤1 DELETE + ≤5 INSERT chunks (100 OTKs at 20 per chunk) = ≤6 statements and ≤400 binds,
    // inside the D1 batch limit.
    let device_sentinel = device_id.unwrap_or("");
    let mut stmts: Vec<D1PreparedStatement> = Vec::with_capacity(6);
    // DELETE first (fresh replace): drop this device's old unconsumed OTKs. consumed=1 rows
    // are NEVER touched.
    stmts.push(
        db.prepare("DELETE FROM one_time_prekeys WHERE user_id = ? AND device_id = ? AND consumed = 0")
            .bind(&[d1_text(&user_id), d1_text(device_sentinel)])?,
    );
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
            // mig 0016 made device_id NOT NULL DEFAULT '', so binding NULL would violate the
            // constraint; '' is the legacy sentinel.
            binds.push(d1_text(device_sentinel));
        }
        stmts.push(db.prepare(&sql).bind(&binds)?);
    }
    db.batch(stmts).await?;
    Response::from_json(&serde_json::json!({ "count": body.otks.len() }))
}

#[derive(Deserialize)]
struct SignedPrekeyBody {
    // SAHA-FIX (2026-06-27): the client's prekey_id is a u64, kept at parity with OtkInput so
    // it cannot hit the u32 parse failure.
    prekey_id: u64,
    prekey_pub_b64: String,
    signature_b64: String,
    // M2-S1 (optional): this device's device_id. When omitted the row is written with the
    // legacy '' sentinel (see the bind below).
    #[serde(default)]
    device_id: Option<String>,
}

pub async fn rotate_signed_prekey(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user_id = match require_auth(&req, &ctx.env) {
        Ok(uid) => uid,
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
    // Sağlamlaştırma #8 (the SPK twin): stop a device from overwriting another device's signed
    // prekey — parity with the send-path device binding (if body.device_id is present it must
    // match the token, and a revoked device cannot rotate).
    {
        let token_device = crate::auth::middleware::extract_bearer(&req)
            .and_then(|t| crate::auth::jwt::device_id_from_token(&ctx.env, &t).ok().flatten());
        if body.device_id.is_some() && token_device.as_deref() != body.device_id.as_deref() {
            return json_err(403, "device_mismatch");
        }
        if let Some(dev) = body.device_id.as_deref() {
            if crate::auth::middleware::device_revoked(&ctx.env, &user_id, dev).await? {
                return json_err(401, "device_revoked");
            }
        }
    }
    let pub_bytes =
        b64_decode(&body.prekey_pub_b64).map_err(|_| Error::RustError("bad pub".into()))?;
    let sig_bytes =
        b64_decode(&body.signature_b64).map_err(|_| Error::RustError("bad sig".into()))?;
    let now = now_secs();
    let db = ctx.env.d1("DB")?;
    // Idempotent upsert (M2-S3.2c fix): when a linked device publishes its finalize SPK and
    // the same (user_id, device_id, prekey_id) arrives again on a retry, update rather than
    // 500. A NULL device_id becomes the '' sentinel, since the PK column is NOT NULL.
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
        d1_text(body.device_id.as_deref().unwrap_or("")),
    ])?
    .run()
    .await?;
    no_content()
}
