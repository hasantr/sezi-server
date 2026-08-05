//! One slot of the key bundle: the per-device SPK read plus the atomic OTK claim that
//! `GET /keys/:user_id/bundle` repeats for every active device. Lifted out of `handlers.rs`
//! under the 800-line ceiling and declared there rather than in `keys/mod.rs`, so the routed
//! handlers stay the whole of `keys::handlers` from the outside — the shape `groups.rs` uses
//! for its own four lifted blocks.
//!
//! The two row shapes below live here because nothing else reads them: the bundle slot is the
//! only place an SPK row and a claimed OTK row are decoded together.

use crate::d1util::d1_text;
use crate::utils::b64_encode;
use serde::Deserialize;
use worker::*;

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

/// M2-S2.3: build the bundle slot for one device (its own SPK plus an OTK claim). `device`
/// None is the pre-device-list bootstrap window described at the call site, where the target
/// provably owns one device and the unfiltered queries therefore select it. A device
/// with no SPK is skipped by returning None, so it does not appear in the bundle; if no
/// device has an SPK, `devices` ends up empty.
pub(super) async fn build_device_bundle(
    db: &D1Database,
    target_id: &str,
    device: Option<&str>,
) -> Result<Option<serde_json::Value>> {
    // Newest SPK, scoped to exactly this device.
    let spk: Option<SpkRow> = match device {
        Some(d) => {
            // The selection used to widen to `device_id IS NULL OR device_id = ''` so a listed
            // device with no SPK of its own could be served the legacy slot's key. Every SPK is
            // written under a real device now — registration's inline write included — so there
            // is nothing in that slot to borrow, and borrowing would hand a peer a key belonging
            // to a different device. A device with no SPK yet is skipped instead.
            db.prepare(
                "SELECT prekey_id, prekey_pub, signature FROM signed_prekeys
                 WHERE user_id = ? AND device_id = ?
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&[d1_text(target_id), d1_text(d)])?
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

    // M2-S3.5 FIELD-CRITICAL: core REQUIRES `DeviceBundle.identity_pubkey_b64` (the peer's
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
