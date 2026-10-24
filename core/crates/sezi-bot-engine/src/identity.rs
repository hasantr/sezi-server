//! The bot's identity: made once, never regenerated (docs/BOTS_BUILD.md §5 — a new key behind the
//! same user id is `key_changed` at every member, fail-closed). Built from the same pieces as a
//! human device's registration (`kernel::runners::auth::build_registration_material`), so the
//! checks a member's kernel runs on a contact's material (`verify_grant_peer_material`) pass.

use sezi_crypto::identity::otk_prekey_id;
use sezi_crypto::identity::Identity;
use sezi_error::{Error, Result};
use sezi_protocol::devices::{build_signed_device_list, device_id_from_ed25519_b64, DeviceEntry};

use crate::store::{load_account, BotStore};
use crate::Registration;

/// The signed prekey's id. Fixed, as on a human device: there is exactly one current signed
/// prekey per device and the relay replaces it in place, so its id must never change.
pub const SPK_PREKEY_ID: u64 = 1;

/// The label of the bot's one device in its signed list.
pub const DEVICE_LABEL: &str = "Bot";

pub(crate) fn create_identity(
    user_id: &str,
    pickle_key: &[u8; 32],
    otks: usize,
    now_ms: i64,
) -> Result<Registration> {
    let mut id = Identity::generate();
    id.generate_otks(otks);
    let otk_list = unpublished(&id);
    // The fallback key IS the signed prekey: Olm falls back to it once the one-time keys run out.
    let (spk_pub_b64, spk_sig_b64) = id.rotate_signed_fallback_b64();
    id.mark_otks_published();

    let fp = id.fingerprint();
    let device_id = device_id_from_ed25519_b64(&fp.ed25519_b64)?;
    let (doc_json, sig_b64) =
        device_list(&id, user_id, 1, &device_id, &fp.ed25519_b64, &fp.x25519_b64, now_ms)?;
    Ok(Registration {
        account_pickle: id.account().pickle().encrypt(pickle_key),
        device_id,
        ed_pub_b64: fp.ed25519_b64,
        x_pub_b64: fp.x25519_b64,
        doc_json,
        sig_b64,
        spk: (SPK_PREKEY_ID, spk_pub_b64, spk_sig_b64),
        otks: otk_list,
    })
}

pub(crate) fn top_up_otks(
    store: &mut impl BotStore,
    pickle_key: &[u8; 32],
    n: usize,
) -> Result<Vec<(u64, String)>> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut id = Identity::from_parts(load_account(store, pickle_key)?, None);
    id.generate_otks(n);
    let fresh = unpublished(&id);
    id.mark_otks_published();
    store.put_account(id.account().pickle().encrypt(pickle_key));
    Ok(fresh)
}

/// The bot's one-device list, signed again under `user_id` at `rev`. For a host that learns the
/// bot's user id only after the identity exists (the wire scenarios register through the mock,
/// which assigns it), and for re-publishing the list.
pub(crate) fn signed_device_list(
    store: &impl BotStore,
    pickle_key: &[u8; 32],
    user_id: &str,
    rev: u64,
    added_at_ms: i64,
) -> Result<(String, String)> {
    let id = Identity::from_parts(load_account(store, pickle_key)?, None);
    let fp = id.fingerprint();
    let device_id = device_id_from_ed25519_b64(&fp.ed25519_b64)?;
    device_list(&id, user_id, rev, &device_id, &fp.ed25519_b64, &fp.x25519_b64, added_at_ms)
}

fn device_list(
    id: &Identity,
    user_id: &str,
    rev: u64,
    device_id: &str,
    ed_pub_b64: &str,
    x_pub_b64: &str,
    added_at_ms: i64,
) -> Result<(String, String)> {
    let entry = DeviceEntry {
        device_id: device_id.to_owned(),
        role: "primary".into(),
        ed_pub_b64: ed_pub_b64.to_owned(),
        x_pub_b64: x_pub_b64.to_owned(),
        label: DEVICE_LABEL.into(),
        added_at_ms,
    };
    build_signed_device_list(id.account(), user_id, rev, vec![entry])
        .map_err(|e| Error::Crypto(format!("bot/device-list: {e}")))
}

/// The keys not yet published, as `(prekey_id, public key)`, sorted by id. The id is derived
/// from the public key (`otk_prekey_id`), never from a position: the relay inserts OTKs with
/// `INSERT OR IGNORE (user, device, prekey_id)`, so positional ids would collide on every top-up.
fn unpublished(id: &Identity) -> Vec<(u64, String)> {
    let mut keys: Vec<(u64, String)> = id
        .unpublished_otks()
        .into_values()
        .map(|k| (otk_prekey_id(&k), vodozemac::base64_encode(k.to_bytes())))
        .collect();
    keys.sort();
    keys
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
