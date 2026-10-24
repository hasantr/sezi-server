//! The registration passes the checks a member's kernel runs on a contact's material.

use sezi_crypto::identity::otk_prekey_id;
use sezi_protocol::devices::{device_id_from_ed25519_b64, verify_bytes_sig, verify_device_list};
use vodozemac::Curve25519PublicKey;

use crate::mem::MemStore;
use crate::testutil::{bot, KEY};
use crate::{create_identity, signed_device_list, top_up_otks, SPK_PREKEY_ID};

#[test]
fn the_signed_list_names_one_primary_device_derived_from_its_key() {
    let reg = create_identity("user-bot", &KEY, 5, 1_700_000_000_000).expect("identity");
    let doc = verify_device_list(&reg.doc_json, &reg.sig_b64, &reg.ed_pub_b64).expect("verifies");
    assert_eq!(doc.user_id, "user-bot");
    assert_eq!(doc.rev, 1);
    assert_eq!(doc.devices.len(), 1);
    let d = &doc.devices[0];
    assert_eq!(d.role, "primary");
    assert_eq!(d.device_id, reg.device_id);
    assert_eq!(d.device_id, device_id_from_ed25519_b64(&reg.ed_pub_b64).unwrap());
    assert_eq!(d.x_pub_b64, reg.x_pub_b64);
    assert_eq!(d.added_at_ms, 1_700_000_000_000);
}

#[test]
fn the_signed_prekey_is_signed_over_its_public_bytes() {
    let reg = create_identity("user-bot", &KEY, 1, 1).expect("identity");
    let (id, spk_pub, spk_sig) = &reg.spk;
    assert_eq!(*id, SPK_PREKEY_ID);
    let bytes = vodozemac::base64_decode(spk_pub).unwrap();
    verify_bytes_sig(&bytes, spk_sig, &reg.ed_pub_b64).expect("the SPK signature verifies");
}

#[test]
fn one_time_key_ids_come_from_the_keys() {
    let reg = create_identity("user-bot", &KEY, 7, 1).expect("identity");
    assert_eq!(reg.otks.len(), 7);
    for (id, pub_b64) in &reg.otks {
        let k = Curve25519PublicKey::from_base64(pub_b64).unwrap();
        assert_eq!(*id, otk_prekey_id(&k));
    }
}

#[test]
fn a_top_up_adds_fresh_keys_and_stores_the_account() {
    let mut b = bot("user-bot");
    let before = b.store.account.clone();
    let fresh = top_up_otks(&mut b.store, &KEY, 4).expect("top up");
    assert_eq!(fresh.len(), 4);
    assert!(fresh.iter().all(|k| !b.reg.otks.contains(k)), "new keys, not the old ones again");
    assert_ne!(b.store.account, before);
    assert!(top_up_otks(&mut b.store, &KEY, 0).unwrap().is_empty());
    assert!(top_up_otks(&mut MemStore::default(), &KEY, 1).is_err(), "no account, no keys");
}

#[test]
fn the_list_can_be_signed_again_under_the_real_user_id() {
    let b = bot("pending");
    let (doc_json, sig) = signed_device_list(&b.store, &KEY, "user-00000002", 1, 5).expect("sign");
    let doc = verify_device_list(&doc_json, &sig, &b.reg.ed_pub_b64).expect("verifies");
    assert_eq!(doc.user_id, "user-00000002");
    assert_eq!(doc.devices[0].device_id, b.reg.device_id);
}
