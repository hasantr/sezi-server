use super::*;

use ed25519_dalek::{Signer, SigningKey};

const SERVER: &str = "test-server:fingerprint-v2";
const ISSUED: i64 = 1_700_000_000_000;
const EXPIRES: i64 = ISSUED + 300_000;

fn principal(user_id: &str, signing: &SigningKey, x_byte: u8) -> ContactPrincipalV2 {
    let ed = signing.verifying_key().to_bytes();
    let x = [x_byte; X25519_PUBLIC_BYTES];
    ContactPrincipalV2 {
        user_id: user_id.into(),
        root_ed_pub_b64: STANDARD_NO_PAD.encode(ed),
        root_x_pub_b64: STANDARD_NO_PAD.encode(x),
        device_id: hex::encode(&blake3::hash(&ed).as_bytes()[..8]),
        device_ed_pub_b64: STANDARD_NO_PAD.encode(ed),
        device_x_pub_b64: STANDARD_NO_PAD.encode(x),
    }
}

fn signed_fixture() -> (String, String) {
    let issuer_key = SigningKey::from_bytes(&[3; 32]);
    let claimant_key = SigningKey::from_bytes(&[5; 32]);
    let secret = [9; CAPABILITY_SECRET_BYTES];
    let offer_id = hex::encode([7; OFFER_ID_BYTES]);
    let mut offer = MutualOnceOfferV2 {
        v: CONTACT_PROTOCOL_V2,
        mode: MUTUAL_ONCE_MODE_V2.into(),
        server_instance: SERVER.into(),
        offer_id: offer_id.clone(),
        issuer: principal("issuer", &issuer_key, 4),
        issued_at_ms: ISSUED,
        expires_at_ms: EXPIRES,
        max_claims: 1,
        capability_commitment_hex: capability_commitment_hex(SERVER, &offer_id, &secret)
            .unwrap(),
        issuer_signature_b64: STANDARD_NO_PAD.encode([0; ED25519_SIGNATURE_BYTES]),
    };
    offer.issuer_signature_b64 = STANDARD_NO_PAD.encode(
        issuer_key
            .sign(&canonical_offer_unsigned(&offer).unwrap())
            .to_bytes(),
    );
    let offer_hash = offer_hash_hex(&offer).unwrap();

    let mut claim = MutualOnceClaimV2 {
        v: CONTACT_PROTOCOL_V2,
        mode: MUTUAL_ONCE_MODE_V2.into(),
        server_instance: SERVER.into(),
        offer_id,
        offer_hash_hex: offer_hash,
        claimant: principal("claimant", &claimant_key, 6),
        claimant_list_rev: 2,
        nonce_hex: hex::encode([8; NONCE_BYTES]),
        claimed_at_ms: ISSUED + 1_000,
        grants: vec![MUTUAL_CONTACT_GRANT_V2.into()],
        capability_secret_b64: STANDARD_NO_PAD.encode(secret),
        claimant_signature_b64: STANDARD_NO_PAD.encode([0; ED25519_SIGNATURE_BYTES]),
        capability_proof_b64: STANDARD_NO_PAD.encode([0; HASH_BYTES]),
    };
    let unsigned = canonical_claim_unsigned(&claim).unwrap();
    let signature = claimant_key.sign(&unsigned).to_bytes();
    claim.claimant_signature_b64 = STANDARD_NO_PAD.encode(signature);
    let mut proof_input = CanonicalWriter::new(CAPABILITY_PROOF_DOMAIN);
    proof_input.put_bytes(&unsigned).unwrap();
    proof_input.put_bytes(&signature).unwrap();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&secret).unwrap();
    mac.update(&proof_input.finish());
    claim.capability_proof_b64 = STANDARD_NO_PAD.encode(mac.finalize().into_bytes());

    (
        serde_json::to_string(&offer).unwrap(),
        serde_json::to_string(&claim).unwrap(),
    )
}

#[test]
fn signed_offer_and_claim_verify_end_to_end() {
    let (offer, claim) = signed_fixture();
    let verified = verify_claim_json(&offer, &claim, SERVER, ISSUED + 2_000).unwrap();
    assert_eq!(verified.offer.issuer.user_id, "issuer");
    assert_eq!(verified.claim.claimant.user_id, "claimant");
    assert_eq!(verified.claim.grants, [MUTUAL_CONTACT_GRANT_V2]);
    assert_eq!(verified.claim_id_hex.len(), HASH_BYTES * 2);
}

#[test]
fn server_expiry_and_grant_escalation_fail_closed() {
    let (offer, claim) = signed_fixture();
    assert_eq!(
        verify_claim_json(&offer, &claim, "another-server", ISSUED + 2_000)
            .unwrap_err()
            .kind,
        VerifyErrorKind::WrongServer
    );
    assert_eq!(
        verify_claim_json(&offer, &claim, SERVER, EXPIRES)
            .unwrap_err()
            .kind,
        VerifyErrorKind::Expired
    );

    let mut escalated: MutualOnceClaimV2 = serde_json::from_str(&claim).unwrap();
    escalated.grants.push("messages.admin".into());
    assert_eq!(
        verify_claim_json(
            &offer,
            &serde_json::to_string(&escalated).unwrap(),
            SERVER,
            ISSUED + 2_000,
        )
        .unwrap_err()
        .kind,
        VerifyErrorKind::GrantRejected
    );
}

#[test]
fn sql_keeps_single_winner_and_cannot_revive_replayed_grant() {
    assert!(INSERT_CLAIM_SQL.contains("INSERT OR IGNORE"));
    assert!(CONSUME_OFFER_SQL.contains("consumed_claim_id IS NULL OR consumed_claim_id=?1"));
    assert!(UPSERT_QR_GRANT_SQL.contains("c.grant_applied=0"));
    assert!(MARK_CLAIM_GRANT_SQL.contains("c.grant_applied=0"));
    assert!(INSERT_ISSUER_REVISION_SQL.contains("INSERT OR IGNORE"));
    assert!(INSERT_CLAIMANT_REVISION_SQL.contains("INSERT OR IGNORE"));
}
