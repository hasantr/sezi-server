//! Contact QR V2 verification / canonicalisation layer — the `verify_offer_json` and
//! `verify_claim_json` entry points, Ed25519/SHA-256/HMAC, and byte-for-byte
//! canonical-transcript verification (`CanonicalWriter`). Split out of contact_qr.rs
//! as a PURE MOVE; the handlers (create_offer/claim_offer/offer_status) call its
//! `pub(super)` surface. Shared types and consts plus the crypto imports
//! (base64/ed25519/hmac/sha2) come from the parent through `use super::*`.
use super::*;

pub(super) fn verify_offer_json(
    offer_json: &str,
    expected_server: &str,
    now_ms_value: i64,
) -> VerifyResult<VerifiedOffer> {
    let offer: MutualOnceOfferV2 = parse_json(offer_json)?;
    validate_offer_structure(&offer)?;
    let transcript = canonical_offer_unsigned(&offer)?;
    verify_ed25519(
        &offer.issuer.device_ed_pub_b64,
        &transcript,
        &offer.issuer_signature_b64,
    )?;
    if offer.server_instance != expected_server {
        return failure(VerifyErrorKind::WrongServer, "wrong server");
    }
    if now_ms_value < offer.issued_at_ms {
        return failure(VerifyErrorKind::NotYetValid, "offer not yet valid");
    }
    if now_ms_value >= offer.expires_at_ms {
        return failure(VerifyErrorKind::Expired, "offer expired");
    }
    let offer_hash_hex = offer_hash_hex(&offer)?;
    Ok(VerifiedOffer {
        offer,
        offer_hash_hex,
    })
}

pub(super) fn verify_claim_json(
    offer_json: &str,
    claim_json: &str,
    expected_server: &str,
    now_ms_value: i64,
) -> VerifyResult<VerifiedClaim> {
    let verified_offer = verify_offer_json(offer_json, expected_server, now_ms_value)?;
    let claim: MutualOnceClaimV2 = parse_json(claim_json)?;
    validate_claim_structure(&claim)?;
    if claim.server_instance != expected_server
        || claim.server_instance != verified_offer.offer.server_instance
    {
        return failure(VerifyErrorKind::WrongServer, "claim wrong server");
    }
    if claim.offer_id != verified_offer.offer.offer_id
        || claim.offer_hash_hex != verified_offer.offer_hash_hex
    {
        return failure(VerifyErrorKind::OfferMismatch, "offer binding mismatch");
    }
    if claim.claimed_at_ms < verified_offer.offer.issued_at_ms
        || claim.claimed_at_ms >= verified_offer.offer.expires_at_ms
    {
        return failure(VerifyErrorKind::Expired, "claim outside offer window");
    }
    if claim.claimed_at_ms > now_ms_value {
        return failure(VerifyErrorKind::NotYetValid, "claim from future");
    }
    if claim.claimant.user_id == verified_offer.offer.issuer.user_id
        || claim.claimant.root_ed_pub_b64 == verified_offer.offer.issuer.root_ed_pub_b64
    {
        return failure(VerifyErrorKind::SelfClaim, "self claim");
    }

    let transcript = canonical_claim_unsigned(&claim)?;
    verify_ed25519(
        &claim.claimant.device_ed_pub_b64,
        &transcript,
        &claim.claimant_signature_b64,
    )?;
    let secret = decode_canonical_b64_fixed(
        &claim.capability_secret_b64,
        CAPABILITY_SECRET_BYTES,
        VerifyErrorKind::InvalidCapability,
    )?;
    let commitment = capability_commitment_hex(
        &verified_offer.offer.server_instance,
        &verified_offer.offer.offer_id,
        &secret,
    )?;
    if commitment != verified_offer.offer.capability_commitment_hex {
        return failure(VerifyErrorKind::InvalidCapability, "commitment mismatch");
    }
    verify_capability_proof(&claim, &secret)?;
    let claim_id_hex = claim_id_hex(&claim)?;
    Ok(VerifiedClaim {
        offer: verified_offer.offer,
        claim,
        offer_hash_hex: verified_offer.offer_hash_hex,
        claim_id_hex,
    })
}

pub(super) fn validate_offer_structure(offer: &MutualOnceOfferV2) -> VerifyResult<()> {
    if offer.v != CONTACT_PROTOCOL_V2 {
        return failure(VerifyErrorKind::UnsupportedVersion, "bad version");
    }
    if offer.mode != MUTUAL_ONCE_MODE_V2 {
        return failure(VerifyErrorKind::InvalidMode, "bad mode");
    }
    validate_server_instance(&offer.server_instance)?;
    decode_canonical_hex_fixed(&offer.offer_id, OFFER_ID_BYTES)?;
    validate_principal(&offer.issuer)?;
    if offer.issued_at_ms < 0 || offer.expires_at_ms <= offer.issued_at_ms {
        return failure(VerifyErrorKind::InvalidField, "bad offer time");
    }
    if offer.expires_at_ms - offer.issued_at_ms > MUTUAL_ONCE_MAX_TTL_MS {
        return failure(VerifyErrorKind::InvalidField, "offer ttl too long");
    }
    if offer.max_claims != 1 {
        return failure(VerifyErrorKind::ClaimsPolicy, "max_claims must be one");
    }
    decode_canonical_hex_fixed(&offer.capability_commitment_hex, HASH_BYTES)?;
    decode_canonical_b64_fixed(
        &offer.issuer_signature_b64,
        ED25519_SIGNATURE_BYTES,
        VerifyErrorKind::InvalidSignature,
    )?;
    Ok(())
}

pub(super) fn validate_claim_structure(claim: &MutualOnceClaimV2) -> VerifyResult<()> {
    if claim.v != CONTACT_PROTOCOL_V2 {
        return failure(VerifyErrorKind::UnsupportedVersion, "bad version");
    }
    if claim.mode != MUTUAL_ONCE_MODE_V2 {
        return failure(VerifyErrorKind::InvalidMode, "bad mode");
    }
    validate_server_instance(&claim.server_instance)?;
    decode_canonical_hex_fixed(&claim.offer_id, OFFER_ID_BYTES)?;
    decode_canonical_hex_fixed(&claim.offer_hash_hex, HASH_BYTES)?;
    validate_principal(&claim.claimant)?;
    if claim.claimant_list_rev == 0 {
        return failure(VerifyErrorKind::InvalidIdentity, "zero list rev");
    }
    decode_canonical_hex_fixed(&claim.nonce_hex, NONCE_BYTES)?;
    if claim.claimed_at_ms < 0 {
        return failure(VerifyErrorKind::InvalidField, "negative claim time");
    }
    if claim.grants.len() != 1 || claim.grants[0] != MUTUAL_CONTACT_GRANT_V2 {
        return failure(VerifyErrorKind::GrantRejected, "grant escalation");
    }
    decode_canonical_b64_fixed(
        &claim.capability_secret_b64,
        CAPABILITY_SECRET_BYTES,
        VerifyErrorKind::InvalidCapability,
    )?;
    decode_canonical_b64_fixed(
        &claim.claimant_signature_b64,
        ED25519_SIGNATURE_BYTES,
        VerifyErrorKind::InvalidSignature,
    )?;
    decode_canonical_b64_fixed(
        &claim.capability_proof_b64,
        HASH_BYTES,
        VerifyErrorKind::InvalidCapabilityProof,
    )?;
    Ok(())
}

pub(super) fn validate_server_instance(value: &str) -> VerifyResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return failure(VerifyErrorKind::InvalidField, "bad server instance");
    }
    Ok(())
}

pub(super) fn validate_principal(principal: &ContactPrincipalV2) -> VerifyResult<()> {
    if principal.user_id.is_empty()
        || principal.user_id.len() > 128
        || principal.user_id.trim() != principal.user_id
        || principal.user_id.chars().any(char::is_control)
    {
        return failure(VerifyErrorKind::InvalidIdentity, "bad user id");
    }
    let root_ed = decode_canonical_b64_fixed(
        &principal.root_ed_pub_b64,
        ED25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?;
    let root_x = decode_canonical_b64_fixed(
        &principal.root_x_pub_b64,
        X25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?;
    let device_ed = decode_canonical_b64_fixed(
        &principal.device_ed_pub_b64,
        ED25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?;
    let device_x = decode_canonical_b64_fixed(
        &principal.device_x_pub_b64,
        X25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?;
    if [&root_ed, &root_x, &device_ed, &device_x]
        .into_iter()
        .any(|key| key.iter().all(|b| *b == 0))
    {
        return failure(VerifyErrorKind::InvalidIdentity, "zero public key");
    }
    let device_id = hex::encode(&blake3::hash(&device_ed).as_bytes()[..8]);
    if principal.device_id != device_id {
        return failure(VerifyErrorKind::InvalidIdentity, "bad device id");
    }
    if (root_ed == device_ed) != (root_x == device_x) {
        return failure(VerifyErrorKind::InvalidIdentity, "partial primary identity");
    }
    Ok(())
}

pub(super) fn verify_ed25519(public_b64: &str, message: &[u8], signature_b64: &str) -> VerifyResult<()> {
    let public = decode_canonical_b64_fixed(
        public_b64,
        ED25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?;
    let public_array: [u8; ED25519_PUBLIC_BYTES] = public
        .as_slice()
        .try_into()
        .map_err(|_| verify_error(VerifyErrorKind::InvalidIdentity, "bad ed key"))?;
    let verifying = VerifyingKey::from_bytes(&public_array)
        .map_err(|_| verify_error(VerifyErrorKind::InvalidIdentity, "bad ed key"))?;
    let signature = decode_canonical_b64_fixed(
        signature_b64,
        ED25519_SIGNATURE_BYTES,
        VerifyErrorKind::InvalidSignature,
    )?;
    let signature_array: [u8; ED25519_SIGNATURE_BYTES] = signature
        .as_slice()
        .try_into()
        .map_err(|_| verify_error(VerifyErrorKind::InvalidSignature, "bad signature"))?;
    // verify_strict: the core uses vodozemac's `verify_strict`, so the worker's accept
    // set must not be WIDER than the core's — exotic signatures carrying a torsion or
    // small-order component are rejected on both sides ("the worker never verifies more
    // weakly than the core").
    verifying
        .verify_strict(message, &Signature::from_bytes(&signature_array))
        .map_err(|_| verify_error(VerifyErrorKind::InvalidSignature, "signature invalid"))
}

pub(super) fn capability_commitment_hex(
    server_instance: &str,
    offer_id_hex: &str,
    secret: &[u8],
) -> VerifyResult<String> {
    let offer_id = decode_canonical_hex_fixed(offer_id_hex, OFFER_ID_BYTES)?;
    let mut writer = CanonicalWriter::new(CAPABILITY_COMMITMENT_DOMAIN);
    writer.put_str(server_instance)?;
    writer.put_bytes(&offer_id)?;
    writer.put_bytes(secret)?;
    Ok(hex::encode(Sha256::digest(writer.finish())))
}

pub(super) fn offer_hash_hex(offer: &MutualOnceOfferV2) -> VerifyResult<String> {
    let mut writer = CanonicalWriter::new(OFFER_HASH_DOMAIN);
    writer.put_bytes(&canonical_offer_unsigned(offer)?)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &offer.issuer_signature_b64,
        ED25519_SIGNATURE_BYTES,
        VerifyErrorKind::InvalidSignature,
    )?)?;
    Ok(hex::encode(Sha256::digest(writer.finish())))
}

pub(super) fn verify_capability_proof(claim: &MutualOnceClaimV2, secret: &[u8]) -> VerifyResult<()> {
    let proof = decode_canonical_b64_fixed(
        &claim.capability_proof_b64,
        HASH_BYTES,
        VerifyErrorKind::InvalidCapabilityProof,
    )?;
    let mut input = CanonicalWriter::new(CAPABILITY_PROOF_DOMAIN);
    input.put_bytes(&canonical_claim_unsigned(claim)?)?;
    input.put_bytes(&decode_canonical_b64_fixed(
        &claim.claimant_signature_b64,
        ED25519_SIGNATURE_BYTES,
        VerifyErrorKind::InvalidSignature,
    )?)?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| verify_error(VerifyErrorKind::InvalidCapabilityProof, "bad hmac key"))?;
    mac.update(&input.finish());
    mac.verify_slice(&proof)
        .map_err(|_| verify_error(VerifyErrorKind::InvalidCapabilityProof, "hmac invalid"))
}

pub(super) fn claim_id_hex(claim: &MutualOnceClaimV2) -> VerifyResult<String> {
    let mut writer = CanonicalWriter::new(CLAIM_ID_DOMAIN);
    writer.put_bytes(&canonical_claim_unsigned(claim)?)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &claim.claimant_signature_b64,
        ED25519_SIGNATURE_BYTES,
        VerifyErrorKind::InvalidSignature,
    )?)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &claim.capability_proof_b64,
        HASH_BYTES,
        VerifyErrorKind::InvalidCapabilityProof,
    )?)?;
    Ok(hex::encode(Sha256::digest(writer.finish())))
}

pub(super) fn canonical_offer_unsigned(offer: &MutualOnceOfferV2) -> VerifyResult<Vec<u8>> {
    let mut writer = CanonicalWriter::new(OFFER_SIGNATURE_DOMAIN);
    writer.put_u32(offer.v);
    writer.put_str(&offer.mode)?;
    writer.put_str(&offer.server_instance)?;
    writer.put_bytes(&decode_canonical_hex_fixed(
        &offer.offer_id,
        OFFER_ID_BYTES,
    )?)?;
    put_principal(&mut writer, &offer.issuer)?;
    writer.put_i64(offer.issued_at_ms);
    writer.put_i64(offer.expires_at_ms);
    writer.put_u32(offer.max_claims);
    writer.put_bytes(&decode_canonical_hex_fixed(
        &offer.capability_commitment_hex,
        HASH_BYTES,
    )?)?;
    Ok(writer.finish())
}

pub(super) fn canonical_claim_unsigned(claim: &MutualOnceClaimV2) -> VerifyResult<Vec<u8>> {
    let mut writer = CanonicalWriter::new(CLAIM_SIGNATURE_DOMAIN);
    writer.put_u32(claim.v);
    writer.put_str(&claim.mode)?;
    writer.put_str(&claim.server_instance)?;
    writer.put_bytes(&decode_canonical_hex_fixed(
        &claim.offer_id,
        OFFER_ID_BYTES,
    )?)?;
    writer.put_bytes(&decode_canonical_hex_fixed(
        &claim.offer_hash_hex,
        HASH_BYTES,
    )?)?;
    put_principal(&mut writer, &claim.claimant)?;
    writer.put_u64(claim.claimant_list_rev);
    writer.put_bytes(&decode_canonical_hex_fixed(&claim.nonce_hex, NONCE_BYTES)?)?;
    writer.put_i64(claim.claimed_at_ms);
    writer.put_strings(&claim.grants)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &claim.capability_secret_b64,
        CAPABILITY_SECRET_BYTES,
        VerifyErrorKind::InvalidCapability,
    )?)?;
    Ok(writer.finish())
}

pub(super) fn put_principal(writer: &mut CanonicalWriter, principal: &ContactPrincipalV2) -> VerifyResult<()> {
    writer.put_str(&principal.user_id)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &principal.root_ed_pub_b64,
        ED25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &principal.root_x_pub_b64,
        X25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?)?;
    writer.put_str(&principal.device_id)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &principal.device_ed_pub_b64,
        ED25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?)?;
    writer.put_bytes(&decode_canonical_b64_fixed(
        &principal.device_x_pub_b64,
        X25519_PUBLIC_BYTES,
        VerifyErrorKind::InvalidIdentity,
    )?)?;
    Ok(())
}

pub(super) struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    pub(super) fn new(domain: &[u8]) -> Self {
        Self {
            bytes: domain.to_vec(),
        }
    }

    fn put_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn put_i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn put_str(&mut self, value: &str) -> VerifyResult<()> {
        self.put_bytes(value.as_bytes())
    }

    pub(super) fn put_bytes(&mut self, value: &[u8]) -> VerifyResult<()> {
        let len = u32::try_from(value.len())
            .map_err(|_| verify_error(VerifyErrorKind::InvalidField, "field too long"))?;
        self.put_u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn put_strings(&mut self, values: &[String]) -> VerifyResult<()> {
        let len = u32::try_from(values.len())
            .map_err(|_| verify_error(VerifyErrorKind::InvalidField, "list too long"))?;
        self.put_u32(len);
        for value in values {
            self.put_str(value)?;
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(super) fn decode_canonical_b64_fixed(
    value: &str,
    expected_len: usize,
    kind: VerifyErrorKind,
) -> VerifyResult<Vec<u8>> {
    let decoded = STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| verify_error(kind, "bad base64"))?;
    if decoded.len() != expected_len || STANDARD_NO_PAD.encode(&decoded) != value {
        return failure(kind, "non-canonical base64");
    }
    Ok(decoded)
}

pub(super) fn decode_canonical_hex_fixed(value: &str, expected_len: usize) -> VerifyResult<Vec<u8>> {
    let decoded =
        hex::decode(value).map_err(|_| verify_error(VerifyErrorKind::InvalidField, "bad hex"))?;
    if decoded.len() != expected_len || hex::encode(&decoded) != value {
        return failure(VerifyErrorKind::InvalidField, "non-canonical hex");
    }
    Ok(decoded)
}

pub(super) fn parse_json<T: DeserializeOwned>(json: &str) -> VerifyResult<T> {
    serde_json::from_str(json).map_err(|_| verify_error(VerifyErrorKind::Malformed, "bad json"))
}

pub(super) fn verify_error(kind: VerifyErrorKind, message: &'static str) -> VerifyError {
    VerifyError { kind, message }
}

pub(super) fn failure<T>(kind: VerifyErrorKind, message: &'static str) -> VerifyResult<T> {
    Err(verify_error(kind, message))
}
