//! Helpers for Olm sessions and the PrekeyBundle.
//!
//! We use `vodozemac::olm::Session` directly — this module only carries the
//! peer's public identity + one-time-key bundle and collapses opening an
//! outbound/inbound session into a single call.

use serde::{Deserialize, Serialize};
use vodozemac::olm::{InboundCreationResult, PreKeyMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::identity::Identity;
use sezi_error::Result;

/// A peer's identity + one-time-key bundle, as fetched from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    /// The peer's Curve25519 (X25519) identity key, base64.
    pub identity_curve: String,
    /// The one-time key consumed from the server, base64.
    pub one_time_key: String,
}

impl PrekeyBundle {
    pub fn from_keys(identity: Curve25519PublicKey, otk: Curve25519PublicKey) -> Self {
        Self { identity_curve: identity.to_base64(), one_time_key: otk.to_base64() }
    }

    pub fn identity(&self) -> Result<Curve25519PublicKey> {
        Ok(Curve25519PublicKey::from_base64(&self.identity_curve)?)
    }

    pub fn otk(&self) -> Result<Curve25519PublicKey> {
        Ok(Curve25519PublicKey::from_base64(&self.one_time_key)?)
    }
}

/// Opens an outbound Olm session against the given bundle.
pub fn outbound(identity: &Identity, bundle: &PrekeyBundle) -> Result<Session> {
    let session = identity.account().create_outbound_session(
        SessionConfig::version_1(),
        bundle.identity()?,
        bundle.otk()?,
    )?;
    Ok(session)
}

/// Opens an inbound session from a PreKey message and decrypts the first plaintext.
pub fn inbound(
    identity: &mut Identity,
    peer_identity_curve: Curve25519PublicKey,
    pre_key: &PreKeyMessage,
) -> Result<InboundCreationResult> {
    let result = identity.account_mut().create_inbound_session(
        SessionConfig::version_1(),
        peer_identity_curve,
        pre_key,
    )?;
    Ok(result)
}
