//! Olm identity and 1:1 session primitives.

pub mod identity;
pub mod kdf;
pub mod megolm;
pub mod messaging;
pub mod session;
/// Both ends opening a session at the same instant — the failure a call makes certain.
#[cfg(test)]
mod session_collision_tests;
/// A 1:1 message's `ext` (caption, album, voice data, forwarded) crossing Olm whole.
#[cfg(test)]
mod payload_ext_tests;
