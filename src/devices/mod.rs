//! Multi-device addressing (M1) — store and distribute the signed device list.
//!
//! `PUT /devices/list`        — upload the primary-signed list (upsert on increasing rev).
//! `GET /devices/list/:user`  — fetch a user's current signed list.
//!
//! Zero-trust: the server VERIFIES the list but can never mint one. The signature is checked
//! over the exact incoming bytes of doc_json (the JWS model — NO re-serialization), using the
//! primary's Ed25519 key taken from the doc itself, which is in turn bound to the registered
//! identity through the stored SPK signature. Note that `users.identity_pubkey` is a
//! Curve25519/DH key and therefore cannot verify Ed25519 signatures — see `handlers.rs` for
//! the full binding chain. The real guarantee lives on the client; the checks here are
//! defence-in-depth and consistency.

pub mod handlers;
pub mod link;
