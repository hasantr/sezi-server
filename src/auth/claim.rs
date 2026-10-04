//! The optional claim secret: who may take an unowned server.
//!
//! Until someone claims it, a fresh server hands its genesis invite to any visitor — through
//! `GET /bootstrap` and printed on the welcome page. On Cloudflare that window is the internet's
//! and lasts minutes; a relay the desktop app installs on a PC binds the LAN, so anyone on the
//! same Wi-Fi could claim it before its owner did.
//!
//! When the worker has `SEZI_CLAIM_SECRET`, the genesis invite is handed out only to a request
//! that carries the same value in the `x-sezi-claim` header, and the welcome page stops printing
//! it. The installer generates the secret and keeps it, so the machine that installed the relay
//! is the one that can claim it. Unset, nothing changes: the Cloudflare one-click deploy has no way
//! to receive a secret, and keeps today's window.
//!
//! Contract with the app (stable wire names):
//!  * the worker reads `SEZI_CLAIM_SECRET` — a `wrangler secret`, or a `.dev.vars` line for a
//!    `wrangler dev` relay;
//!  * the claimant sends it as the `x-sezi-claim` header on `GET /bootstrap` AND on
//!    `POST /auth/redeem` (a genesis invite minted before the secret existed claims nothing
//!    without it — `invite_attribution::CLAIM_INVITE_SQL`);
//!  * `/server/info` and `/capabilities` carry `claim_secret_required: bool`, so another device
//!    can tell the user to claim from the installing machine instead of failing mysteriously.
//!
//! A missing or wrong header gets the closed gate's answer, `410 bootstrap_complete`, byte for
//! byte — the same refusal the ghost-owner recovery gives. A wrong guess must not be told apart
//! from a missing one, and the existence of the secret is already advertised where it is
//! needed (`claim_secret_required`), so a distinct error would only add an oracle.

use worker::{Env, Request};

/// The worker binding that holds the claim secret.
pub(crate) const CLAIM_SECRET_BINDING: &str = "SEZI_CLAIM_SECRET";

/// The request header that carries it. A header, not a query parameter, so the secret stays out
/// of access logs and browser history — the same reasoning as `x-sezgi-admin-key`.
pub(crate) const CLAIM_HEADER: &str = "x-sezi-claim";

/// The configured claim secret, or `None` when there is none.
///
/// `secret` and `var` are the same lookup in this workers-rs (both read `env[name]` as a string),
/// so this one call covers a `wrangler secret`, a `[vars]` entry and a `.dev.vars` line alike. An
/// empty or blank value counts as unset: the button-deploy runtime hands back `Ok("")` for a
/// secret that was never set (see `self_provision::ensure_one_key`), and an empty secret must not
/// become a gate that an empty header opens.
pub(crate) fn configured_secret(env: &Env) -> Option<String> {
    env.secret(CLAIM_SECRET_BINDING)
        .ok()
        .map(|s| s.to_string().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Does this server require the claim secret? What `claim_secret_required` advertises.
pub(crate) fn claim_secret_required(env: &Env) -> bool {
    configured_secret(env).is_some()
}

/// May this request be handed the genesis invite?
pub(crate) fn claim_authorized(req: &Request, env: &Env) -> bool {
    let submitted = req.headers().get(CLAIM_HEADER).ok().flatten();
    claim_permitted(configured_secret(env).as_deref(), submitted.as_deref())
}

/// The decision itself, pure so it is tested: no secret configured → anyone (today's behaviour);
/// a secret configured → only a header that matches it, compared in constant time.
fn claim_permitted(expected: Option<&str>, submitted: Option<&str>) -> bool {
    match expected {
        None => true,
        Some(expected) => {
            submitted.is_some_and(|s| crate::auth::hashing::secret_eq(s.trim(), expected))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::claim_permitted;

    #[test]
    fn without_a_secret_the_claim_window_is_unchanged() {
        assert!(claim_permitted(None, None));
        assert!(claim_permitted(None, Some("anything")));
    }

    #[test]
    fn with_a_secret_only_the_matching_header_may_claim() {
        let secret = Some("s3cr3t-from-the-installer");
        assert!(claim_permitted(secret, Some("s3cr3t-from-the-installer")));
        assert!(!claim_permitted(secret, None), "a missing header");
        assert!(!claim_permitted(secret, Some("")), "an empty header");
        assert!(!claim_permitted(secret, Some("s3cr3t-from-the-installe")), "a prefix");
        assert!(!claim_permitted(secret, Some("S3CR3T-FROM-THE-INSTALLER")), "another case");
    }
}
