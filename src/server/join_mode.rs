//! Join mode — a server has exactly one: invite-only.
//!
//! Sezi is outward-closed (AGENTS.md, first line), and `join_mode = "open"` never worked in a way
//! anyone could use: an open-mode redeem in production answered 204 and "mailed" the code to the
//! client's synthetic `@sezgi.local` address through a console log, the kernel then failed with
//! `register/verification-code-missing`, and no client has a control for it. All the mode did was
//! let an owner who set it through the API break every join — and, with the old
//! first-registration-owns-the-server rule, hand a fresh server to whoever registered first.
//!
//! So the settings handler refuses it, and nothing reads the stored column any more: a server that
//! already stored `open` behaves as invite-only, advertises `invite_only`, and has the value
//! overwritten by the owner's next settings save. No migration — a stored `open` is inert, and the
//! column's default was always `invite_only`.

/// The one join mode. Advertised by `/server/info`, echoed by the settings handler and by redeem.
pub(crate) const JOIN_MODE: &str = "invite_only";

/// The wire code for a settings request that asks for open mode. A 400 like any invalid value,
/// but typed, because it is a deliberate refusal of a value the API used to accept — not a typo.
pub(crate) const OPEN_MODE_REFUSED: &str = "join_mode_open_unsupported";

/// Validate a `join_mode` an owner asked for: `Ok` for invite-only, otherwise the error code.
pub(crate) fn check_requested(requested: &str) -> Result<(), &'static str> {
    match requested {
        JOIN_MODE => Ok(()),
        "open" => Err(OPEN_MODE_REFUSED),
        _ => Err("bad_request"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_invite_only_is_accepted_and_open_is_refused_by_name() {
        assert_eq!(check_requested("invite_only"), Ok(()));
        assert_eq!(check_requested("open"), Err(OPEN_MODE_REFUSED));
        for junk in ["", "OPEN", "invite-only", "closed"] {
            assert_eq!(check_requested(junk), Err("bad_request"), "{junk:?}");
        }
    }

    /// A stored `open` must change nothing, which holds only while no handler reads the column.
    /// Each of these used to: redeem branched on it, `/server/info` echoed it, and the settings
    /// handler wrote it back on every save.
    #[test]
    fn no_handler_reads_the_stored_join_mode() {
        for (name, src) in [
            ("auth/invite.rs", include_str!("../auth/invite.rs")),
            ("server/handlers.rs", include_str!("handlers.rs")),
            ("admin/handlers.rs", include_str!("../admin/handlers.rs")),
        ] {
            for line in src.lines().filter(|l| l.contains("SELECT")) {
                assert!(
                    !line.contains("join_mode"),
                    "{name} reads server_settings.join_mode again: {line}"
                );
            }
        }
    }
}
