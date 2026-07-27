/// Evaluate only the positive direct-message authorization core.
///
/// Block direction and reporting intentionally stay with each caller because
/// message sending and contact-state introspection expose different views.
pub(crate) fn direct_message_allowed(dm_policy: &str, granted: bool, common_group: bool) -> bool {
    dm_policy == "members" || granted || common_group
}

/// Emit the canonical low/high SQL expressions for an unordered contact pair.
macro_rules! contact_pair_order_sql {
    ($left:literal, $right:literal) => {
        concat!(
            "CASE WHEN ",
            $left,
            " < ",
            $right,
            " THEN ",
            $left,
            " ELSE ",
            $right,
            " END, CASE WHEN ",
            $left,
            " < ",
            $right,
            " THEN ",
            $right,
            " ELSE ",
            $left,
            " END"
        )
    };
}
pub(crate) use contact_pair_order_sql;

/// Emit the symmetric active-block exclusion for a contact pair.
macro_rules! contact_pair_block_guard_sql {
    ($left:literal, $right:literal) => {
        concat!(
            "NOT EXISTS (SELECT 1 FROM contact_blocks b WHERE ",
            "(b.blocker_user_id = ",
            $left,
            " AND b.blocked_user_id = ",
            $right,
            ") OR ",
            "(b.blocker_user_id = ",
            $right,
            " AND b.blocked_user_id = ",
            $left,
            "))"
        )
    };
}
pub(crate) use contact_pair_block_guard_sql;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_message_allowed_matches_both_paths() {
        for dm_policy in ["members", "requests", "contacts_only"] {
            for granted in [false, true] {
                for common_group in [false, true] {
                    let send_path = dm_policy == "members" || granted || common_group;
                    let state_path = dm_policy == "members" || granted || common_group;
                    let actual = direct_message_allowed(dm_policy, granted, common_group);

                    assert_eq!(actual, send_path);
                    assert_eq!(actual, state_path);
                }
            }
        }

        // Blocking deliberately remains outside this positive-authorization
        // helper: send denies early on either direction, while contact state
        // combines it only with the outbound `blocked_by_me` flag.
    }

    #[test]
    fn grant_convergence_sqls_share_pair_order_and_block_guard() {
        let cases = [
            (
                "request",
                crate::contacts::APPLY_ACCEPTED_GRANT_SQL,
                contact_pair_order_sql!("r.source_user_id", "r.target_user_id"),
                contact_pair_block_guard_sql!("r.source_user_id", "r.target_user_id"),
            ),
            (
                "qr",
                crate::contact_qr::UPSERT_QR_GRANT_SQL,
                contact_pair_order_sql!("o.issuer_user_id", "c.claimant_user_id"),
                contact_pair_block_guard_sql!("o.issuer_user_id", "c.claimant_user_id"),
            ),
            (
                "invite",
                crate::auth::invite_attribution::APPLY_INVITE_GRANT_SQL,
                contact_pair_order_sql!("ia.inviter_user_id", "ia.used_by"),
                contact_pair_block_guard_sql!("ia.inviter_user_id", "ia.used_by"),
            ),
        ];

        for (source, sql, pair_order, block_guard) in cases {
            assert!(sql.contains(pair_order), "{source} pair ordering drifted");
            assert!(sql.contains(block_guard), "{source} block guard drifted");
        }
    }
}
