//! What the invite page may say about an invite, and the one statement that reads it.
//!
//! **The view is an allow-list.** [`InviteView`] is the WHOLE of what either answer carries, and it
//! has no field for the token, the code, the token or code hash, the minter's or anyone's account
//! id, the redemption count of a personal invite, or a member of any group. Adding one is a change
//! to this struct and to the key-set test beside it, never a side effect of a wider `SELECT`.
//!
//! **One statement, one row, whatever the code.** [`DESCRIBE_BY_CODE_SQL`] starts from a constant
//! one-row base and LEFT JOINs the invite onto it, so an unknown code, a spent one, an expired one
//! and a live one all run the same statement and get one row back of the same shape. Which of them
//! it was is decided afterwards, in Rust, by [`describe`] — and every way of being unusable comes
//! out as the same `None`.

use serde::{Deserialize, Serialize};
use worker::*;

use crate::d1util::{d1_int, d1_text};

/// The body of both statements; only the column the invite is found by differs. Binds: `?1` the
/// lookup key, `?2` now.
///
/// `taken` is a class invite's seats as redeem would count them: when the invite LOOKS full, the
/// same recount `class_invite::RELEASE_SEATS_SQL` writes (verified redemptions plus codes still
/// live), read here without writing it — a student who scanned and walked away must not make the
/// page say "full" to the next one, who redeem would let in.
macro_rules! describe_sql {
    ($match:literal) => {
        concat!(
            "SELECT s.name AS server_name,
                    it.kind AS kind,
                    it.email_hint AS label,
                    it.used AS used,
                    it.expires_at AS expires_at,
                    it.revoked_at AS revoked_at,
                    it.max_uses AS max_uses,
                    CASE WHEN it.kind = 'class' AND it.uses >= it.max_uses THEN (
                      SELECT COUNT(*) FROM invite_attributions ia
                       WHERE ia.source_hash = it.token_hash
                         AND (ia.verified_at IS NOT NULL OR EXISTS (
                               SELECT 1 FROM verification_codes vc
                                WHERE vc.invite_token_hash = ia.invite_token_hash
                                  AND vc.expires_at > ?2)))
                    ELSE it.uses END AS taken,
                    (it.owner_user_id IS NOT NULL) AS has_minter,
                    u.display_name AS inviter_name,
                    g.name AS landing_group,
                    it.landing_needs_approval AS needs_approval
               FROM (SELECT 1 AS one) base
               LEFT JOIN server_settings s ON s.id = 1
               LEFT JOIN invite_tokens it ON ",
            $match,
            "
               LEFT JOIN users u ON u.id = it.owner_user_id
               LEFT JOIN groups g ON g.id = it.landing_room_id"
        )
    };
}

/// By the code's lookup hash (`invite_code::code_hash`), the index redeem uses.
pub(crate) const DESCRIBE_BY_CODE_SQL: &str = describe_sql!("it.code_hash = ?1");
/// By the raw bearer token — the app's personal-invite envelope carries no code.
pub(crate) const DESCRIBE_BY_TOKEN_SQL: &str = describe_sql!("it.token = ?1");

/// The row [`DESCRIBE_BY_CODE_SQL`] returns. Every invite column is `None` when nothing matched.
#[derive(Debug, Default, Clone, Deserialize)]
pub(crate) struct DescribeRow {
    pub(crate) server_name: Option<String>,
    pub(crate) kind: Option<String>,
    pub(crate) label: Option<String>,
    pub(crate) used: Option<i64>,
    pub(crate) expires_at: Option<i64>,
    pub(crate) revoked_at: Option<i64>,
    pub(crate) max_uses: Option<i64>,
    pub(crate) taken: Option<i64>,
    pub(crate) has_minter: Option<i64>,
    pub(crate) inviter_name: Option<String>,
    pub(crate) landing_group: Option<String>,
    pub(crate) needs_approval: Option<i64>,
}

/// What an invite is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum InviteKind {
    /// One person, one seat; may introduce the joiner to the inviter.
    Personal,
    /// Many seats, a name, possibly a landing group that needs approval (campus plan Wave F).
    Class,
}

/// Everything the page and the JSON answer say about a usable invite — and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct InviteView {
    pub(crate) kind: InviteKind,
    /// The name the server advertises — the same public value as `/server/info`.
    pub(crate) server_name: String,
    /// A personal invite's minter, by display name when they set one. Never a class invite's:
    /// it introduces nobody, and its code is read off a wall by people the minter has not met.
    pub(crate) inviter_name: Option<String>,
    /// A class invite's name ("BIL203 · 2026 fall"). A personal invite's label is the admin's own
    /// note about whom it is for, so it is never shown to the person holding the code.
    pub(crate) label: Option<String>,
    /// The group a joiner also goes into, when it still exists.
    pub(crate) landing_group: Option<String>,
    /// A group admin approves that landing first (class invites only).
    pub(crate) landing_needs_approval: bool,
    /// Seats a class invite still has; `None` for a personal invite.
    pub(crate) seats_left: Option<i64>,
    /// Unix seconds.
    pub(crate) expires_at: i64,
}

/// The server name a server that never set one shows (`server::handlers::info`'s fallback).
const DEFAULT_SERVER_NAME: &str = "Sezi";

/// Is this invite usable right now, and if so what may be said about it? `None` for a code that
/// matched nothing, an invite that is spent, expired, revoked or full, and the founding invite —
/// all alike, so the answer never tells a guesser which of them it hit.
///
/// The founding (genesis) invite is never described: it has no minter, it is public anyway while
/// the server has no owner, and after that it is spent — so there is nothing to say and no reason
/// to make it a second kind of answer.
pub(crate) fn describe(row: &DescribeRow, now: i64) -> Option<InviteView> {
    let kind = match row.kind.as_deref()? {
        "personal" => InviteKind::Personal,
        "class" => InviteKind::Class,
        _ => return None,
    };
    if row.has_minter.unwrap_or(0) == 0 || row.revoked_at.is_some() {
        return None;
    }
    let expires_at = row.expires_at?;
    if expires_at <= now {
        return None;
    }
    let seats_left = match kind {
        InviteKind::Personal => {
            if row.used.unwrap_or(1) != 0 {
                return None;
            }
            None
        }
        InviteKind::Class => {
            let left = row.max_uses? - row.taken.unwrap_or(0);
            if left <= 0 {
                return None;
            }
            Some(left)
        }
    };
    let text = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Some(InviteView {
        kind,
        server_name: text(&row.server_name).unwrap_or_else(|| DEFAULT_SERVER_NAME.into()),
        inviter_name: match kind {
            InviteKind::Personal => text(&row.inviter_name),
            InviteKind::Class => None,
        },
        label: match kind {
            InviteKind::Class => text(&row.label),
            InviteKind::Personal => None,
        },
        landing_group: text(&row.landing_group),
        landing_needs_approval: kind == InviteKind::Class
            && row.needs_approval.unwrap_or(0) != 0
            && text(&row.landing_group).is_some(),
        seats_left,
        expires_at,
    })
}

/// What the request named the invite by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LookupKey {
    /// A typed code in canonical form (`K7QM4827`).
    Code(String),
    /// A raw bearer token — accepted only from the app (JSON), see [`LookupKey::parse`].
    Token(String),
}

/// A bearer token's length: `random_b64u(18)` in `admin::invites`.
const TOKEN_LEN: usize = 24;

impl LookupKey {
    /// What to look up, or `None` for text that names no invite (answered without a lookup, and
    /// costing nothing).
    ///
    /// A CODE is anything `invite_code::normalize` accepts — the projector URL's own grammar. A
    /// TOKEN (24 base64url characters) is accepted only when `allow_token`, which is only ever the
    /// app's `POST /invites/describe` BODY: a bearer token never travels in a URL, where access
    /// logs, proxies and error messages keep it. A path segment is a code or nothing.
    pub(crate) fn parse(text: &str, allow_token: bool) -> Option<LookupKey> {
        if let Some(code) = crate::auth::invite_code::normalize(text) {
            return Some(LookupKey::Code(code));
        }
        let token_like = text.len() == TOKEN_LEN
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        (allow_token && token_like).then(|| LookupKey::Token(text.to_string()))
    }
}

/// Run the one statement for `key`.
pub(crate) async fn lookup(db: &D1Database, key: &LookupKey, now: i64) -> Result<DescribeRow> {
    let (sql, bound) = match key {
        LookupKey::Code(code) => (
            DESCRIBE_BY_CODE_SQL,
            crate::auth::invite_code::code_hash(code),
        ),
        LookupKey::Token(token) => (DESCRIBE_BY_TOKEN_SQL, token.clone()),
    };
    let row: Option<DescribeRow> = db
        .prepare(sql)
        .bind(&[d1_text(&bound), d1_int(now)])?
        .first(None)
        .await?;
    Ok(row.unwrap_or_default())
}
