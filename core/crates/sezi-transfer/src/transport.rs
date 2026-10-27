//! Which transport carries a connection or a transfer.

use serde::{Deserialize, Serialize};

/// Connection transport kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// HTTP/HTTPS request — auth, message POST, media upload/download
    Http,
    /// WebSocket /sync stream
    WebSocket,
    /// iroh QUIC, LAN only — P2P blob transfer
    IrohQuic,
}

impl TransportKind {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            TransportKind::Http => "http",
            TransportKind::WebSocket => "ws",
            TransportKind::IrohQuic => "iroh",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Self::Http),
            "ws" => Some(Self::WebSocket),
            "iroh" => Some(Self::IrohQuic),
            "any" => Some(Self::Http), // 'any' defaults to Http; the dispatcher applies the real rule
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Peer link state
// ---------------------------------------------------------------------------
// These two describe an `IrohQuic` link and are computed by `sezi-p2p` — but they are DECLARED
// here, once, because `sezi-p2p` is optional and cannot build for the browser while
// `frb_generated.rs` writes their path UNCONDITIONALLY (codegen emits no cfg). A second copy
// behind a `#[cfg]` is the trap being avoided: a `#[frb(mirror)]` whose copies drift panics at the
// FFI boundary rather than failing the build.
//
// This crate is the seam that works — platform-free, and a non-optional dependency of both the
// root crate and `sezi-p2p`, which re-exports these so every existing path still resolves. Pure
// data: no iroh type appears in either declaration.

/// Peer link kind — answers the user's question "how are we talking right now?". `None` means
/// the peer is currently unreachable or no connection was ever established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLinkKind {
    /// The active IP address is RFC 1918 / link-local / IPv6 ULA — same local network.
    Lan,
    /// The active IP address is public — a hole-punched direct path over the Internet.
    DirectInternet,
    /// Only the relay path is active — no direct path has opened yet.
    Relay,
    /// Both direct and relay are active (a transition moment or a stable mixed state).
    Mixed,
    /// remote_info returned Some but no address is Active; or the peer was never seen.
    None,
}

/// Peer link snapshot — enough information for the UI badge and bottom sheet. Every address
/// field is optional; in a Relay-only state, for example, lan_addr and public_addr are None.
#[derive(Debug, Clone)]
pub struct PeerLinkInfo {
    pub kind: PeerLinkKind,
    /// Active LAN IP+port (RFC1918/ULA/link-local), e.g. "192.168.1.42:55600".
    pub lan_addr: Option<String>,
    /// Active public IP+port (hole-punched).
    pub public_addr: Option<String>,
    /// Active relay URL.
    pub relay_url: Option<String>,
}
