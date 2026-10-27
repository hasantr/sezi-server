//! Attachment transfer plumbing — byte progress and in-flight cancellation.
//!
//! This crate exists to break one edge. The transports — file crypto (`sezi-file`), HTTP
//! upload/download (`net/`), iroh blob transfer (`p2p/`) — all report progress and honour
//! cancellation, and they did it by calling UP into `crate::attach_progress`: a module on the FFI
//! surface, named in `flutter_rust_bridge.yaml`. A transport crate cannot depend on the bridge, so
//! that single call pinned all three to the root crate.
//!
//! The split follows what each side actually owns. The bridge keeps the `#[frb(mirror)]`
//! declaration for the attachment phase Dart renders and the `attachment_cancel` FFI function;
//! the phase type itself moved here, into `phase.rs`. What else moved here is the machinery,
//! plus the four steps a byte loop can genuinely be in — see [`progress::TransferStep`], which is
//! deliberately NOT a copy of the phase.
//!
//! Two process-wide registries live here, both `OnceLock<Mutex<…>>`: the kernel progress sink and
//! the in-flight cancellation map. Globals because the transports run on arbitrary tasks with no
//! handle to thread through — that was true before the move, and the move did not change it.

/// In-flight cancellation registry.
///
/// Was native-only until 2026-08-24, "exactly as it was in the root crate" — and the browser is
/// where cancelling matters most, because that is the target whose user may be paying per byte.
/// A `CancellationToken` is a mutex and an atomic; nothing in it needs a socket or a thread, and
/// the tokio features the workspace floor already ships to wasm carry it.
pub mod inflight;
/// The attachment phase, its DB spelling and the monotonic transition guard. Platform-free.
pub mod phase;
pub mod progress;
/// Which transport carries a connection. Platform-free.
pub mod transport;
