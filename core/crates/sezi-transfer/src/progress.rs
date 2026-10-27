//! Byte-progress reporting, from a transport to the kernel.

#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Mutex, OnceLock};

#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::mpsc;

/// What a transport byte loop is doing.
///
/// Deliberately NOT the attachment's persisted phase. That one has seventeen variants (see
/// [`crate::phase::AttachmentPhase`], in this crate — `core/src/attach_progress.rs` only
/// re-exports it for the bridge) and covers states no byte loop can ever observe: a user consent
/// wait, a migration leftover, a terminal outcome. A transport only ever encrypts, decrypts,
/// uploads or downloads, and these four are all any of them has ever passed. Widening this to
/// mirror the phase would hand every transport thirteen variants it must never emit.
///
/// Mapping the four onto the seventeen is `impl From<TransferStep> for AttachmentPhase` in
/// `phase.rs`, and the compiler checks that mapping is total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStep {
    Encrypting,
    Decrypting,
    Uploading,
    Downloading,
}

/// A transport progress event, handed to the kernel (see [`set_kernel_sink`]).
///
/// `bytes_total == 0` means indeterminate progress; the UI renders that as a spinner.
/// `bytes_done == bytes_total && bytes_total > 0` signals completion — it may be the same event as
/// the terminal phase.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// The `uuid.v4()` minted by the send/download call that started this transfer. The attachment
    /// row is looked up by this key, and its transferred-bytes/phase are updated from the event.
    pub key: String,
    pub step: TransferStep,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

// --- Kernel bridge (NATIVE-only: tokio mpsc) ---
//
// ONE consumer, deliberately: progress reaches Dart as a kernel `DomainEvent`, never over a
// second `StreamSink` straight from here.

/// The sole consumer of transport byte/step progress. At boot the kernel installs an
/// `UnboundedSender` here; [`emit`] sends every event → the kernel updates the attachment row's
/// `progress_bytes`/phase and emits a `DomainEvent` (which Dart listens to).
#[cfg(not(target_arch = "wasm32"))]
static KERNEL_SINK: OnceLock<Mutex<Option<mpsc::UnboundedSender<TransferProgress>>>> =
    OnceLock::new();

#[cfg(not(target_arch = "wasm32"))]
fn kernel_sink() -> &'static Mutex<Option<mpsc::UnboundedSender<TransferProgress>>> {
    KERNEL_SINK.get_or_init(|| Mutex::new(None))
}

/// Called once at kernel boot to bridge progress events into the kernel. Idempotent (a re-set
/// overwrites). If the receiver side closes, [`emit`] swallows the send error.
#[cfg(not(target_arch = "wasm32"))]
pub fn set_kernel_sink(tx: mpsc::UnboundedSender<TransferProgress>) {
    *kernel_sink().lock().unwrap() = Some(tx);
}

/// Internal emit — transport sites hand their events off here. With no kernel bridge installed yet
/// (pre-boot) the event is silently dropped; if the receiver has closed, the slot is cleared.
#[cfg(not(target_arch = "wasm32"))]
pub fn emit(event: TransferProgress) {
    let mut guard = kernel_sink().lock().unwrap();
    let closed = if let Some(tx) = guard.as_ref() {
        tx.send(event).is_err()
    } else {
        false
    };
    if closed {
        *guard = None;
    }
}

/// On wasm there is no kernel progress sink yet, so the event is dropped. The signature stays
/// because the `sezi-file` crypto island calls [`emit_bytes`]; only the body is a no-op.
#[cfg(target_arch = "wasm32")]
pub fn emit(_event: TransferProgress) {}

/// Determinate progress (the uploading/downloading chunk counter).
pub fn emit_bytes(key: &str, step: TransferStep, bytes_done: u64, bytes_total: u64) {
    emit(TransferProgress {
        key: key.to_string(),
        step,
        bytes_done,
        bytes_total,
    });
}
