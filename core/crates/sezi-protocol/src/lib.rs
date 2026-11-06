//! The Sezi wire format.

pub mod activity_batch;
pub mod bots;
pub mod client_level;
pub mod devices;
pub mod edit;
pub mod envelope;
pub mod history_page;
pub mod indirect;
pub mod inner;
pub mod link_card;
/// What a new device signs while it polls `link-status` (CRY-1: tagged, never the raw code).
pub mod link_proof;
pub mod media_id;
pub mod media_meta;
pub mod mentions;
/// The framed payload: deflated when it pays, padded to a bucket (`kernel/olm_frame.rs`).
pub mod payload_frame;
pub mod reaction;
pub mod reply;
pub mod sticker;
pub mod takeover;
pub mod plugin_log;
