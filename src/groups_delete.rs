//! `DELETE /groups/:id` — the whole teardown, as one ordered batch.
//!
//! Split out of `groups.rs` for size, and it earns its own file for the same reason
//! `groups_transfer.rs` does: the ORDER of the statements is the correctness argument, and an
//! argument that lives somewhere else gets "tidied" by the next reader.
//!
//! What the handler used to do was delete `group_members`, delete `groups`, and stop. The room's
//! `plugin_media_objects` / `plugin_code_objects` rows have no foreign key onto `groups`
//! (migrations 0026 and 0028 declare only `PRIMARY KEY(room_id, blob_id)`), so nothing cascaded
//! them: the metadata survived, the R2 blobs behind it were never queued for deletion, and
//! `usage::reconcile_storage` kept summing `plugin_media_objects.size_bytes` into the uploader's
//! quota. A deleted group therefore ate its uploader's storage allowance permanently, with no row
//! left anywhere that could ever release it. `plugin_epoch_floor` was left behind too.
//!
//! The SQL below is not new: it is `membership.rs`'s account-deletion shape and `admin/reset.rs`'s
//! wipe shape, re-scoped from "this uploader" / "everything" to "this room". The key strings stay
//! byte-identical to `storage::{plugin_media_key, plugin_code_key}` so the daily `retry_orphans`
//! pass can find the objects.

use crate::d1util::{d1_int, d1_text};
use worker::*;

/// Blobs → `storage_orphans`. Binds: now, room. `INSERT OR IGNORE` because the outbox is keyed
/// `(store_id, key)` and a retried delete must not multiply rows.
pub(super) const ORPHAN_PLUGIN_MEDIA_SQL: &str =
    "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
     SELECT store_id,'plugin-media/' || room_id || '/' || blob_id,size_bytes,?,0
       FROM plugin_media_objects WHERE room_id = ?";

/// The plugin-CODE channel, same shape. Binds: now, room. These blobs are deliberately outside the
/// quota counters (0028) but very much inside R2, so skipping them would leak storage while
/// leaving the quota arithmetic looking correct.
pub(super) const ORPHAN_PLUGIN_CODE_SQL: &str =
    "INSERT OR IGNORE INTO storage_orphans(store_id,key,size_bytes,created_at,retry_count)
     SELECT store_id,'plugin-code/' || room_id || '/' || blob_id,size_bytes,?,0
       FROM plugin_code_objects WHERE room_id = ?";

/// Tear a group down. The caller has already been checked to be the sitting owner.
///
/// ONE batch, and unlike the two sequential `.run()` calls this replaces, that is load-bearing in
/// three separate ways:
///
/// 1. **ORPHAN BEFORE DELETE, ATOMICALLY.** The orphan statements read the very rows the delete
///    statements remove, so the order is forced — `membership.rs:262-291` orphans before
///    `:370-379` drops the metadata, and that is not incidental. Getting it right *within one
///    request* is not enough on its own, though: run the two halves as separate transactions and a
///    failure in between leaves `storage_orphans` rows naming blobs whose metadata is still live,
///    and the daily `retry_orphans` pass then deletes a blob out from under a group that still
///    exists. Silent data loss in the opposite direction from the leak we are fixing. The implicit
///    transaction D1 wraps a batch in makes "queued and dropped" a single fact.
/// 2. **NO HALF-DELETED GROUP.** Previously `DELETE FROM group_members` and `DELETE FROM groups`
///    were two awaited round trips; a failure between them left a `groups` row whose membership had
///    already been erased — invisible to `list_my_groups`, and undeletable through this very
///    handler, which needs an owner row to authorise. `create_group` batches for exactly this
///    reason and says so.
/// 3. **SUBREQUESTS.** Seven statements as one batch is one subrequest instead of seven, which is
///    what buys the room for the post-commit live nudges (`groups_notify.rs`).
///
/// `plugin_epoch_floor` is DELETED, not bumped. The handler used to call
/// `plugin_log::bump_epoch_floor` best-effort afterwards and left the row behind forever. A bump
/// fences a member who left out of an epoch other members still write to; here nobody is left and
/// the room id — a v4 UUID — can never be handed out again, so there is no future append to fence.
/// `membership.rs:314` reaches the same conclusion from the other side, sweeping floors whose group
/// no longer exists; doing it in the same transaction just means the sweep has nothing to find.
pub(super) async fn delete_group_rows(db: &D1Database, group_id: &str, now: i64) -> Result<()> {
    db.batch(vec![
        db.prepare(ORPHAN_PLUGIN_MEDIA_SQL)
            .bind(&[d1_int(now), d1_text(group_id)])?,
        db.prepare(ORPHAN_PLUGIN_CODE_SQL)
            .bind(&[d1_int(now), d1_text(group_id)])?,
        // Only now that the outbox owns them may the authoritative inventory rows go. Dropping
        // `plugin_media_objects` is also what releases the uploader's quota: `usage.rs` derives
        // `user_storage` by summing this table, so the row IS the charge.
        db.prepare("DELETE FROM plugin_media_objects WHERE room_id = ?")
            .bind(&[d1_text(group_id)])?,
        db.prepare("DELETE FROM plugin_code_objects WHERE room_id = ?")
            .bind(&[d1_text(group_id)])?,
        // `group_members` also cascades off the `groups` FK; the explicit delete is
        // belt-and-braces, and inside a batch it costs nothing.
        db.prepare("DELETE FROM group_members WHERE group_id = ?")
            .bind(&[d1_text(group_id)])?,
        db.prepare("DELETE FROM groups WHERE id = ?")
            .bind(&[d1_text(group_id)])?,
        db.prepare("DELETE FROM plugin_epoch_floor WHERE room_id = ?")
            .bind(&[d1_text(group_id)])?,
    ])
    .await?;
    Ok(())
}
