-- 0019: FORWARD SECRECY — the per-room plugin server-log EPOCH FLOOR, enforced blind.
--
-- The floor RISES whenever a member is REMOVED from a group (kick / self-leave / server-level
-- delete). If a plugin server-log append carries `key_epoch < floor` the worker REJECTS it
-- with `409 epoch_stale` → server-side, this stops a removed member (or a writer left behind)
-- from writing new data under an OLD epoch and punching a hole in forward secrecy. The server
-- stays BLIND: it only compares an INTEGER and SEES neither the key nor the content.
--
-- room_id = group_id (groups.id; the plugin_log DO keys on the same id_from_name(room)). The
-- floor defaults to 0 (with no row, floor=0 is assumed → no constraint). The
-- membership-removal handlers bump it atomically with
-- `INSERT ... ON CONFLICT DO UPDATE floor=floor+1`. IF NOT EXISTS keeps it idempotent.

CREATE TABLE IF NOT EXISTS plugin_epoch_floor (
    room_id TEXT PRIMARY KEY,
    floor   INTEGER NOT NULL DEFAULT 0
);
