-- 0044: JOIN REQUESTS — a person who came in through a class invite and is waiting for a group
-- admin to let them into the invite's landing group (campus plan Wave F; Hasan, round 4: "a class
-- invite keeps admin approval, and it applies only to people who came in through the class
-- invite").
--
-- A state of its own, in a table of its own, and NOT a third `group_members.status`. A
-- `group_members` row of any status is visible to every member (`GET /groups/:id/members`),
-- counted against the fan-out ceiling, and read by every client's consent path, where an unknown
-- status would be mistaken for an invitation to accept. A request is none of those: only the
-- group's admins see it, it carries no membership, and the requester sees only their own.
--
-- Approval writes the ordinary consent row (`status = 'pending'`, `added_by` = the approving admin)
-- and the requester's client accepts it on its own, so the room key reaches them through the same
-- `GroupJoinAccepted` path every invitee uses. Nothing about E2E membership changes here.
--
-- `state`: pending → approved | denied. Decided rows are kept 30 days so the requester's
-- `GET /join-requests/mine` can say what happened, then swept (`maintenance.rs`).
-- `invite_hash` is the class invite's token hash (the ledger's `source_hash`): the admin's invite
-- list counts a class's pending requests by it. `invite_label` is a snapshot of the invite's name
-- for the request row ("via BIL203 · 2026 fall") — the invite may be revoked or swept long before an
-- admin gets to the list.
--
-- Both foreign keys CASCADE: deleting the group (`groups_delete.rs`) or the account
-- (`membership.rs`) takes the request with it, and neither teardown needs a statement for it.
CREATE TABLE IF NOT EXISTS group_join_requests (
  group_id      TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invite_hash   TEXT,
  invite_label  TEXT,
  state         TEXT NOT NULL DEFAULT 'pending'
                  CHECK(state IN ('pending', 'approved', 'denied')),
  requested_at  INTEGER NOT NULL,
  decided_at    INTEGER,
  decided_by    TEXT,
  PRIMARY KEY (group_id, user_id)
);

-- The admin's list: a group's pending requests, newest first.
CREATE INDEX IF NOT EXISTS idx_join_requests_pending
  ON group_join_requests(group_id, requested_at, user_id) WHERE state = 'pending';
-- The requester's own view.
CREATE INDEX IF NOT EXISTS idx_join_requests_user ON group_join_requests(user_id);
-- The invite list's per-class pending count.
CREATE INDEX IF NOT EXISTS idx_join_requests_invite
  ON group_join_requests(invite_hash) WHERE state = 'pending';
