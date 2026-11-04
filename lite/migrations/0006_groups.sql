-- Sezgi: the group-chat substrate (membership).
--
-- groups          : a group/room inside the server (the creator = the group owner).
-- group_members   : group SUB-membership — SEPARATE from SERVER membership (users).
--                   The in-group role (owner/admin/member) is independent of the server role.
--
-- E2E: the server never sees group CONTENT (the envelope is opaque); it only holds membership
-- and fans a message out to the members' DO inboxes. Content crypto is Megolm (client-side).
-- A single-server install → there is NO server_id column (as with users).

CREATE TABLE IF NOT EXISTS groups (
    id          TEXT PRIMARY KEY,                    -- UUID v4
    name        TEXT NOT NULL,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id),
    role        TEXT NOT NULL DEFAULT 'member',      -- 'owner' | 'admin' | 'member'
    joined_at   INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

-- For the "groups I am a member of" query (list_my_groups).
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
