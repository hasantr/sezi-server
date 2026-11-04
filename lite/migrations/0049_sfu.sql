-- Group calls through Cloudflare Realtime SFU (F3, docs/F3_GROUP_SFU.md).
--
-- sfu_usage: the month's SFU egress as the members report it (what each received), and whether
-- the owner was already told about 80 % and 100 % of the cap this month.
CREATE TABLE IF NOT EXISTS sfu_usage (
    month        TEXT PRIMARY KEY,           -- "YYYY-MM", UTC (turn::current_month_utc)
    egress_bytes INTEGER NOT NULL DEFAULT 0,
    warned_80    INTEGER NOT NULL DEFAULT 0,
    warned_100   INTEGER NOT NULL DEFAULT 0
);

-- The same split by group, for "which group spent what" in the owner's use screen.
CREATE TABLE IF NOT EXISTS sfu_room_usage (
    month        TEXT NOT NULL,
    room_id      TEXT NOT NULL,
    egress_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (month, room_id)
);

-- Every SFU session this relay opened, so a later track call is allowed only to the member who
-- owns the session, and a pull only of tracks published in the SAME room and call. Pruned after
-- a day (a call longer than that re-opens nothing: its session simply keeps working at CF, and
-- only new track calls on it would be refused).
CREATE TABLE IF NOT EXISTS sfu_sessions (
    session_id TEXT PRIMARY KEY,
    room_id    TEXT NOT NULL,
    call_id    TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    -- When this session last reported its received bytes; a report is clamped to what the
    -- elapsed time could carry, so a client cannot inflate (or a bug multiply) the month.
    last_report_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sfu_sessions_created ON sfu_sessions(created_at);
