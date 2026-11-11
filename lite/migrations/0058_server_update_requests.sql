-- 0058: SERVER UPDATE REQUESTS — the owner's one-tap update of a self-hosted (bare workerd) relay
-- (docs/SERVER_UPDATE_PLAN.md §4.2, rollout step 8).
--
-- The relay runs inside workerd's sandbox and can start nothing on its box, so the box asks: its
-- update timer (deploy/sezi-update-poll.sh, as root, every 2 min) calls
-- `GET /internal/update-request` on loopback with the updater token, takes the newest request
-- here, runs deploy/update.sh --to <build> — which installs only a build the signed release
-- channel names — and reports with `POST /internal/update-result`. The owner's app writes a row
-- with `POST /admin/server-update` and reads the latest with `GET /admin/server-update`.
-- A nightly automatic update (an owner's opt-in) is reported as a row of its own, `automatic` = 1.
--
-- Expand-only: a new table, read by nothing older. The two small settings — when the box last
-- called in, and the nightly switch — are `server_config` keys (`server_update.rs`).
CREATE TABLE IF NOT EXISTS server_update_requests (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  to_build     INTEGER NOT NULL,            -- yyyyMMddHHmm, the build asked for
  requested_by TEXT NOT NULL,               -- the owner's user id, or 'updater' for a nightly run
  requested_at INTEGER NOT NULL,            -- ms
  picked_at    INTEGER,                     -- ms the box's updater took it
  done_at      INTEGER,                     -- ms it ended (a result, superseded or expired)
  ok           INTEGER,                     -- 1 / 0, NULL until it ended
  code         TEXT,                        -- update.sh's result code (`ok`, `unhealthy-rolled-back` …)
  from_build   INTEGER,                     -- what the box ran before
  automatic    INTEGER NOT NULL DEFAULT 0   -- 1 = the nightly run, nobody asked
);
CREATE INDEX IF NOT EXISTS idx_server_update_requests_open ON server_update_requests (done_at, id);
