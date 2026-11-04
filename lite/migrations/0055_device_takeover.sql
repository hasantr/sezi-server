-- Edited in place (release_at, released_at) before its first deploy: no relay ever ran an earlier
-- form of it (ZH runs the template synced at 7ab3cbdf, which predates it).
--
-- 0055: THE ESCROWED ROOT — a linked device taking over a lost primary, opened only with a server
-- admin (docs/PRIMARY_DEVICE_LOSS_PLAN.md §3-§4).
--
-- `device_escrow`: the relay's share of each linked device's escrow copy. The primary seals its Olm
-- account under a random secret R and sends that copy to the linked device over self-Olm, which
-- the relay carries and cannot read; R itself is uploaded here (`PUT /devices/escrow`, the
-- primary's token). Neither half opens anything alone. One row per (user, linked device);
-- `escrow_id` pairs R with the copy the device holds. Deleted with the device's revocation (the
-- list PUT, `devices/handlers.rs`) and with the account (CASCADE).
--
-- `takeover_requests`: a linked device asking to become the primary (`POST /devices/takeover`),
-- carrying a one-time public key. A server admin approves it (`POST /admin/takeovers/:id/approve`)
-- with the six-digit code the device shows — derived from the request's id and that key
-- (`sezi_protocol::takeover`), so the admin cannot approve without hearing it from whoever holds
-- the device. Only then does `GET /devices/takeover` hand R to that device, sealed to the one-time
-- key. `state`: pending → approved | refused (the primary) | failed (three wrong codes) |
-- cancelled (the device, a newer request, or the device's revocation); a pending or approved
-- request past `expires_at` (24 h; an approval moves it to a day after the release) reads as
-- expired, and an approved one before `release_at` reads as held. Times are MILLISECONDS.

CREATE TABLE IF NOT EXISTS device_escrow (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL,
    escrow_id   TEXT NOT NULL,
    r_b64       TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS takeover_requests (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL,
    one_time_pub_b64  TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'pending',
    wrong_codes       INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    decided_by        TEXT,
    decided_at        INTEGER,
    -- When an approved request's R may be released. An admin's approval of an account whose
    -- primary was seen within a day HOLDS the release for 6 h (Hasan, 2026-10-30), so a living
    -- primary has time to refuse; one not seen for a day releases at once.
    release_at        INTEGER,
    -- The first time R was handed out: the moment the old primary's relay session is ended.
    released_at       INTEGER
);

CREATE INDEX IF NOT EXISTS takeover_requests_device ON takeover_requests(user_id, device_id, created_at);
CREATE INDEX IF NOT EXISTS takeover_requests_open ON takeover_requests(state, expires_at);
