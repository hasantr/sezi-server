-- 0057: REGISTRATION RECEIPTS — a registration whose answer was lost can be answered again
-- (docs/RELAY_AUDIT_2026_11_03.md finding #5).
--
-- `POST /auth/verify` writes the account in ONE batch, and that batch deletes the single-use
-- verification code. When the batch committed but its answer never reached the app, the app's
-- retry found no code, and the account it had just created was out of reach for good — an owner
-- saw `410 bootstrap_complete` on its own server. The same batch now leaves this receipt: the
-- code's hash and what the registration was bound to. A retry with the same code, the same
-- identity key and the same device, while the account has published no device yet and within
-- the receipt's half hour, is answered with fresh tokens for that account (`auth/verify_replay.rs`).
-- Guesses are charged like the code's own (`attempts`). The daily cleanup deletes expired rows.
--
-- No foreign key: a receipt outlives nothing — the replay checks that its account still exists.
CREATE TABLE IF NOT EXISTS registration_receipts (
  email           TEXT PRIMARY KEY,
  code_hash       TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  device_id       TEXT NOT NULL,
  identity_hash   TEXT NOT NULL,
  inviter_user_id TEXT,
  inviter_ed_pub  TEXT,
  attempts        INTEGER NOT NULL DEFAULT 0,
  expires_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_registration_receipts_expires ON registration_receipts (expires_at);
