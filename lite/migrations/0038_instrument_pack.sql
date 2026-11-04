-- 0038: instrument_pack — the ONE SoundFont (.sf2) the operator hosts for the music plugin.
--
-- SINGLE ROW (id = 1, the server_settings shape): a server hosts at most one pack and a PUT
-- REPLACES it. `hash` is BLAKE3 of the file in hex and does three jobs at once — it is the
-- storage key (`packs/<hash>.sf2`), the HTTP ETag, and the pin the client keeps beside its
-- downloaded copy, so a member that already holds this hash never fetches the bytes again.
--
-- PLAINTEXT, BY DECLARED EXCEPTION. Every other blob this relay stores is ciphertext it cannot
-- read. A SoundFont is public content the operator fetched from the internet — not anyone's
-- message — and encrypting it under a key the server itself would hold is theatre, not privacy.
-- Membership still gates every read: /instrument-pack takes an active member token.
--
-- `store_id` records WHICH backend took the object, exactly as media_objects/avatar_objects do,
-- so a pack survives an install that later adds an S3 backend.
CREATE TABLE IF NOT EXISTS instrument_pack (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  hash           TEXT NOT NULL,                       -- BLAKE3 hex: storage key, ETag and client pin
  name           TEXT NOT NULL DEFAULT '',            -- display name (X-Pack-Name); '' when none was sent
  size_bytes     INTEGER NOT NULL,
  store_id       TEXT NOT NULL DEFAULT 'r2-primary',
  uploaded_at_ms INTEGER NOT NULL
);
