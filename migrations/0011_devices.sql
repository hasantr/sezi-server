-- Sezgi: multi-device addressing (device identity + the signed list).
--
-- A WhatsApp-style star: 1 primary (the root of trust) + up to 4 linked devices.
-- Every device runs its OWN Olm Account; a private key is NEVER carried between devices.
-- The device list is signed with the PRIMARY device's Ed25519 → the server STORES and
-- DISTRIBUTES the list but can NEITHER PRODUCE NOR ALTER it (zero trust; an injected device
-- cannot pass signature verification). The real verification happens on the client; the
-- checks here are defence in depth.
--
-- devices       : the device record at (user_id, device_id) level; the server-side
--                 projection of the signed list. revoked_at NULL = active.
-- device_lists  : the canonical signed document per user (verbatim JSON + signature).
--                 doc_json follows the JWS model: the signature covers EXACTLY the bytes of
--                 the JSON string that was produced → it is never re-serialised.
--
-- The link/QR tables come with the linked-device flow. This migration is entirely additive;
-- the existing message/auth/DO paths are UNCHANGED.

CREATE TABLE IF NOT EXISTS devices (
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,          -- 16 hex (hex(BLAKE3(ed_pub)[0..8]))
    role        TEXT NOT NULL,          -- 'primary' | 'linked'
    ed_pub      BLOB NOT NULL,
    x_pub       BLOB NOT NULL,
    label       TEXT,
    added_at    INTEGER NOT NULL,
    revoked_at  INTEGER,                -- NULL = active
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS device_lists (
    user_id     TEXT PRIMARY KEY,
    rev         INTEGER NOT NULL,       -- strictly increasing (rollback protection)
    doc_json    TEXT NOT NULL,          -- the verbatim signed document (the JWS bytes)
    sig_b64     TEXT NOT NULL,          -- primary.sign(doc_json_utf8_bytes)
    updated_at  INTEGER NOT NULL
);
