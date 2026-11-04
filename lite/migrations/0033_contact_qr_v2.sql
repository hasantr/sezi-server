-- Contact QR V2: short-lived, single-use mutual-contact capabilities.
--
-- The public signed offer is safe to persist. The 256-bit capability secret is
-- present only in the QR and is disclosed during the winning claim; neither the
-- raw secret nor raw claim JSON is stored here. `contact_qr_claims.offer_id`
-- being UNIQUE is the database-enforced single-winner boundary.

CREATE TABLE IF NOT EXISTS contact_qr_offers (
  offer_id                    TEXT PRIMARY KEY CHECK(length(offer_id) = 32),
  offer_hash_hex              TEXT NOT NULL UNIQUE CHECK(length(offer_hash_hex) = 64),
  server_fingerprint          TEXT NOT NULL,
  issuer_user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issuer_device_id            TEXT NOT NULL,
  offer_json                  TEXT NOT NULL,
  issued_at_ms                INTEGER NOT NULL,
  expires_at_ms               INTEGER NOT NULL,
  max_claims                  INTEGER NOT NULL DEFAULT 1 CHECK(max_claims = 1),
  capability_commitment_hex   TEXT NOT NULL CHECK(length(capability_commitment_hex) = 64),
  created_at                  INTEGER NOT NULL,
  consumed_at_ms              INTEGER,
  consumed_claim_id           TEXT UNIQUE,
  CHECK(expires_at_ms > issued_at_ms),
  CHECK(expires_at_ms - issued_at_ms <= 900000)
);
CREATE INDEX IF NOT EXISTS idx_contact_qr_offers_issuer
  ON contact_qr_offers(issuer_user_id, created_at DESC, offer_id);
CREATE INDEX IF NOT EXISTS idx_contact_qr_offers_expiry
  ON contact_qr_offers(expires_at_ms, consumed_at_ms);

CREATE TABLE IF NOT EXISTS contact_qr_claims (
  claim_id_hex                 TEXT PRIMARY KEY CHECK(length(claim_id_hex) = 64),
  offer_id                     TEXT NOT NULL UNIQUE
    REFERENCES contact_qr_offers(offer_id) ON DELETE CASCADE,
  claimant_user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  claimant_device_id           TEXT NOT NULL,
  claimant_list_rev            INTEGER NOT NULL CHECK(claimant_list_rev > 0),
  nonce_hash_hex               TEXT NOT NULL CHECK(length(nonce_hash_hex) = 64),
  claimed_at_ms                INTEGER NOT NULL,
  capability_proof_hash_hex    TEXT NOT NULL CHECK(length(capability_proof_hash_hex) = 64),
  grant_applied                INTEGER NOT NULL DEFAULT 0 CHECK(grant_applied IN (0, 1)),
  grant_id                     TEXT,
  created_at                   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contact_qr_claims_claimant
  ON contact_qr_claims(claimant_user_id, created_at DESC, claim_id_hex);
