-- Sezgi: çoklu-cihaz adresleme (M1 — cihaz kimliği + imzalı liste).
--
-- WhatsApp-yıldız modeli: 1 birincil (primary, güven kökü) + ≤4 bağlı (linked).
-- Her cihaz KENDİ Olm Account'unu çalıştırır; özel anahtar cihazlar arasında
-- ASLA taşınmaz. Cihaz-listesi BİRİNCİL cihazın Ed25519'u ile imzalıdır →
-- server listeyi SAKLAR/DAĞITIR ama ÜRETEMEZ/DEĞİŞTİREMEZ (sıfır-güven;
-- enjekte cihaz imza doğrulamasından geçemez). Asıl doğrulama client'ta,
-- buradaki kontroller savunma-derinliği.
--
-- devices       : (user_id, device_id) düzeyinde cihaz kaydı; imzalı listenin
--                 server-tarafı izdüşümü. revoked_at NULL = aktif.
-- device_lists  : kullanıcı-başına kanonik imzalı doküman (verbatim JSON + imza).
--                 doc_json JWS-modeli: imza, üretilen JSON string'inin AYNEN o
--                 baytları üzerinde → asla yeniden serileştirilmez.
--
-- Link/QR tabloları M2'de (bağlı cihaz akışı). Bu migration tamamen additive;
-- mevcut mesaj/auth/DO yolları DEĞİŞMEZ.

CREATE TABLE IF NOT EXISTS devices (
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,          -- 16 hex (hex(BLAKE3(ed_pub)[0..8]))
    role        TEXT NOT NULL,          -- 'primary' | 'linked'
    ed_pub      BLOB NOT NULL,
    x_pub       BLOB NOT NULL,
    label       TEXT,
    added_at    INTEGER NOT NULL,
    revoked_at  INTEGER,                -- NULL = aktif
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS device_lists (
    user_id     TEXT PRIMARY KEY,
    rev         INTEGER NOT NULL,       -- kesin artan (rollback koruması)
    doc_json    TEXT NOT NULL,          -- verbatim imzalı doküman (JWS baytları)
    sig_b64     TEXT NOT NULL,          -- primary.sign(doc_json_utf8_bytes)
    updated_at  INTEGER NOT NULL
);
