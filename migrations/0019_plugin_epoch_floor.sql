-- 0019: FORWARD-SECRECY (Faz-D) — per-room eklenti server-log EPOCH FLOOR (server-kör zorlama).
--
-- Gruptan üye ÇIKARILDIĞINDA (kick / self-leave / server-level delete) bu floor ARTAR. Eklenti
-- server-log append'i `key_epoch < floor` ise worker `409 epoch_stale` ile REDDEDER → çıkarılan
-- üyenin (ya da geride-kalan yazarın) ESKİ epoch'a yeni-veri yazıp forward-secrecy'yi delmesini
-- server-tarafında engeller. Server KÖR kalır: yalnız INTEGER karşılaştırır, anahtar/içerik GÖRMEZ.
--
-- room_id = group_id (groups.id; plugin_log DO da id_from_name(room) ile aynı anahtar). floor
-- default 0 (satır yoksa floor=0 kabul edilir → kısıt yok). Membership-removal handler'ları
-- `INSERT ... ON CONFLICT DO UPDATE floor=floor+1` ile atomik bump eder. IF NOT EXISTS idempotent.

CREATE TABLE IF NOT EXISTS plugin_epoch_floor (
    room_id TEXT PRIMARY KEY,
    floor   INTEGER NOT NULL DEFAULT 0
);
