-- 0017: Model-B Layer-1 BLOCKER fix — cihaz-listesi rev HIGH-WATER (revoke-resurrection).
--
-- Sorun: `device_lists` satırı D1-churn'de kaybolursa, eski (silme-öncesi,
-- tombstone'suz) primary-imzalı bir doc fresh-insert olarak kabul edilip
-- aktif-cihaz upsert'i `revoked_at=NULL` ile ÇIKARILMIŞ bir cihazı diriltebiliyordu
-- (Codex BLOCKER, 2026-06-16). Tombstone yalnız restore-eden doc ONU TAŞIYORSA korur;
-- silme-öncesi bayat doc taşımaz.
--
-- Fix: `users.device_list_rev` = bu kullanıcının GÖRÜLEN en yüksek cihaz-listesi rev'i,
-- `device_lists` blob'undan BAĞIMSIZ kolon (satır kaybına dayanıklı). Worker
-- `validate_and_store_signed_list` artık `doc.rev < device_list_rev` PUT'unu reddeder
-- (bayat → resurrection engellenir) ve kazanan yazar high_water'ı MAX ile ilerletir.
-- EŞİT-rev (== high_water) RESTORE için izinli (imza zaten doğrulandı = gerçek en-güncel doc).
--
-- Backfill: mevcut device_lists.rev'den başlat (deploy-anı penceresi sıfır olsun;
-- yoksa high_water 0'dan başlar + ilk PUT'ta yakalar — yine güvenli ama backfill temiz).

ALTER TABLE users ADD COLUMN device_list_rev INTEGER NOT NULL DEFAULT 0;

UPDATE users SET device_list_rev = COALESCE(
  (SELECT rev FROM device_lists WHERE device_lists.user_id = users.id),
  0
);
