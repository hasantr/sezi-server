-- Sezgi: grup KATILIM ONAYI (consent-first; Faz 6 #3).
--
-- "Eklenmek ≠ otomatik katılmak": bir kullanıcı gruba eklenince SESSİZCE üye
-- olmaz; 'pending' durumda davet alır → KABUL (active) veya RED (satır silinir).
--   status   : 'pending' | 'active'  (yalnız active üye mesaj alır/gönderir/sayılır)
--   added_by : daveti gönderen (kabul edince ona GroupJoinAccepted → o anahtarı
--              dağıtır; E2E: anahtar yalnız kabulden SONRA akar).
--
-- Geriye-uyum: DEFAULT 'active' → mevcut (zaten katılmış) üyeler + eski satırlar
-- active kalır. YALNIZ yeni eklenenler (create_group ilk üyeler + add-member)
-- pending yazılır. added_by NULL = eski satır / kurucu.

ALTER TABLE group_members ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE group_members ADD COLUMN added_by TEXT;
