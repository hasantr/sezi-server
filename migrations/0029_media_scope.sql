-- 0029: medya IDOR kapısı (2026-07-10 audit #2) — recipient/room scope bağı.
-- Önceden /media/:id yalnız require_auth'lu → blob_id bilen HERKES çekebiliyordu.
-- Artık upload'ta uploader hedefi ilan eder (scope_kind='peer'|'room', scope_id),
-- download bunu kapılar: uploader HER ZAMAN; peer scope'ta karşı-taraf; room
-- scope'ta aktif grup üyesi. Kolon YOKKEN (NULL) = eski/ilan-siz → yalnız
-- uploader (fail-closed; kimse dağıtımda değil, geçmiş-kaybı sorun değil).
ALTER TABLE media_objects ADD COLUMN scope_kind TEXT;
ALTER TABLE media_objects ADD COLUMN scope_id TEXT;
