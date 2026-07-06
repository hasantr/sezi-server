-- 0018: M10 owner-race — tek-owner garantisi (eşzamanlı ilk-kayıt İKİ owner yaratmasın).
--
-- Sorun: `auth/verify.rs` ilk kullanıcıyı owner yapar (`SELECT id FROM users LIMIT 1`
-- boşsa role='owner'). İki istek aynı anda bu SELECT'i boş görürse İKİ kullanıcı da
-- owner olarak INSERT edilebilir (TOCTOU). Owner = sunucu kurucusu/korumalı rol →
-- iki owner yetki modelini bozar.
--
-- Fix: D1 (SQLite) partial UNIQUE index — yalnız role='owner' satırları üzerinde
-- tekillik zorlar. İkinci owner INSERT'i UNIQUE-violation ile başarısız olur (DB-atomik;
-- TOCTOU penceresi kapanır). member/admin satırları index'e GİRMEZ → onlarda kısıt yok.
-- IF NOT EXISTS → idempotent re-run güvenli.

-- FIX-2 (DEPLOY-HAZARD): pre-dedup. Prod DB'de bu bug'ların (transfer-owner race /
-- bootstrap TOCTOU) ürettiği kirli durum (>=2 owner) zaten varsa, CREATE UNIQUE INDEX
-- PATLAR → D1 migration batch abort → DEPLOY BLOKLU. Idempotent temizlik: EN ESKİ
-- owner'ı (created_at MIN, tie-break rowid MIN) KORU, diğer tüm owner'ları admin'e indir.
-- 0 veya 1 owner varsa NO-OP (zararsız re-run). created_at = INTEGER (0001_init).
UPDATE users SET role = 'admin'
 WHERE role = 'owner'
   AND id NOT IN (
     SELECT id FROM users WHERE role = 'owner'
      ORDER BY created_at ASC, rowid ASC LIMIT 1
   );

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_owner ON users(role) WHERE role = 'owner';

-- M10 bootstrap-race — eşzamanlı /bootstrap çağrıları çoklu genesis token
-- üretebiliyordu (her ikisi de "mevcut genesis yok" görüp INSERT). Genesis satırı
-- = `owner_user_id IS NULL AND used = 0` (sistem-üretimi, kullanılmamış). Partial
-- UNIQUE index → aynı anda EN FAZLA bir kullanılmamış genesis daveti olabilir;
-- ikinci eşzamanlı INSERT UNIQUE-violation ile düşer → bootstrap handler hatayı
-- yutup mevcut tek-satırı re-SELECT eder (idempotent, tek token döner). Gerçek
-- davetler (`create_invite`, owner_user_id dolu) bu index'e GİRMEZ → kısıt yok.
-- used=1 genesis de index-dışı (kullanıldıktan sonra yeniden tekil-kısıt gerekmez,
-- zaten owner oluşunca kapı 410). `used` indeksli kolon ama tüm partial-satırlarda
-- used=0 → sabit değer; tekillik owner_user_id-NULL+used=0 kümesinde tek-satır demek.
-- FIX-2 (DEPLOY-HAZARD): pre-dedup. Bootstrap-race >=2 kullanılmamış-genesis varsa
-- CREATE UNIQUE INDEX patlar. EN ESKİ kullanılmamış-genesis'i (created_at MIN, tie-break
-- rowid MIN) KORU, diğerlerini used=1 işaretle → index-dışına çıkar. invite_tokens
-- kolonları: token(PK)/used/expires_at/created_at(INTEGER, 0001_init)/owner_user_id
-- (0004). 0/1 genesis varsa NO-OP. token PK → NOT IN alt-sorgu token'a göre.
UPDATE invite_tokens SET used = 1
 WHERE owner_user_id IS NULL AND used = 0
   AND token NOT IN (
     SELECT token FROM invite_tokens
      WHERE owner_user_id IS NULL AND used = 0
      ORDER BY created_at ASC, rowid ASC LIMIT 1
   );

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_genesis_invite
  ON invite_tokens(used) WHERE owner_user_id IS NULL AND used = 0;
