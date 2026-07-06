-- Sezgi: owner rolü + davet izleme.
-- users.role artık 'owner' | 'admin' | 'member' taşır (ilk kayıt = owner, verify.rs).
-- owner_user_id: daveti üreten admin/owner (create_invite'ta set).
-- invite_token: redeem→verify köprüsü; verify'da kullanıcı oluşunca used_by doldurulur.

ALTER TABLE invite_tokens ADD COLUMN owner_user_id TEXT REFERENCES users(id);
ALTER TABLE verification_codes ADD COLUMN invite_token TEXT;
