-- Sezgi: grup-sohbeti altyapısı (Faz 1 — üyelik).
--
-- groups          : sunucu-içi grup/oda (kurucu = grup-owner).
-- group_members   : grup ALT-üyeliği — SUNUCU üyeliğinden (users) AYRI.
--                   Grup-içi rol (owner/admin/member) sunucu-rolünden bağımsız.
--
-- E2E: sunucu grup İÇERİĞİNİ asla görmez (envelope opak); yalnız üyelik tutar +
-- (Faz 2) mesajı üyelerin DO inbox'larına fan-out eder. İçerik kriptosu Megolm
-- (client). Tek-sunucu kurulum → server_id kolonu YOK (users gibi).

CREATE TABLE IF NOT EXISTS groups (
    id          TEXT PRIMARY KEY,                    -- UUID v4
    name        TEXT NOT NULL,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id    TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id),
    role        TEXT NOT NULL DEFAULT 'member',      -- 'owner' | 'admin' | 'member'
    joined_at   INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

-- "Üyesi olduğum gruplar" sorgusu (list_my_groups) için.
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
