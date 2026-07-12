-- 0027: server_plugin_policy — server-çapı eklenti kullanılabilirlik politikası.
--
-- Owner/admin, client'taki server-yönetim ekranından bir eklentiyi server çapında
-- KULLANILAMAZ (DISABLED) işaretler. DEFAULT herkes ENABLED → yalnız DISABLED olan
-- eklentiler burada satır tutar (satır varlığı = disabled). Boş tablo = tümü açık.
--
-- Tek-server-tek-DB mimaride server_id kolonu GEREKMEZ (server_config/server_settings
-- deseni: tablo tek sunucunun state'i). Okuma: GET /plugin-policy (HERHANGİ aktif üye →
-- client picker'ı filtreler). Yazma: POST /admin/plugin-policy (require_admin: admin|owner).

CREATE TABLE IF NOT EXISTS server_plugin_policy (
  plugin_id   TEXT PRIMARY KEY,
  disabled_at INTEGER NOT NULL
);
