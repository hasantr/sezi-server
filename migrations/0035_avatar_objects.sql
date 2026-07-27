-- 0035: Profil/grup avatar blob deposu (Profil Fotoğrafı Epic §2.3).
-- E2E-şifreli avatar blob'ları için KULLANICI-BAŞINA TEK MANTIKSAL SLOT.
--
-- media_objects'ten BİLİNÇLİ AYRI tutulur:
--   * expires_at YOK → KALICI. Mesaj-retention TTL-cleanup'ı (maintenance::cleanup_expired,
--     yalnız media_objects.expires_at < now siler) bu tabloya DOKUNMAZ → avatar sınıfı
--     retention'dan MUAF (plan §2.3). Avatar bir profil-DURUMU'dur, efemer medya değil.
--   * user_id PRIMARY KEY → tek mantıksal slot: yeni yükleme öncekini storage_orphans'a
--     düşürür (mevcut orphan/temizlik altyapısı — günlük retry_orphans blob'u depodan siler).
--
-- Blob İÇERİĞİ sunucuya KÖR: anahtar yalnız E2E kanalda dolaşır; server yalnız opak bytes tutar.
CREATE TABLE IF NOT EXISTS avatar_objects (
  user_id     TEXT PRIMARY KEY REFERENCES users(id),
  object_id   TEXT NOT NULL,                 -- avatar_ref: E2E'de taşınan opak capability; download bununla çözer
  store_id    TEXT NOT NULL DEFAULT 'r2-primary',
  size_bytes  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- Download tek-segment opak object_id ile çözer (depo anahtarı avatar/{user}/{object_id},
-- '/' içerir → path param olamaz). Tek-slot: upsert eski object_id'yi düşürür → eski ref
-- artık çözülemez (404), eski blob storage_orphans'ta bekler.
CREATE UNIQUE INDEX IF NOT EXISTS idx_avatar_object_id ON avatar_objects (object_id);
