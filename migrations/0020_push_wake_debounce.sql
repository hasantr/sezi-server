-- Kurtarma-sağlamlık K3 (FCM-wake storm-fix): recipient+device başına son-wake damgası.
-- wedge/burst'te N-undelivered-mesaj → 1-wake/pencere (~20sn). İçeriksiz-wake "uyan +
-- TÜM pending'i çek" semantiği taşıdığı için debounce KAYIPSIZ (bir wake hepsini drain eder).
-- Eksik tablo (migration uygulanmamış) → fcm.rs graceful: debounce-yok = eski davranış (kırılmaz).

CREATE TABLE IF NOT EXISTS push_wake_debounce (
  user_id       TEXT NOT NULL,
  device_id     TEXT NOT NULL,   -- '' = device-blind (recipient_device_id None)
  last_sent_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, device_id)
);
