-- Recovery robustness (the FCM-wake storm fix): the last-wake stamp per recipient+device.
-- During a wedge or a burst, N undelivered messages → one wake per window (~20s). A
-- contentless wake carries "wake up and pull ALL pending", so the debounce is LOSSLESS — a
-- single wake drains all of them.
-- If the table is missing (the migration was never applied) fcm.rs degrades gracefully:
-- no debounce = the old behaviour, nothing breaks.

CREATE TABLE IF NOT EXISTS push_wake_debounce (
  user_id       TEXT NOT NULL,
  device_id     TEXT NOT NULL,   -- '' = device-blind (recipient_device_id None)
  last_sent_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, device_id)
);
