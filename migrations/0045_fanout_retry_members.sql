-- D8 (2026-10-13): a group fan-out retries per MEMBER, not per device.
--
-- One row now carries a member and all of their devices, as the JSON array the inbox's
-- `/notify-member` takes (`["dev1","dev2"]`); NULL together with a NULL `recipient_device` is a
-- device-blind member. Rows written before this column keep their single `recipient_device`, and
-- the drain reads them as a one-device member, so nothing queued at upgrade time is lost.
--
-- Why it matters beyond tidiness: a row per device made one asleep 80 × 2 class message cost
-- ~1,575 D1 row writes in the queue, and the Free plan allows 100,000 a day for the whole server.
ALTER TABLE fanout_retry ADD COLUMN recipient_devices TEXT;
