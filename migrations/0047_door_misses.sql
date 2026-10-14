-- 0047: the door's miss counter, strongly consistent (K6 review, 2026-10-14).
--
-- Redeem and the invite page bound guessing a 39-bit invite code by counting MISSES per client
-- address. That count lived in the KV rate limiter, which is a read-modify-write over an
-- eventually consistent store (concurrent writes overwrite each other, reads are edge-cached, a
-- failure is read as "allow"), and both doors peeked it before the lookup and charged it after —
-- so a guesser with many requests in flight got a lookup for every one of them.
--
-- One row per address and fixed window. A request RESERVES a miss in one atomic statement before
-- it looks anything up (`door_bucket::RESERVE_SQL`), and a hit gives it back. D1 runs every
-- statement on its single primary, so the count is a real bound at any concurrency. Rows of past
-- windows are swept by the daily maintenance.
CREATE TABLE IF NOT EXISTS door_misses (
  bucket        TEXT PRIMARY KEY,
  window_start  INTEGER NOT NULL,
  misses        INTEGER NOT NULL
);
