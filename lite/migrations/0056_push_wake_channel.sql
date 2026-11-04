-- 0056: the channel a visible wake is drawn on (`push/style.rs`, `WakeChannel`), POCO 2026-11-03.
--
-- A visible wake (0051) was drawn on the message channel, which shows a launcher badge: the
-- generic wake counted one, the real notification one more, and the app taking the generic one
-- down one less. An app that created the badge-less 'sezgi_wake_v1' channel says so at register
-- (`wake_channel`), and its visible wakes are drawn there. NULL — every existing token, every
-- data token, every app that does not say it — keeps the message channel, so no wake names a
-- channel its app never created. Only the allow-listed id is ever written here.
ALTER TABLE push_tokens ADD COLUMN wake_channel TEXT;
