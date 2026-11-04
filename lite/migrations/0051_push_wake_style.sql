-- 0051: how a token is woken (`push/style.rs`), Hasan's phone 2026-10-24.
--
-- `wake` = 'data' is every token so far: a data-only wake the app's own process decrypts. A device
-- whose maker will not start the app for such a wake (MIUI/HyperOS with Autostart off) registers
-- 'visible', and its wakes also carry a fixed generic notification the OS draws itself. The client
-- registers 'data' again once the switch is on. `wake_lang` is that notification's language
-- ('tr' | 'en'), kept only for a visible token. DEFAULT 'data' leaves every existing token, and
-- every client that sends no `wake`, exactly as it was.
ALTER TABLE push_tokens ADD COLUMN wake TEXT NOT NULL DEFAULT 'data';
ALTER TABLE push_tokens ADD COLUMN wake_lang TEXT;
