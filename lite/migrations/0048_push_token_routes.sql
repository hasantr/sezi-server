-- 0048: the own-project push route is decided per TOKEN (K8 fix, adversarial review 2026-10-14).
--
-- The first K8 build recorded ONE server-wide verdict ("Google refused the owner's Firebase project
-- for these phones") and moved every wake to the shared relay. Two wakes racing on a fresh server
-- (an own-build phone and a published-app phone) could then move an own-build server to a relay
-- that cannot reach it. Now a token Google refuses for the owner's project is marked here with
-- that project's id and relayed from then on; every other token keeps going direct. A new token
-- for the device clears the mark (`push/handlers.rs`), and so does the owner saving the
-- credentials (`admin/fcm_config.rs`).
--
-- The server-wide verdict routes nothing any more; its row is removed.
DELETE FROM server_config WHERE key = 'push_own_project_mismatch';
ALTER TABLE push_tokens ADD COLUMN relay_project TEXT;
