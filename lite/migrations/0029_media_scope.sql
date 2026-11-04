-- 0029: the media IDOR gate — binding a blob to a recipient/room scope.
-- /media/:id used to require nothing but auth, so ANYONE who knew a blob_id could fetch it.
-- The uploader now declares the target at upload time (scope_kind='peer'|'room', scope_id) and
-- the download gates on it: the uploader ALWAYS; in a peer scope, the other party; in a room
-- scope, an active group member. When the columns are absent (NULL) = old/undeclared → the
-- uploader only (fail-closed; nobody is in distribution yet, so losing the history is fine).
ALTER TABLE media_objects ADD COLUMN scope_kind TEXT;
ALTER TABLE media_objects ADD COLUMN scope_id TEXT;
