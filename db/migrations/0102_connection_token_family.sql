-- A refresh token's family sealed, so the database's owner can't hide a
-- refresh token's use (tamper pass S205, Threat-Model R-15; S206 V3).
--
-- A refresh token is used once: its row's `used_at` is filled in by the use,
-- and a second use is a reuse that revokes its connection (0093, SEC-OAUTH-05).
-- The owner, holding a stolen refresh token, could clear `used_at` or delete
-- the used row and refresh with it unseen. Now a use is judged from the
-- token's family too, rows the owner can't rewrite unseen:
--
-- - every token made from now on has MAC version 2 (`mac_version`): its MAC
--   (the agent-key pepper, a key the database never holds) also covers
--   `parent_id`, the refresh token it replaced, so a child moved off its
--   parent no longer matches its secret; and a row moved back to version 1
--   doesn't either, its MAC taken over version 2's message;
-- - its secret is itself the pepper's MAC of its kind, key and ID, so a token
--   sent with its row gone can still be shown to be one the app issued.
--
-- A refresh token is used if `used_at` says so, or if any token names it
-- as its parent; its parent with another refresh child is a family split in
-- two. Either way its connection is revoked, and where the row disagrees, the
-- integrity alarm. As any rotation's reuse detection, a use hidden by deleting
-- the child too is found when the other holder's next token is sent: a
-- genuine token with no row.
--
-- Tokens made before this migration are version 1, their parent unsealed and
-- their secret random; the last of them ends 30 days after (90 for a pair's
-- access token's connection). `connection_tokens_by_parent` finds a token's
-- children and its siblings in one statement, on the index alone.

-- Building the index holds a lock that makes every refresh wait, so it gives
-- up rather than queue behind a long transaction (the runner resets the
-- setting after the file).
SET LOCAL lock_timeout = '5s';

ALTER TABLE agents.connection_tokens
  ADD COLUMN mac_version smallint NOT NULL DEFAULT 1 CHECK (mac_version IN (1, 2));

CREATE INDEX connection_tokens_by_parent ON agents.connection_tokens (org_id, parent_id) WHERE parent_id IS NOT NULL;
