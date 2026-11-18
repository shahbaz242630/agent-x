-- When each MCP client last connected, and the connections each member made
-- (Phase 6 6E3b; ADR-016).
--
-- oauth.clients.last_connected_at is set as a
-- connection's tokens are issued, by a code or a refresh, at most once an
-- hour (the token's own transaction, sent on the same trip as its rows). The
-- sweep then deletes a client that registered and never connected after a
-- day, as before, and one that last connected more than 90 days ago: by then
-- no connection of its can still be refreshed (a refresh token's 30 idle
-- days, a connection's 90), so nothing that works is lost. A client's
-- connections name it by ID alone (agents.connections), never by a foreign
-- key, so deleting it touches no organisation's rows.
--
-- `first_connected_at` stays: it is when the client was first trusted by a
-- person, which the sweep no longer reads. A client that connected before
-- this ran starts from its first connection.

ALTER TABLE oauth.clients ADD COLUMN last_connected_at timestamptz;
ALTER TABLE oauth.clients
  ADD CONSTRAINT last_connected_after_the_first CHECK (
    last_connected_at IS NULL OR (first_connected_at IS NOT NULL AND last_connected_at >= first_connected_at)
  );

UPDATE oauth.clients SET last_connected_at = first_connected_at WHERE first_connected_at IS NOT NULL;

-- The sweep's clients unused for 90 days.
CREATE INDEX clients_by_last_connection ON oauth.clients (last_connected_at);

GRANT UPDATE (last_connected_at) ON oauth.clients TO agentx_app;

-- The connections a member made, revoked when they are removed from the
-- organisation (decision 7): found by who made them, in the removal's own
-- transaction.
CREATE INDEX connections_by_maker ON agents.connections (org_id, made_by);
