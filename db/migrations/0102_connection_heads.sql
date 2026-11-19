-- A connection's current refresh token kept in a signed state, so the
-- database's owner can't hide a refresh token's use (tamper pass S205,
-- Threat-Model R-15; S206 V3).
--
-- A refresh token is used once: its row's `used_at` is filled in by the use,
-- and a second use is a reuse that revokes its connection (0093, SEC-OAUTH-05).
-- The owner, holding a stolen refresh token, could clear `used_at` (and
-- delete or put back the rows a use made) and refresh with it unseen, even
-- fork the connection into two chains that both refresh for ever.
--
-- agents.connection_heads is a connection's refresh head: an authority table
-- (ADR-012 §2), read and changed through its signed state, at the
-- connection's level in the lock order (ADR-006 §6: 3b, after the connection
-- itself). Sealed: `refresh_id`, the one refresh token of the connection that
-- may be used now. Each refresh locks it, refuses any other token as a reuse
-- (revoking the connection, and where the token's row says it is unused, the
-- integrity alarm), and moves it to the new refresh token in the same
-- transaction. Rolling it back means removing its signed events, which the
-- chain's own checks find. A row is addressed by its organisation and its
-- connection's ID (`id_is_its_connection`), as a supplier's remittance
-- setting is its supplier's (0061).
--
-- A connection made before this migration has no row until its next refresh,
-- which adds it (its token then judged by `used_at` alone, as before).
--
-- Each token's secret is, from this release, the agent-key pepper's MAC of
-- its kind, key and ID (no column: the secret is never kept), so a token sent
-- with its row gone can still be shown to be one the app issued.
--
-- The app adds rows and reads them, and changes only the sealed field and the
-- two signed-state columns, which the audit module's record writes and seals
-- together. It never deletes one (no grant). The backup role reads everything.

CREATE TABLE agents.connection_heads (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  refresh_id uuid NOT NULL,
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT id_is_its_connection FOREIGN KEY (org_id, id) REFERENCES agents.connections (org_id, id)
);

ALTER TABLE agents.connection_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents.connection_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents.connection_heads
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON agents.connection_heads TO agentx_app;
GRANT UPDATE (refresh_id, state_version, state_event_id) ON agents.connection_heads TO agentx_app;
GRANT SELECT ON agents.connection_heads TO agentx_backup;
