-- MCP clients named by their own metadata document, and connections made
-- from a device (Phase 6 6E3c; ADR-016 §5; SEC-OAUTH-09).
--
-- oauth.client_metadata keeps, for a day, the client ID metadata documents
-- Agent X fetched (CIMD): a client whose ID is an https address on the
-- allowlist (AGENTX_OAUTH_CLIENT_METADATA_ORIGINS: Claude, ChatGPT, Hermes)
-- publishes there what it is and where it may be sent back to. The fetch is
-- a public GET carrying no customer data (ADR-013). A document grants
-- nothing, as a registration grants nothing: a connection is made only by a
-- person's consent. Global, as oauth.clients is; swept once its day is past.
--
-- A device flow (RFC 8628) is opened with no browser: the person types its
-- user code into the console, which claims the flow for that browser, by its
-- flow cookie's hash, so the consent that follows is the code flow's own and
-- only that browser decides it. Claimed once: a second browser typing the
-- same code finds nothing. Its device code is looked up by its hash.

CREATE TABLE oauth.client_metadata (
  client_id text PRIMARY KEY CHECK (
    pg_catalog.char_length(client_id) BETWEEN 1 AND 2048 AND client_id ~ '^https://[^/?#]+/[^#]*$'
  ),
  name text NOT NULL CHECK (pg_catalog.char_length(name) BETWEEN 1 AND 100),
  -- A published client may list more addresses than one that registers itself (5): web, desktop and loopback.
  redirect_uris text[] NOT NULL CHECK (
    pg_catalog.cardinality(redirect_uris) BETWEEN 1 AND 10
    AND pg_catalog.array_ndims(redirect_uris) = 1
  ),
  grant_types text[] NOT NULL CHECK (
    pg_catalog.cardinality(grant_types) BETWEEN 1 AND 3
    AND pg_catalog.array_ndims(grant_types) = 1
  ),
  fetched_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  CONSTRAINT kept_after_it_was_fetched CHECK (expires_at > fetched_at AND pg_catalog.isfinite(expires_at))
);

-- The sweep's documents past their day.
CREATE INDEX client_metadata_by_end ON oauth.client_metadata (expires_at);

-- Kept, read, fetched again over its own row once its day is past, and swept.
GRANT SELECT, INSERT, DELETE ON oauth.client_metadata TO agentx_app;
GRANT UPDATE (name, redirect_uris, grant_types, fetched_at, expires_at) ON oauth.client_metadata TO agentx_app;
GRANT SELECT ON oauth.client_metadata TO agentx_backup;

-- A device flow may now name the browser that claimed it; still no redirect, challenge, state or code.
ALTER TABLE oauth.flows DROP CONSTRAINT a_device_flow_is_a_device;
ALTER TABLE oauth.flows
  ADD CONSTRAINT a_device_flow_is_a_device CHECK (
    kind <> 'device' OR (
      redirect_uri IS NULL AND code_challenge IS NULL AND state IS NULL
      AND device_hash IS NOT NULL AND user_code_hash IS NOT NULL AND interval_s IS NOT NULL AND code_hash IS NULL
    )
  );

-- A device code, by its hash, as the device polls the token endpoint.
CREATE UNIQUE INDEX flows_by_device ON oauth.flows (device_hash);

-- Only to claim a device flow for the browser whose person typed its code (oauth/flows.ts deviceClaimed).
GRANT UPDATE (browser_hash) ON oauth.flows TO agentx_app;
