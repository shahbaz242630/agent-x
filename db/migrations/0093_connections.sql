-- MCP connections by OAuth (Phase 6 6E3a; MCP-Guide M5; ADR-016): Agent X's
-- own OAuth 2.1 authorization server, so an MCP client a person can't paste a
-- key into (ChatGPT, claude.ai) acts as one agent the person picks.
--
-- A person's consent issues a *connection key*: an ordinary agents.agent_keys
-- row (0027), ACTIVE, with the scopes ticked, expiring as any key does, whose
-- secret is random and thrown away, so no `axk_` text can ever work for it.
-- Beside it, agents.connections says it is a connection: the client, the MCP
-- resource and the redirect address it was made for. The OAuth tokens point
-- at that key, so the principal a token is accepted as is the key's own:
-- authorisation, spend requests, the activity log and hand-off are unchanged.
-- Suspending the agent refuses its tokens; revoking a connection is revoking
-- its key; a hand-over revokes every key, connection keys among them.
--
-- agents.connections is a tenant table behind the tenant policy, and an
-- authority table (ADR-012 §2) made once (0032's `made_once`): its agent,
-- client, resource and redirect address must equal its signed event
-- (`connection.made`), so a connection pointed at another client or resource
-- is caught at the next read. Its ID is its key's, so a key is a connection
-- at most once, and the key, with its agent, is a foreign key: a connection
-- can't be pointed at another agent's key (on the required list). It has no
-- status: its key's status and expiry are its own. Its client's name is what
-- the consent page showed, grants nothing and is not sealed; who made it is a
-- membership's ID with no foreign key, as an agent's owner is (0027).
--
-- agents.connection_tokens holds each access and refresh token a connection
-- was given: HMAC-SHA-256 of its secret with the agent-key pepper over its
-- kind, key, ID, expiry and scopes (domain-separated from a key's own MAC), so
-- a row changed in any of those no longer matches its secret. Not signed: a
-- token grants only what its key and connection grant, both signed, and every
-- token of a connection dies with its key. A refresh token is used once
-- (`used_at`, filled in once); a second use revokes the connection. The app
-- adds rows, reads them, fills in `used_at`, and deletes rows only past 120
-- days (the restrictive `retention` policy), long after any could work.
--
-- The `oauth` schema holds what comes before any organisation is known: the
-- clients that registered themselves (RFC 7591), and the authorization flows
-- under way. Both global, on the CI-06 list with their exact columns, neither
-- holding anything that grants: a flow names the organisation and key it was
-- allowed with by ID alone (no foreign key, SEC-TEN-08), and a token is only
-- issued after that organisation's own signed rows are read. A flow keeps the
-- client's `state` until it ends (RFC 6749 §4.1.2: it goes back unchanged).
--
-- The security events gain two kinds: `oauth_refused` (a client refused
-- before any organisation is known) and `connection_token_reused` (a refresh
-- token used twice, its connection revoked: the organisation's own).

CREATE TABLE agents.connections (
  org_id uuid NOT NULL,
  -- Its key's ID: one connection a key, at most.
  id uuid NOT NULL,
  agent_id uuid NOT NULL,
  client_id text NOT NULL CHECK (pg_catalog.char_length(client_id) BETWEEN 1 AND 2048),
  resource text NOT NULL CHECK (pg_catalog.char_length(resource) BETWEEN 1 AND 2048),
  -- None for a device's connection (6E3c), which has no browser to send back.
  redirect_uri text CHECK (pg_catalog.char_length(redirect_uri) BETWEEN 1 AND 2048),
  client_name text NOT NULL CHECK (pg_catalog.char_length(client_name) BETWEEN 1 AND 100),
  via text NOT NULL CHECK (via IN ('code', 'device')),
  made_by uuid NOT NULL,
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT a_code_has_its_redirect CHECK ((via = 'code') = (redirect_uri IS NOT NULL)),
  CONSTRAINT of_its_key_and_agent FOREIGN KEY (org_id, id, agent_id)
    REFERENCES agents.agent_keys (org_id, id, agent_id),
  CONSTRAINT of_an_agent_too FOREIGN KEY (org_id, agent_id) REFERENCES agents.agents (org_id, id)
);

-- An agent's connections, newest last: listed, counted against its limit, and the day's budget.
CREATE INDEX connections_by_agent ON agents.connections (org_id, agent_id, created_at);

ALTER TABLE agents.connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents.connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents.connections
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER made_once BEFORE UPDATE ON agents.connections
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_made_once();

GRANT SELECT, INSERT ON agents.connections TO agentx_app;
-- Only as the audit module's record seals a new connection: `made_once` refuses any change after.
GRANT UPDATE (agent_id, client_id, resource, redirect_uri, state_version, state_event_id)
  ON agents.connections TO agentx_app;
GRANT SELECT ON agents.connections TO agentx_backup;

CREATE TABLE agents.connection_tokens (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  key_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('access', 'refresh')),
  scopes text NOT NULL CHECK (
    pg_catalog.char_length(scopes) <= 200 AND scopes ~ '^[a-z]+:[a-z]+( [a-z]+:[a-z]+)*$'
  ),
  secret_mac text NOT NULL CHECK (secret_mac ~ '^[0-9a-f]{64}$'),
  secret_key_version integer NOT NULL CHECK (secret_key_version >= 1),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  -- The refresh token it was rotated from; none for the pair a code or a device gave.
  parent_id uuid,
  used_at timestamptz,
  PRIMARY KEY (org_id, id),
  CONSTRAINT only_a_refresh_is_used CHECK (used_at IS NULL OR kind = 'refresh'),
  CONSTRAINT token_expires_after_it_was_made CHECK (expires_at > created_at AND pg_catalog.isfinite(expires_at)),
  CONSTRAINT of_a_connection FOREIGN KEY (org_id, key_id) REFERENCES agents.connections (org_id, id)
);

-- A connection's tokens, newest first; and the organisation's oldest, for the sweep.
CREATE INDEX connection_tokens_by_key ON agents.connection_tokens (org_id, key_id, created_at DESC);
CREATE INDEX connection_tokens_by_time ON agents.connection_tokens (org_id, created_at);

ALTER TABLE agents.connection_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents.connection_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents.connection_tokens
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);
-- Past every token's life (an access token's hour, a refresh token's 30 idle days, a connection's 90).
CREATE POLICY retention ON agents.connection_tokens AS RESTRICTIVE FOR DELETE
  USING (created_at < pg_catalog.now() - pg_catalog.make_interval(days => 120));

GRANT SELECT, INSERT, DELETE ON agents.connection_tokens TO agentx_app;
GRANT UPDATE (used_at) ON agents.connection_tokens TO agentx_app;
GRANT SELECT ON agents.connection_tokens TO agentx_backup;

CREATE SCHEMA oauth;
GRANT USAGE ON SCHEMA oauth TO agentx_app, agentx_backup;

CREATE TABLE oauth.clients (
  client_id text PRIMARY KEY CHECK (client_id ~ '^axcl_[0-9a-f]{32}$'),
  name text NOT NULL CHECK (pg_catalog.char_length(name) BETWEEN 1 AND 100),
  redirect_uris text[] NOT NULL CHECK (
    pg_catalog.cardinality(redirect_uris) BETWEEN 1 AND 5
    AND pg_catalog.array_ndims(redirect_uris) = 1
  ),
  application_type text NOT NULL CHECK (application_type IN ('web', 'native')),
  grant_types text[] NOT NULL CHECK (
    pg_catalog.cardinality(grant_types) BETWEEN 1 AND 3
    AND pg_catalog.array_ndims(grant_types) = 1
  ),
  software_id text CHECK (pg_catalog.char_length(software_id) BETWEEN 1 AND 255),
  software_version text CHECK (pg_catalog.char_length(software_version) BETWEEN 1 AND 255),
  created_at timestamptz NOT NULL,
  first_connected_at timestamptz,
  CONSTRAINT connected_after_it_registered CHECK (first_connected_at IS NULL OR first_connected_at >= created_at)
);

-- The day's registrations, counted against the daily cap, and the sweep's never-connected clients.
CREATE INDEX clients_by_time ON oauth.clients (created_at);

GRANT SELECT, INSERT, DELETE ON oauth.clients TO agentx_app;
GRANT UPDATE (first_connected_at) ON oauth.clients TO agentx_app;
GRANT SELECT ON oauth.clients TO agentx_backup;

CREATE TABLE oauth.flows (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('code', 'device')),
  client_id text NOT NULL CHECK (pg_catalog.char_length(client_id) BETWEEN 1 AND 2048),
  redirect_uri text CHECK (pg_catalog.char_length(redirect_uri) BETWEEN 1 AND 2048),
  state text CHECK (pg_catalog.char_length(state) BETWEEN 1 AND 512),
  code_challenge text CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  scopes_asked text NOT NULL CHECK (
    pg_catalog.char_length(scopes_asked) <= 200 AND scopes_asked ~ '^[a-z]+:[a-z]+( [a-z]+:[a-z]+)*$'
  ),
  resource text NOT NULL CHECK (pg_catalog.char_length(resource) BETWEEN 1 AND 2048),
  -- SHA-256 of the browser's flow cookie, as hex: only that browser reads or decides the flow.
  browser_hash text CHECK (browser_hash ~ '^[0-9a-f]{64}$'),
  device_hash text CHECK (device_hash ~ '^[0-9a-f]{64}$'),
  user_code_hash text UNIQUE CHECK (user_code_hash ~ '^[0-9a-f]{64}$'),
  interval_s integer CHECK (interval_s BETWEEN 1 AND 60),
  created_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  decided_at timestamptz,
  outcome text CHECK (outcome IN ('allowed', 'denied')),
  -- The organisation and connection key it was allowed with: IDs only, no foreign key (SEC-TEN-08).
  org_id uuid,
  key_id uuid,
  code_hash text UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  code_ends_at timestamptz,
  used_at timestamptz,
  polled_at timestamptz,
  CONSTRAINT flow_ends_after_it_begins CHECK (ends_at > created_at),
  CONSTRAINT a_code_flow_is_a_browser CHECK (
    kind <> 'code' OR (
      redirect_uri IS NOT NULL AND code_challenge IS NOT NULL AND browser_hash IS NOT NULL
      AND device_hash IS NULL AND user_code_hash IS NULL AND interval_s IS NULL AND polled_at IS NULL
    )
  ),
  CONSTRAINT a_device_flow_is_a_device CHECK (
    kind <> 'device' OR (
      redirect_uri IS NULL AND code_challenge IS NULL AND browser_hash IS NULL AND state IS NULL
      AND device_hash IS NOT NULL AND user_code_hash IS NOT NULL AND interval_s IS NOT NULL AND code_hash IS NULL
    )
  ),
  CONSTRAINT decided_once_whole CHECK ((decided_at IS NULL) = (outcome IS NULL)),
  CONSTRAINT allowed_names_its_connection CHECK (
    (outcome = 'allowed') = (org_id IS NOT NULL AND key_id IS NOT NULL)
  ),
  CONSTRAINT a_code_with_its_end CHECK ((code_hash IS NULL) = (code_ends_at IS NULL)),
  CONSTRAINT used_only_once_allowed CHECK (used_at IS NULL OR outcome = 'allowed')
);

-- The sweep's ended flows.
CREATE INDEX flows_by_end ON oauth.flows (ends_at);

GRANT SELECT, INSERT, DELETE ON oauth.flows TO agentx_app;
GRANT UPDATE (decided_at, outcome, org_id, key_id, code_hash, code_ends_at, used_at, polled_at)
  ON oauth.flows TO agentx_app;
GRANT SELECT ON oauth.flows TO agentx_backup;

ALTER TABLE security.events DROP CONSTRAINT events_kind_check;
ALTER TABLE security.events
  ADD CONSTRAINT events_kind_check
  CHECK (kind IN ('sign_in_failed', 'rate_limited', 'partner_event_refused', 'oauth_refused'));

ALTER TABLE security.org_events DROP CONSTRAINT org_events_kind_check;
ALTER TABLE security.org_events
  ADD CONSTRAINT org_events_kind_check
  CHECK (kind IN ('sign_in_failed', 'rate_limited', 'connection_token_reused'));
