-- AI agents and their keys (ADR-011 §1, ADR-005 §6, PRD §3 `Agent` /
-- `AgentCredential`; BR-03; Phase 1 C1-1). The agents module owns both tables
-- (ADR-004), in a schema of its own; the directory owns the lookup from a
-- key's ID to its organisation.
--
-- directory.agent_keys is that lookup: a key's ID and its organisation, IDs
-- only, in a global table, so a request carrying a key can be placed in its
-- organisation before any is known (ADR-005 §6: "checking an agent key"). It
-- grants nothing: the key itself, with its secret's MAC, its agent, its
-- status and its expiry, is then read by that ID inside the organisation's
-- own withTenant and verified against its signed state, so an entry pointed
-- at another organisation finds no key there. On the CI-06 list with exactly
-- its columns (SEC-TEN-08). The app adds an entry and reads it; it never
-- changes or deletes one, so an entry stays after its key is revoked, as the
-- key's row does.
--
-- agents.agents is an agent: a tenant table, behind the tenant policy, and an
-- authority table (ADR-012 §2): its owner (a membership of the organisation),
-- its status and its scopes (the most any of its keys may be given) must
-- equal the agent's latest signed event, so an owner who reactivates a
-- suspended agent, widens its scopes or moves it to another member is caught
-- at the next read. Suspending is the kill switch (ADR-012 §5): ACTIVE >
-- SUSPENDED and back. Its name is what people call it, shown to the
-- organisation's own members, never logged or put in an audit event, and not
-- an authority field (it grants nothing), as an organisation's is. The owner
-- is a membership's ID with no foreign key: the agents module may not reach
-- into identity's tables (ADR-004's map), so the use case that adds an agent
-- checks the membership, and the seal holds it after.
--
-- agents.agent_keys is a key: its ID is the one in the key an agent sends
-- (`axk_<keyId>_<secret>`), and the row holds only HMAC-SHA-256 of the secret
-- with the agent-key pepper (ADR-011 §1), as lower-case hex, with the pepper's
-- version. Also an authority table: its agent, status, scopes, secret's MAC,
-- pepper version and expiry are sealed, so an owner who plants a secret they
-- know, moves a key to another agent, revokes a revocation or stretches an
-- expiry is caught at the next read. A key moves ACTIVE > REVOKED, once. A
-- rotation leaves the old key ACTIVE and moves its expiry forward to the end
-- of the overlap (ADR-011 §1), through its signed state; an expiry is only
-- ever brought forward, which the app holds. It points at its directory
-- entry, made in the same transaction, so no key exists that the lookup
-- leaves out or places in another organisation.
--
-- Scopes are words like `requests:write`, one space apart; the app holds
-- which words there are, and that they are sorted and each given once, so the
-- sealed text is the same for the same scopes.
--
-- The app adds rows and reads them, and changes only their authority fields
-- and the two signed-state columns, which the audit module's record writes
-- and seals together; never a name, a key or a creation time, and never
-- deletes (a key deleted and inserted again would be born ACTIVE).
-- The backup role reads everything, as it must for a logical backup.

CREATE TABLE directory.agent_keys (
  key_id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id),
  CONSTRAINT places_one_key UNIQUE (key_id, org_id)
);

GRANT SELECT, INSERT ON directory.agent_keys TO agentx_app;
GRANT SELECT ON directory.agent_keys TO agentx_backup;

CREATE SCHEMA agents;
GRANT USAGE ON SCHEMA agents TO agentx_app, agentx_backup;

CREATE TABLE agents.agents (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  name text NOT NULL CHECK (pg_catalog.char_length(name) BETWEEN 1 AND 100),
  owner uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED')),
  scopes text NOT NULL CHECK (
    pg_catalog.char_length(scopes) <= 200 AND scopes ~ '^[a-z]+:[a-z]+( [a-z]+:[a-z]+)*$'
  ),
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id)
);

ALTER TABLE agents.agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents.agents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents.agents
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON agents.agents
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE');

GRANT SELECT, INSERT ON agents.agents TO agentx_app;
GRANT UPDATE (owner, status, scopes, state_version, state_event_id) ON agents.agents TO agentx_app;
GRANT SELECT ON agents.agents TO agentx_backup;

CREATE TABLE agents.agent_keys (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  agent_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
  scopes text NOT NULL CHECK (
    pg_catalog.char_length(scopes) <= 200 AND scopes ~ '^[a-z]+:[a-z]+( [a-z]+:[a-z]+)*$'
  ),
  secret_mac text NOT NULL CHECK (secret_mac ~ '^[0-9a-f]{64}$'),
  secret_key_version integer NOT NULL CHECK (secret_key_version >= 1),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT expires_after_it_was_made CHECK (expires_at > created_at AND pg_catalog.isfinite(expires_at)),
  CONSTRAINT of_an_agent FOREIGN KEY (org_id, agent_id) REFERENCES agents.agents (org_id, id),
  CONSTRAINT listed_in_the_directory FOREIGN KEY (id, org_id)
    REFERENCES directory.agent_keys (key_id, org_id)
);

-- An agent's keys, found when they are listed, rotated or counted.
CREATE INDEX agent_keys_by_agent ON agents.agent_keys (org_id, agent_id);

ALTER TABLE agents.agent_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents.agent_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agents.agent_keys
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON agents.agent_keys
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('ACTIVE', 'ACTIVE>REVOKED');

GRANT SELECT, INSERT ON agents.agent_keys TO agentx_app;
GRANT UPDATE (
  agent_id, status, scopes, secret_mac, secret_key_version, expires_at, state_version, state_event_id
) ON agents.agent_keys TO agentx_app;
GRANT SELECT ON agents.agent_keys TO agentx_backup;
