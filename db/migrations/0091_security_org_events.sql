-- An organisation's own security events (Phase 6 6E1b, CO7b; BR-16, BR-18;
-- ADR-005 §2, ADR-011 §7, ADR-013): the rate-limit hits and failed step-ups
-- of the people and agents verified in it, shown to its admins.
--
-- `security.events` (0012) stays global: most of what it counts happens
-- before anyone is known (a sign-in that failed, an address over its limit, a
-- partner's message refused), and no organisation may ever see those. An
-- event the API can tie to one organisation (a member's request once their
-- membership there is found active, an agent's by the organisation its key
-- belongs to) is written here instead, never in both. The wall is the
-- database's own: a tenant table with forced row-level security and the one
-- tenant policy, so an organisation's read reaches its own rows alone, and a
-- read with no organisation set reaches none. CI-06 refuses a view or a
-- policy on a global table, so a filtered view of 0012 was not an option.
-- Rows already in 0012 are left there, organisation-less, and never shown.
--
-- The columns are 0012's, with the organisation, and the agent where one was
-- refused (its rate limit or its organisation's): one row a count of one
-- kind, reason, address, person or agent, in one minute. The address is a
-- clue, never proof (decision 26), kept in-country, here alone.
--
-- Kept for the same retention (AGENTX_SECURITY_EVENT_RETENTION_DAYS), then
-- each organisation's rows are swept inside its own transaction once a UTC
-- day. The app adds rows, reads them and deletes them; it never changes one.
-- The backup role reads it, as it reads everything.

CREATE TABLE security.org_events (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  -- A step-up that failed is a `sign_in_failed`; a partner's refused message is never an organisation's.
  kind text NOT NULL CHECK (kind IN ('sign_in_failed', 'rate_limited')),
  reason text NOT NULL CHECK (reason ~ '^[a-z][a-z_]{0,63}$'),
  ip inet,
  -- The person, or the agent, the event is about; at most one of them.
  user_id uuid,
  agent_id uuid,
  window_start timestamptz NOT NULL,
  count integer NOT NULL CHECK (count >= 1),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (org_id, id),
  CONSTRAINT org_events_one_actor CHECK (user_id IS NULL OR agent_id IS NULL),
  CONSTRAINT org_events_window_before_it_is_written CHECK (window_start <= created_at)
);

ALTER TABLE security.org_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.org_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON security.org_events
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- A page by time, newest first (the admins' page), and the sweep's oldest first.
CREATE INDEX org_events_by_time ON security.org_events (org_id, window_start, id);

GRANT SELECT, INSERT, DELETE ON security.org_events TO agentx_app;
GRANT SELECT ON security.org_events TO agentx_backup;
