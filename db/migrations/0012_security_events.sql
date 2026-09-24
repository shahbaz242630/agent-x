-- Security events (ADR-005 §6, ADR-011 §7; Phase 1 B2-5): failed sign-ins
-- and rate-limit hits, with the client's IP address. They happen before any
-- organisation is known, so the table is global, on the CI-06 list with its
-- reason, its exact columns and the app's rights on it.
--
-- An IP address is personal data. It is kept here, in-country, and nowhere
-- else: never in a log line (ADR-011 §7, ADR-013). A row is kept for the
-- retention period the config names (AGENTX_SECURITY_EVENT_RETENTION_DAYS, 30
-- days at least), then the API's hourly sweep deletes it.
--
-- One row counts the events of one kind, reason, address and person in one
-- window of time, so a flood of refusals is a count that grows, never a row
-- per request (B2-5b writes them a batch at a time).
--
-- The app adds rows, reads them and deletes them once past their retention;
-- it never changes one. The backup role reads it, as it reads everything.

CREATE SCHEMA security;
GRANT USAGE ON SCHEMA security TO agentx_app, agentx_backup;

CREATE TABLE security.events (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('sign_in_failed', 'rate_limited')),
  -- Why, in the kind's own words: a sign-in's failed step, or the limit hit.
  reason text NOT NULL CHECK (reason ~ '^[a-z][a-z_]{0,63}$'),
  -- The client's address as the API saw it (behind the trusted proxies);
  -- null if it had none it could read.
  ip inet,
  -- The person, when the event is about a signed-in one.
  user_id uuid,
  window_start timestamptz NOT NULL,
  count integer NOT NULL CHECK (count >= 1),
  created_at timestamptz NOT NULL,
  CONSTRAINT window_before_it_is_written CHECK (window_start <= created_at)
);

-- The sweep takes the oldest first.
CREATE INDEX events_by_age ON security.events (created_at);

GRANT SELECT, INSERT, DELETE ON security.events TO agentx_app;
GRANT SELECT ON security.events TO agentx_backup;
