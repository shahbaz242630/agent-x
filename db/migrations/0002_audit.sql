-- The audit module's tables (ADR-004, ADR-011 §3, ADR-012 §2): every
-- organisation's audit trail, one hash-chained line of events each, sealed by
-- the app with keys the database never holds.
--
-- Both tables are tenant tables, behind the tenant policy. The schema is
-- append-only for the app (ADR-005 §9, SEC-EVD-01): it may add events and read
-- them, never change or delete one. The chain head is the exception, on the
-- CI-06 list: the app locks it and moves it on with every event.
--
-- The backup role reads everything, as it must for a logical backup.

CREATE SCHEMA audit;
GRANT USAGE ON SCHEMA audit TO agentx_app, agentx_backup;

-- One row per event. The seal (prev_hash, hash, mac) is computed by the app
-- over the other columns; see packages/platform/src/audit-chain. The details
-- are the exact JSON text that was sealed, kept as text: jsonb would rewrite
-- it, and a change that keeps its meaning must still show. The checks here
-- only keep honest mistakes out: someone with the owner's rights can drop
-- them, which is why the app checks every event, and counts them all.
CREATE TABLE audit.events (
  org_id uuid NOT NULL,
  seq bigint NOT NULL CHECK (seq >= 1),
  id uuid NOT NULL,
  recorded_at timestamptz NOT NULL,
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  action text NOT NULL,
  subject_type text NOT NULL,
  subject_id uuid NOT NULL,
  subject_version integer NOT NULL CHECK (subject_version >= 1),
  details text NOT NULL CHECK (pg_catalog.jsonb_typeof(details::jsonb) = 'object'),
  prev_hash bytea NOT NULL CHECK (pg_catalog.octet_length(prev_hash) = 32),
  hash bytea NOT NULL CHECK (pg_catalog.octet_length(hash) = 32),
  mac bytea NOT NULL,
  mac_key_version integer NOT NULL,
  PRIMARY KEY (org_id, seq),
  UNIQUE (org_id, id)
);

ALTER TABLE audit.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.events
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON audit.events TO agentx_app;
GRANT SELECT ON audit.events TO agentx_backup;

-- One row per organisation: the chain's last event number and hash, and their
-- MAC. Locked last by every transaction that records an event (ADR-006 §6),
-- then moved on: the app may change those four columns, never the organisation.
CREATE TABLE audit.heads (
  org_id uuid NOT NULL PRIMARY KEY,
  seq bigint NOT NULL CHECK (seq >= 0),
  hash bytea NOT NULL CHECK (pg_catalog.octet_length(hash) = 32),
  mac bytea NOT NULL,
  mac_key_version integer NOT NULL
);

ALTER TABLE audit.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit.heads
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON audit.heads TO agentx_app;
GRANT UPDATE (seq, hash, mac, mac_key_version) ON audit.heads TO agentx_app;
GRANT SELECT ON audit.heads TO agentx_backup;
