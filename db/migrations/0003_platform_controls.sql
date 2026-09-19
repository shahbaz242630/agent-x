-- The platform-controls module's audit chain (ADR-004, ADR-011 §3, ADR-014
-- §8): the platform's own events, apart from every organisation's. The first
-- is the config hash each process writes at start-up (ADR-012 §6, SEC-OPS-05);
-- operator actions join it later. Sealed and checked by the app the same way
-- as the organisation chains (packages/platform/src/audit-chain).
--
-- Both tables belong to no organisation, so they are global tables, each on
-- the CI-06 list with its reason and columns. The schema is append-only for the
-- app: it may add events and read them, never change or delete one. The chain
-- head is the exception, on the CI-06 list: the app locks it and moves it on.
--
-- The backup role reads everything, as it must for a logical backup.

CREATE SCHEMA platform_controls;
GRANT USAGE ON SCHEMA platform_controls TO agentx_app, agentx_backup;

-- One row per event. The details are the exact JSON text that was sealed.
-- The checks here only keep honest mistakes out: someone with the owner's
-- rights can drop them, which is why the app checks every event, and counts
-- them all.
CREATE TABLE platform_controls.audit_events (
  seq bigint NOT NULL PRIMARY KEY CHECK (seq >= 1),
  id uuid NOT NULL UNIQUE,
  recorded_at timestamptz NOT NULL,
  actor_type text NOT NULL,
  actor_id text NOT NULL,
  action text NOT NULL,
  details text NOT NULL CHECK (pg_catalog.jsonb_typeof(details::jsonb) = 'object'),
  prev_hash bytea NOT NULL CHECK (pg_catalog.octet_length(prev_hash) = 32),
  hash bytea NOT NULL CHECK (pg_catalog.octet_length(hash) = 32),
  mac bytea NOT NULL,
  mac_key_version integer NOT NULL
);

GRANT SELECT, INSERT ON platform_controls.audit_events TO agentx_app;
GRANT SELECT ON platform_controls.audit_events TO agentx_backup;

-- The chain's one head row: its last event number and hash, and their MAC.
-- Locked last by every transaction that records an event (ADR-006 §6), then
-- moved on: the app may change those four columns only.
CREATE TABLE platform_controls.audit_head (
  only_row boolean NOT NULL PRIMARY KEY DEFAULT true CHECK (only_row),
  seq bigint NOT NULL CHECK (seq >= 0),
  hash bytea NOT NULL CHECK (pg_catalog.octet_length(hash) = 32),
  mac bytea NOT NULL,
  mac_key_version integer NOT NULL
);

GRANT SELECT, INSERT ON platform_controls.audit_head TO agentx_app;
GRANT UPDATE (seq, hash, mac, mac_key_version) ON platform_controls.audit_head TO agentx_app;
GRANT SELECT ON platform_controls.audit_head TO agentx_backup;
