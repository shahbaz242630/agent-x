-- API idempotency (ADR-007 §4, PRD §7.2): each write that carries an
-- idempotency key is done once. The app's step is
-- packages/platform/src/db/idempotency.ts: it claims a row here first in the
-- write's own transaction (ADR-006 §6, lock order 0), does the write, and
-- records its result on the row, all in that one transaction. A second
-- request with the same key waits on the primary key until the first
-- transaction ends, then reads the row the first committed.
--
-- A key belongs to one organisation, one client (a user or an agent) and one
-- operation, so the primary key is all four with the key: another client's
-- key, or the same key on another operation, is another row.
--
-- What the first request asked for is kept only as a keyed hash (HMAC, the
-- app's `request-hash` key, which the database never holds) with that key's
-- version (ADR-014 §3): a request may carry bank details, and a plain hash of
-- them could be guessed offline from a copy of this table. The request itself
-- is never stored.
--
-- A tenant table, behind the tenant policy. The app adds rows, reads them,
-- and fills in a row's result once; it never changes a key or a hash, and
-- never deletes (the retention sweep, which needs the list of organisations,
-- comes with them). The backup role reads everything, as it must for a
-- logical backup.
--
-- The checks here only keep honest mistakes out; the app checks the same and
-- more before it writes.

CREATE SCHEMA idempotency;
GRANT USAGE ON SCHEMA idempotency TO agentx_app, agentx_backup;

CREATE TABLE idempotency.keys (
  org_id uuid NOT NULL,
  client_kind text NOT NULL CHECK (client_kind IN ('user', 'agent')),
  client_id uuid NOT NULL,
  operation text NOT NULL CHECK (pg_catalog.octet_length(operation) BETWEEN 1 AND 64),
  key text NOT NULL CHECK (pg_catalog.octet_length(key) BETWEEN 1 AND 255),
  request_hash bytea NOT NULL CHECK (pg_catalog.octet_length(request_hash) = 32),
  request_hash_key_version integer NOT NULL CHECK (request_hash_key_version >= 1),
  created_at timestamptz NOT NULL,
  -- The write's answer: its status and the resource it made or changed. Empty
  -- only inside the claiming transaction, which fills both before it commits.
  result_status integer CHECK (result_status BETWEEN 200 AND 299),
  result_id uuid,
  CHECK ((result_status IS NULL) = (result_id IS NULL)),
  PRIMARY KEY (org_id, client_kind, client_id, operation, key)
);

ALTER TABLE idempotency.keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency.keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idempotency.keys
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON idempotency.keys TO agentx_app;
GRANT UPDATE (result_status, result_id) ON idempotency.keys TO agentx_app;
GRANT SELECT ON idempotency.keys TO agentx_backup;
