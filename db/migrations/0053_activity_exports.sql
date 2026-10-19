-- The activity log's background downloads (Phase 3 L5c; partner decision 31):
-- a range longer than one instant download holds (50,000 requests), up to 366
-- days, built in the background, one compressed file a month, kept 7 days in
-- the UAE store, the asker told when it is ready (the email in words alone,
-- decision 30), each download of a file on the audit log.
--
-- - `activity_exports.exports`: one row a download asked for, its ID the
--   `access_log.export_requested` event it recorded on the organisation's
--   chain in the same transaction; its range, actor and format, and the last
--   request written when it was asked (`written_up_to`, a UUIDv7: no later
--   row is in the file, so a rebuild reads the same requests). Added once,
--   never changed.
-- - `activity_exports.files`: one row a month of the range (UTC months, the
--   first and last cut to the range). Born `waiting`; a builder claims it,
--   `building` until `building_until` (a lease it renews as it writes, so a
--   server stopped mid-file leaves it to the next); `ready` with its count,
--   size and SHA-256, or `failed` after its tries. `file_moves` allows only
--   those moves; a ready or failed file never changes again.
--
-- A download is ready once every file is, failed once one is; it expires 7
-- days after its last file was ready, worked out from `ready_at`: rows are
-- never deleted (the store deletes the files themselves, by its own rule).
-- Not the `access` schema, which is append-only (ADR-005 §9): a file's state
-- moves. Tenant tables, row security forced; the app adds rows and moves a
-- file's state columns alone.
--
-- Notice kinds: `access_log_export_ready` and `access_log_export_failed`, to
-- the admin who asked; and for L7, `access_log_exported`, Agent X's own team
-- exported the activity log for a case, to every admin (ADR-005 §6). Each
-- `aboutId` is the audit log entry it is about.

CREATE SCHEMA activity_exports;
GRANT USAGE ON SCHEMA activity_exports TO agentx_app, agentx_backup;

CREATE TABLE activity_exports.exports (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  requested_by uuid NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  range_from timestamptz NOT NULL,
  range_to timestamptz NOT NULL,
  actor_type text CHECK (actor_type IN ('user', 'agent')),
  actor_id uuid,
  format text NOT NULL CHECK (format IN ('csv', 'ndjson')),
  written_up_to uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT range_runs_forward CHECK (range_from < range_to AND range_to - range_from <= interval '366 days'),
  CONSTRAINT actor_whole CHECK ((actor_type IS NULL) = (actor_id IS NULL))
);

ALTER TABLE activity_exports.exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_exports.exports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON activity_exports.exports
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- The organisation's downloads, newest first.
CREATE INDEX exports_by_time ON activity_exports.exports (org_id, requested_at, id);

GRANT SELECT, INSERT ON activity_exports.exports TO agentx_app;
GRANT SELECT ON activity_exports.exports TO agentx_backup;

CREATE TABLE activity_exports.files (
  org_id uuid NOT NULL,
  export_id uuid NOT NULL,
  month date NOT NULL CHECK (month = pg_catalog.date_trunc('month', month)::date),
  state text NOT NULL CHECK (state IN ('waiting', 'building', 'ready', 'failed')),
  attempts smallint NOT NULL CHECK (attempts BETWEEN 0 AND 10),
  building_until timestamptz,
  requests integer CHECK (requests >= 0),
  bytes bigint CHECK (bytes > 0),
  sha256 text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  ready_at timestamptz,
  failure text CHECK (failure ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  PRIMARY KEY (org_id, export_id, month),
  FOREIGN KEY (org_id, export_id) REFERENCES activity_exports.exports (org_id, id),
  CONSTRAINT building_has_its_lease CHECK ((state = 'building') = (building_until IS NOT NULL)),
  CONSTRAINT ready_has_its_facts CHECK (
    (state = 'ready') = (requests IS NOT NULL AND bytes IS NOT NULL AND sha256 IS NOT NULL AND ready_at IS NOT NULL)
    AND (state = 'ready' OR (requests IS NULL AND bytes IS NULL AND sha256 IS NULL AND ready_at IS NULL))
  ),
  CONSTRAINT failed_has_its_reason CHECK ((state = 'failed') = (failure IS NOT NULL))
);

ALTER TABLE activity_exports.files ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_exports.files FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON activity_exports.files
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- The builder's next file: a waiting one, or one whose builder's lease ran out.
CREATE INDEX files_to_build ON activity_exports.files (org_id, state, building_until)
  WHERE state IN ('waiting', 'building');

CREATE FUNCTION activity_exports.guard_file() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'UPDATE')
     OR TG_TABLE_SCHEMA <> 'activity_exports' OR TG_TABLE_NAME <> 'files' THEN
    RAISE EXCEPTION 'activity_exports.guard_file must run BEFORE INSERT OR UPDATE, FOR EACH ROW, on activity_exports.files'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state IS DISTINCT FROM 'waiting' OR NEW.attempts IS DISTINCT FROM 0 THEN
      RAISE EXCEPTION 'a file is born waiting, never tried'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'file_moves';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.state IN ('ready', 'failed') THEN
    RAISE EXCEPTION 'a % file never changes again', OLD.state
      USING ERRCODE = 'check_violation', CONSTRAINT = 'file_moves';
  END IF;
  -- A try is counted by a claim alone, one a claim: from waiting, or over a builder whose lease ran out.
  IF OLD.state = 'waiting' AND NEW.state = 'building' AND NEW.attempts IS DISTINCT FROM OLD.attempts + 1 THEN
    RAISE EXCEPTION 'a claim counts one try'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'file_moves';
  END IF;
  IF NEW.attempts IS DISTINCT FROM OLD.attempts AND NOT (
    NEW.attempts = OLD.attempts + 1 AND NEW.state = 'building'
    AND (OLD.state = 'waiting' OR OLD.building_until < pg_catalog.clock_timestamp())
  ) THEN
    RAISE EXCEPTION 'a try is counted by a claim alone'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'file_moves';
  END IF;
  IF (OLD.state, NEW.state) NOT IN (
    ('waiting', 'building'), ('building', 'building'), ('building', 'waiting'),
    ('building', 'ready'), ('building', 'failed')
  ) THEN
    RAISE EXCEPTION 'a file does not move from % to %', OLD.state, NEW.state
      USING ERRCODE = 'check_violation', CONSTRAINT = 'file_moves';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER file_moves BEFORE INSERT OR UPDATE ON activity_exports.files
  FOR EACH ROW EXECUTE FUNCTION activity_exports.guard_file();

GRANT SELECT, INSERT ON activity_exports.files TO agentx_app;
GRANT UPDATE (state, attempts, building_until, requests, bytes, sha256, ready_at, failure)
  ON activity_exports.files TO agentx_app;
GRANT SELECT ON activity_exports.files TO agentx_backup;

ALTER TABLE notifications.outbox DROP CONSTRAINT outbox_kind_check;
ALTER TABLE notifications.outbox
  ADD CONSTRAINT outbox_kind_check
    CHECK (
      kind IN (
        'role_granted',
        'member_rejoined',
        'member_removed',
        'role_removed',
        'contact_added',
        'contact_removed',
        'second_factor_removed',
        'second_factor_added',
        'password_changed',
        'sign_in_email_changed',
        'sign_in_blocked',
        'sign_in_restored',
        'factor_reset_link',
        'factor_reset_asked',
        'factor_reset_confirmed',
        'factor_reset_cancelled',
        'factor_reset_expired',
        'factor_reset_completed',
        'supplier_reactivated',
        'supplier_payee_changed',
        'supplier_details_changed',
        'supplier_verified',
        'supplier_suspended',
        'agent_handed_over',
        'agent_handed_to_you',
        'mandate_accepted',
        'mandate_suspended',
        'mandate_resumed',
        'mandate_revoked',
        'mandate_expired',
        'organization_policy_changed',
        'mandate_policy_changed',
        'spend_request_waiting',
        'organization_frozen',
        'organization_unfrozen',
        'audit_log_exported',
        'access_log_export_ready',
        'access_log_export_failed',
        'access_log_exported'
      )
    );
