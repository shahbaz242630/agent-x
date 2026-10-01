-- Payee storage (ADR-014 §3; SEC-PAY-06, SEC-DB-01; Phase 1 E2-1b): the
-- registrations of a supplier's payee with the partner, the payee reference a
-- version takes from one, one supplier per payee in an organisation, and the
-- notices of a supplier's changes.
--
-- suppliers.beneficiary_registrations is a registration Agent X started with
-- the partner: a tenant table and an authority table (ADR-012 §2), since a
-- payee reference and its payee key rest on it; the eleventh, locked after
-- its supplier and before its versions (ADR-006 §6: 6). Its ID is ours, and
-- the partner's idempotency key for it. Tx 1 adds it STARTED, naming the
-- supplier, the version Tx 2 will make, the partner, the route and the member
-- who started it (a membership's ID, with no foreign key, as a version's
-- `entered_by`). How it ended is the partner's word, server to server, never
-- anything that came back through the browser (SEC-PAY-08): REGISTERED, with
-- the partner's reference, the payee key (the partner's stable identity, or
-- our fingerprint with its key's version), the name check, the bank's masked
-- name, the partner's hint (never an account number) and when; FAILED, with
-- why; or UNKNOWN, when the call was lost, until the partner is asked again
-- by our ID. Every column but its keys and creation time is sealed (it must
-- equal its latest signed event), so a payee reference or key swapped, a name
-- check changed, a failure turned into a registration or a registration moved
-- to another supplier is caught at the next read. The status guard holds the
-- moves; `registered_with_its_reference` and `failed_with_its_reason` hold
-- what each end needs (both on the authority-table list, for CI's A3c). A
-- registration has a reference or a failure, never both.
--
-- A version takes its payee reference only from a registration of its own
-- supplier (`payee_from_its_suppliers_registration`): one of another
-- supplier's, or another organisation's, is refused. Null is allowed, so the
-- key is not on the schema policy's `requiredForeignKeys`, which holds only
-- keys whose columns are NOT NULL: it is org-scoped, and sealed at both ends
-- (a version's `registration_id`, a registration's `supplier_id`). A version
-- that carries the reference of the one it follows names the same
-- registration, of the same supplier.
--
-- One supplier per payee key in an organisation, a suspended supplier
-- included (partner, S71): `one_supplier_a_payee`. Partial, so `payee_key` is
-- never a key column: Postgres counts only a full unique index's columns, and
-- one would turn the signed state's write of the key into a key update, which
-- waits behind every KEY SHARE a version's foreign key takes (ADR-006 §6). The
-- live schema guard and CI-06 accept it exactly as the schema policy lists it
-- (E2-1a), and since this migration makes it, see it missing too.
--
-- A version's reference columns keep the app's UPDATE grant (0032): the
-- audit module's record('new') writes every sealed field of a new row, these
-- among them, and `made_once` refuses any change after its first signed
-- state.
--
-- The app adds registrations and reads them, and changes only their sealed
-- fields and the two signed-state columns, which the audit module's record
-- writes. Never a key or a creation time, and never deletes (a registration
-- deleted would hide a start from the day's budget). The backup role reads
-- everything, as it must for a logical backup.
--
-- Five notices of a supplier's changes, about the supplier (sent by E2-2 and
-- E3-2): reactivated, its payee changed, its details changed, verified, and
-- suspended. The checks change; the new table and key are ones the running
-- image's live guard holds to a tenant table's rules during the release.

CREATE TABLE suppliers.beneficiary_registrations (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  supplier_id uuid NOT NULL,
  version_id uuid NOT NULL,
  partner text NOT NULL CHECK (partner ~ '^[a-z][a-z0-9_]{0,31}$'),
  route text NOT NULL CHECK (route IN ('hosted', 'pass_through')),
  started_by uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('STARTED', 'REGISTERED', 'FAILED', 'UNKNOWN')),
  beneficiary_ref text CHECK (beneficiary_ref ~ '^[!-~]{1,128}$'),
  payee_key text CHECK (payee_key ~ '^[!-~]{1,128}$'),
  payee_key_version integer CHECK (payee_key_version >= 1),
  name_check text CHECK (name_check IN ('match', 'partial', 'no_match', 'unavailable')),
  -- At most 140 characters is at most 560 bytes in UTF-8, so no byte bound of its own (B8-3).
  masked_name text CHECK (pg_catalog.char_length(masked_name) BETWEEN 1 AND 140 AND masked_name !~ '[[:cntrl:]]'),
  payee_hint text CHECK (pg_catalog.char_length(payee_hint) BETWEEN 1 AND 40 AND payee_hint !~ '[[:cntrl:]]'),
  registered_at timestamptz CHECK (pg_catalog.isfinite(registered_at)),
  failure text CHECK (failure IN ('invalid_details', 'expired', 'unknown')),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_registration_a_version UNIQUE (org_id, version_id),
  CONSTRAINT its_suppliers_registration UNIQUE (org_id, supplier_id, id),
  CONSTRAINT for_a_supplier FOREIGN KEY (org_id, supplier_id) REFERENCES suppliers.suppliers (org_id, id),
  CONSTRAINT a_key_version_with_its_key CHECK (payee_key_version IS NULL OR payee_key IS NOT NULL),
  CONSTRAINT a_reference_or_a_failure CHECK (beneficiary_ref IS NULL OR failure IS NULL),
  -- What each end needs, written before the move to it (the status is the signed state's last step).
  CONSTRAINT registered_with_its_reference CHECK (
    status <> 'REGISTERED'
    OR (beneficiary_ref IS NOT NULL AND name_check IS NOT NULL AND payee_hint IS NOT NULL AND registered_at IS NOT NULL)
  ),
  CONSTRAINT failed_with_its_reason CHECK (status <> 'FAILED' OR failure IS NOT NULL)
);

-- The budget's count: the registrations an organisation started since a time.
CREATE INDEX registrations_by_creation ON suppliers.beneficiary_registrations (org_id, created_at);

ALTER TABLE suppliers.beneficiary_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppliers.beneficiary_registrations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON suppliers.beneficiary_registrations
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON suppliers.beneficiary_registrations
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'STARTED', 'STARTED>REGISTERED', 'UNKNOWN>REGISTERED', 'STARTED>FAILED', 'UNKNOWN>FAILED', 'STARTED>UNKNOWN'
  );

GRANT SELECT, INSERT ON suppliers.beneficiary_registrations TO agentx_app;
GRANT UPDATE (
  status, supplier_id, version_id, partner, route, started_by, beneficiary_ref, payee_key, payee_key_version,
  name_check, masked_name, payee_hint, registered_at, failure, state_version, state_event_id
) ON suppliers.beneficiary_registrations TO agentx_app;
GRANT SELECT ON suppliers.beneficiary_registrations TO agentx_backup;

-- A version's payee reference comes from a registration of its own supplier.
ALTER TABLE suppliers.supplier_versions
  ADD CONSTRAINT payee_from_its_suppliers_registration FOREIGN KEY (org_id, supplier_id, registration_id)
    REFERENCES suppliers.beneficiary_registrations (org_id, supplier_id, id);

-- One supplier per payee key in an organisation, suspended ones included.
CREATE UNIQUE INDEX one_supplier_a_payee ON suppliers.suppliers (org_id, payee_key) WHERE payee_key IS NOT NULL;

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
        'supplier_suspended'
      )
    );
