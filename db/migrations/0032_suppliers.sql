-- An organisation's suppliers (PRD §3 `Supplier` / `SupplierVersion`,
-- ADR-012 §1, §2, ADR-014 §3; BR-04, BR-21; Phase 1 E1-1): the businesses its
-- agents may ask to pay. The suppliers module owns both tables (ADR-004), in
-- a schema of its own.
--
-- suppliers.suppliers is a supplier: a tenant table and an authority table
-- (ADR-012 §2), since a payment will rest on it; the ninth, at the
-- supplier's level in the lock order (ADR-006 §6: 6). Sealed (they must
-- equal the supplier's latest signed event):
-- - `status`: UNVERIFIED until a second person verifies it (E3), VERIFIED,
--   or SUSPENDED by the business (the brake) and back. Any change of its
--   details takes it back to UNVERIFIED. The status guard holds the moves.
-- - `current_version_id`: the version payments use; `pending_version_id`, a
--   change waiting for its step-up and verification (E2, E3).
-- - `cooling_off_until`, `verified_by` (the verifier's membership) and
--   `verified_version_id`, the version that was verified.
-- - `payee_key` and `payee_key_version` (ADR-014 §3, E2): the partner's
--   stable identity for the payee, or our keyed fingerprint with its key's
--   version; none until a payee is registered.
-- So an owner who verifies a supplier past the app, points it at another
-- version, cuts its cooling-off short or swaps its payee is caught at the
-- next read.
--
-- A supplier is VERIFIED only on the version that was verified, with no
-- change waiting (`verified_rests_on_its_version`): so a supplier suspended
-- before it was ever verified can't come back VERIFIED, and a new current
-- version can't be put in place while it is VERIFIED. The app unverifies it
-- first, and clears what was verified as it does.
--
-- suppliers.supplier_versions is one version of a supplier's details, made
-- once and never changed: a change of details is a new version. Also an
-- authority table, so its supplier, its number and everything it says are
-- sealed: the name, which contact kinds it holds, since when its phone is
-- the one it has (`phone_since`: carried from the version before while the
-- phone is the same, so a call-back's "unchanged for 30 days" reads one
-- field, E3), the independent source the details were checked against (a
-- registry or the official website, and its reference, ADR-012 §1), who
-- entered it and when, and (E2) the beneficiary registration that gave its
-- payee reference, the reference and the partner's masked hint (never an
-- account number, ADR-014 §3). Its contacts (a phone, required; an email and
-- a trade licence number, optional) are encrypted with AES-256-GCM under one
-- key version, with the organisation, the version and the contact's kind as
-- associated data (ADR-011 §2): so a contact copied to another kind, version
-- or organisation won't open. `contacts` (sealed) says which it holds, so
-- one taken away is caught.
--
-- A version is made once: `made_once` refuses any change to one whose first
-- signed state is recorded, so the app's rights on its sealed columns (which
-- the audit module's record needs to write them, once) change nothing after.
-- The live schema guard holds the trigger as it holds the status guard.
--
-- A version belongs to its supplier (a foreign key on the pair), and a
-- supplier's versions to it: its current, pending and verified versions are
-- its own. The supplier's row names its first version before that version
-- exists, in the same transaction, so that one key is checked at commit. The
-- member who entered a version and the verifier are memberships' IDs with no
-- foreign key: the module may not reach into identity's tables (ADR-004's
-- map), so the use case checks the membership, as for an agent's owner.
--
-- The app adds rows and reads them, and changes only the sealed fields and
-- the two signed-state columns, which the audit module's record writes and
-- seals together (a version's, only as it is made). Never a key, a supplier
-- a version belongs to or a creation time outside the seal, and never
-- deletes (a supplier deleted and added again would be born with no
-- history). The backup role reads everything, as it must for a logical
-- backup.

-- The made-once guard: like the status guard (0004), no rights of its own, no
-- EXECUTE granted, its search_path pg_catalog alone, and refusing to run as
-- anything but a BEFORE UPDATE trigger for each row. It never changes the
-- row: its verdict is all it gives. Named to sort before `status_guard`, so a
-- table with both runs it first.
CREATE FUNCTION state_rules.guard_made_once() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'state_rules.guard_made_once must run BEFORE UPDATE, FOR EACH ROW'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  -- Its first signed state recorded, the row is made: nothing in it changes again.
  IF OLD.state_event_id IS NOT NULL THEN
    RAISE EXCEPTION 'a row in %.% is made once and never changed', TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = 'check_violation', CONSTRAINT = 'made_once';
  END IF;
  RETURN NEW;
END;
$$;

CREATE SCHEMA suppliers;
GRANT USAGE ON SCHEMA suppliers TO agentx_app, agentx_backup;

CREATE TABLE suppliers.suppliers (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('UNVERIFIED', 'VERIFIED', 'SUSPENDED')),
  current_version_id uuid NOT NULL,
  pending_version_id uuid,
  cooling_off_until timestamptz CHECK (pg_catalog.isfinite(cooling_off_until)),
  verified_by uuid,
  verified_version_id uuid,
  payee_key text CHECK (payee_key ~ '^[!-~]{1,128}$'),
  payee_key_version integer CHECK (payee_key_version >= 1),
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT a_key_version_with_its_key CHECK (payee_key_version IS NULL OR payee_key IS NOT NULL),
  CONSTRAINT pending_is_not_current CHECK (pending_version_id IS DISTINCT FROM current_version_id),
  CONSTRAINT verified_rests_on_its_version CHECK (
    status <> 'VERIFIED'
    OR (verified_version_id IS NOT NULL AND verified_version_id = current_version_id AND pending_version_id IS NULL)
  )
);

-- The budget's count (E1-2): the suppliers an organisation added since a time.
CREATE INDEX suppliers_by_creation ON suppliers.suppliers (org_id, created_at);

ALTER TABLE suppliers.suppliers ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppliers.suppliers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON suppliers.suppliers
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON suppliers.suppliers
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'UNVERIFIED', 'UNVERIFIED>VERIFIED', 'VERIFIED>UNVERIFIED', 'UNVERIFIED>SUSPENDED', 'VERIFIED>SUSPENDED',
    'SUSPENDED>UNVERIFIED', 'SUSPENDED>VERIFIED'
  );

GRANT SELECT, INSERT ON suppliers.suppliers TO agentx_app;
GRANT UPDATE (
  status, current_version_id, pending_version_id, cooling_off_until, verified_by, verified_version_id, payee_key,
  payee_key_version, state_version, state_event_id
) ON suppliers.suppliers TO agentx_app;
GRANT SELECT ON suppliers.suppliers TO agentx_backup;

CREATE TABLE suppliers.supplier_versions (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  supplier_id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  display_name text NOT NULL CHECK (pg_catalog.char_length(display_name) BETWEEN 1 AND 100),
  contacts text NOT NULL CHECK (contacts IN ('phone', 'phone email', 'phone licence', 'phone email licence')),
  phone_ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(phone_ciphertext) BETWEEN 29 AND 1024),
  email_ciphertext bytea CHECK (pg_catalog.octet_length(email_ciphertext) BETWEEN 29 AND 1024),
  licence_ciphertext bytea CHECK (pg_catalog.octet_length(licence_ciphertext) BETWEEN 29 AND 1024),
  contacts_key_version integer NOT NULL CHECK (contacts_key_version >= 1),
  phone_since timestamptz NOT NULL,
  source_kind text NOT NULL CHECK (source_kind IN ('registry', 'official_website')),
  source_ref text NOT NULL CHECK (source_ref ~ '^[!-~]{1,200}$'),
  entered_by uuid NOT NULL,
  entered_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(entered_at)),
  registration_id uuid,
  beneficiary_ref text CHECK (beneficiary_ref ~ '^[!-~]{1,128}$'),
  payee_hint text CHECK (pg_catalog.char_length(payee_hint) BETWEEN 1 AND 40 AND payee_hint !~ '[[:cntrl:]]'),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_number_a_version UNIQUE (org_id, supplier_id, version),
  CONSTRAINT its_suppliers_own UNIQUE (org_id, supplier_id, id),
  CONSTRAINT of_a_supplier FOREIGN KEY (org_id, supplier_id) REFERENCES suppliers.suppliers (org_id, id),
  -- The kinds it holds are the contacts it has: none taken away, none planted.
  CONSTRAINT contacts_as_held CHECK (
    (email_ciphertext IS NOT NULL) = (contacts IN ('phone email', 'phone email licence'))
    AND (licence_ciphertext IS NOT NULL) = (contacts IN ('phone licence', 'phone email licence'))
  ),
  -- Its phone was the supplier's from a time no later than the version was entered.
  CONSTRAINT phone_since_it_was_entered CHECK (pg_catalog.isfinite(phone_since) AND phone_since <= entered_at),
  -- A payee reference comes with the registration that gave it (ADR-014 §3).
  CONSTRAINT a_reference_with_its_registration CHECK (
    (beneficiary_ref IS NULL OR registration_id IS NOT NULL) AND (payee_hint IS NULL OR beneficiary_ref IS NOT NULL)
  )
);

ALTER TABLE suppliers.supplier_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppliers.supplier_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON suppliers.supplier_versions
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER made_once BEFORE UPDATE ON suppliers.supplier_versions
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_made_once();

-- A supplier's current, pending and verified versions are its own. The
-- current one is checked at commit, since the supplier names its first
-- version before that version is added.
ALTER TABLE suppliers.suppliers
  ADD CONSTRAINT current_is_its_own FOREIGN KEY (org_id, id, current_version_id)
    REFERENCES suppliers.supplier_versions (org_id, supplier_id, id) DEFERRABLE INITIALLY DEFERRED,
  ADD CONSTRAINT pending_is_its_own FOREIGN KEY (org_id, id, pending_version_id)
    REFERENCES suppliers.supplier_versions (org_id, supplier_id, id),
  ADD CONSTRAINT verified_is_its_own FOREIGN KEY (org_id, id, verified_version_id)
    REFERENCES suppliers.supplier_versions (org_id, supplier_id, id);

GRANT SELECT, INSERT ON suppliers.supplier_versions TO agentx_app;
-- Only as the audit module's record seals a new version: `made_once` refuses any change after.
GRANT UPDATE (
  supplier_id, version, display_name, contacts, phone_since, source_kind, source_ref, entered_by, entered_at,
  registration_id, beneficiary_ref, payee_hint, state_version, state_event_id
) ON suppliers.supplier_versions TO agentx_app;
GRANT SELECT ON suppliers.supplier_versions TO agentx_backup;
