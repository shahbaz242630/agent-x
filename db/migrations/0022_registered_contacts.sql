-- Registered contacts (ADR-012 §1, §8, ADR-003 §4; SEC-OPS-06; Phase 1
-- B6-1a): an organisation's own contacts, by email address, that it names as
-- its trust anchor. They are told of the changes that matter (a payee
-- changed, their own list changed) and they confirm a lost second factor's
-- reset (B6-3). The identity module owns them (ADR-004), beside the
-- invitations and step-up they are made with.
--
-- identity.registered_contacts is a tenant table, behind the tenant policy,
-- and an authority table (ADR-012 §2), since a contact confirms a reset: its
-- status, the admin who added it (by their membership), when it starts to
-- count, and the step-up challenge opened for it must equal its latest signed
-- event. So an owner who plants a contact, brings a removed one back, or
-- moves one's start earlier is caught at the next read. It is on the
-- product's authority-table list (packages/core/src/authority-tables.ts).
--
-- An admin adds one with step-up: it starts as a DRAFT, the pending change
-- the step-up binds to (ADR-003 §9 step 1), and becomes ACTIVE once the
-- step-up is consumed, when its start (`counts_from`) is set: a cooling-off
-- after that moment, so a contact put in by someone who took over an admin's
-- session counts for nothing until the old contacts have been told and had
-- time to act (SEC-OPS-06). Removing one needs step-up too (ACTIVE>REMOVED).
-- A contact is never changed in place: a new address is a new contact.
--
-- A DRAFT has no start; a contact past its draft always has one, written just
-- before the status moves, in the same transaction. The status has one CHECK,
-- its machine's states (A3c), so that rule is the module's and the seal's: a
-- start the app never wrote fails the row's signed state.
--
-- The address is kept encrypted (ADR-011 §2), with the organisation and the
-- contact as its associated data, so a value copied to another row or
-- organisation won't open. It is written once, with the row, and never
-- changed: the app may update only the signed fields and the two
-- signed-state columns.
--
-- The admin who added it is a membership of the same organisation (a
-- composite key, so it can't point at another organisation's).
-- The backup role reads everything, as it must for a logical backup.

CREATE TABLE identity.registered_contacts (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'REMOVED')),
  added_by uuid NOT NULL,
  counts_from timestamptz,
  step_up_challenge_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  email_ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(email_ciphertext) BETWEEN 29 AND 1024),
  email_key_version integer NOT NULL CHECK (email_key_version >= 1),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT counts_after_it_was_added CHECK (counts_from IS NULL OR counts_from > created_at),
  CONSTRAINT added_by_a_member FOREIGN KEY (org_id, added_by) REFERENCES identity.memberships (org_id, id)
);

ALTER TABLE identity.registered_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.registered_contacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity.registered_contacts
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON identity.registered_contacts
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('DRAFT', 'DRAFT>ACTIVE', 'ACTIVE>REMOVED');

GRANT SELECT, INSERT ON identity.registered_contacts TO agentx_app;
GRANT UPDATE (status, added_by, counts_from, step_up_challenge_id, state_version, state_event_id)
  ON identity.registered_contacts TO agentx_app;
GRANT SELECT ON identity.registered_contacts TO agentx_backup;
