-- The reset of a lost second factor (ADR-003 §4, ADR-012 §8; SEC-OPS-04;
-- Phase 1 B6-3a): an admin asks, with a step-up, for another member of the
-- organisation whose second factor is lost; one of the organisation's
-- registered contacts that counts confirms, out of band, by a link sent to
-- it; a cooling-off follows, in which any admin may cancel; then Agent X
-- removes the factor at the login service (B6-3c). The identity module owns
-- both tables (ADR-004), beside the memberships and contacts they name.
--
-- identity.factor_resets is a tenant table, behind the tenant policy, and an
-- authority table (ADR-012 §2): a reset ends in a login's second factor
-- removed, so its status, whom it is for and who asked (by their
-- memberships), the step-up challenge opened for it, when it lapses, the
-- contact who confirmed it and when its cooling-off ends must equal its
-- latest signed event. An owner who plants a reset, moves one on, names
-- another person or contact, or cuts a cooling-off short is caught at the
-- next read. It is on the product's authority-table list
-- (packages/core/src/authority-tables.ts), at lock level 2c, after the
-- contacts it is confirmed by.
--
-- Its moves: DRAFT (the pending change the admin's step-up binds to) >
-- AWAITING_CONTACT (stepped up: the contacts that count are sent their
-- links) > COOLING_OFF (a contact confirmed) > COMPLETED (the factor
-- removed); CANCELLED by an admin from any of the first three; EXPIRED when
-- no contact confirmed before `expires_at`. A person has at most one reset
-- open at a time: the app holds that, asking under a lock for the person and
-- reading their open resets through their signed states first (a partial
-- unique index would enforce nothing outside its condition, which the live
-- schema guard refuses). No one asks for their own: an organisation whose
-- only admin lost theirs follows the runbook (ADR-003 §4).
--
-- A reset is confirmed and its cooling-off set together, in the same
-- transaction, so the two are null together or set together.
--
-- identity.factor_reset_confirmations holds one secret per reset and
-- contact, the one a contact's link carries: kept encrypted with
-- field-encryption (ADR-011 §2), its organisation, reset and contact as the
-- associated data, so a row planted by someone without the key won't open,
-- and a secret copied to another row won't either. Written once, never
-- changed: a confirmed reset moves on, and its links then do nothing.
-- The backup role reads everything, as it must for a logical backup.

CREATE TABLE identity.factor_resets (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('DRAFT', 'AWAITING_CONTACT', 'COOLING_OFF', 'COMPLETED', 'CANCELLED', 'EXPIRED')),
  person uuid NOT NULL,
  requested_by uuid NOT NULL,
  step_up_challenge_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  confirmed_by uuid,
  cooling_off_until timestamptz,
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT reset_lapses_after_it_was_asked CHECK (expires_at > created_at),
  CONSTRAINT no_one_resets_their_own CHECK (person <> requested_by),
  CONSTRAINT confirmed_with_its_cooling_off CHECK ((confirmed_by IS NULL) = (cooling_off_until IS NULL)),
  CONSTRAINT cooling_off_after_it_was_asked CHECK (cooling_off_until IS NULL OR cooling_off_until > created_at),
  CONSTRAINT for_a_member FOREIGN KEY (org_id, person) REFERENCES identity.memberships (org_id, id),
  CONSTRAINT asked_by_a_member FOREIGN KEY (org_id, requested_by) REFERENCES identity.memberships (org_id, id),
  CONSTRAINT confirmed_by_a_contact FOREIGN KEY (org_id, confirmed_by) REFERENCES identity.registered_contacts (org_id, id)
);

-- A person's resets, found when another is asked for.
CREATE INDEX factor_resets_by_person ON identity.factor_resets (org_id, person);

ALTER TABLE identity.factor_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.factor_resets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity.factor_resets
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON identity.factor_resets
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'DRAFT',
    'DRAFT>AWAITING_CONTACT',
    'AWAITING_CONTACT>COOLING_OFF',
    'COOLING_OFF>COMPLETED',
    'DRAFT>CANCELLED',
    'AWAITING_CONTACT>CANCELLED',
    'COOLING_OFF>CANCELLED',
    'DRAFT>EXPIRED',
    'AWAITING_CONTACT>EXPIRED'
  );

GRANT SELECT, INSERT ON identity.factor_resets TO agentx_app;
GRANT UPDATE (
  status, person, requested_by, step_up_challenge_id, expires_at, confirmed_by, cooling_off_until,
  state_version, state_event_id
) ON identity.factor_resets TO agentx_app;
GRANT SELECT ON identity.factor_resets TO agentx_backup;

CREATE TABLE identity.factor_reset_confirmations (
  org_id uuid NOT NULL,
  reset_id uuid NOT NULL,
  contact_id uuid NOT NULL,
  secret_ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(secret_ciphertext) BETWEEN 29 AND 1024),
  secret_key_version integer NOT NULL CHECK (secret_key_version >= 1),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (org_id, reset_id, contact_id),
  CONSTRAINT for_a_reset FOREIGN KEY (org_id, reset_id) REFERENCES identity.factor_resets (org_id, id),
  CONSTRAINT to_a_contact FOREIGN KEY (org_id, contact_id) REFERENCES identity.registered_contacts (org_id, id)
);

ALTER TABLE identity.factor_reset_confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.factor_reset_confirmations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity.factor_reset_confirmations
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON identity.factor_reset_confirmations TO agentx_app;
GRANT SELECT ON identity.factor_reset_confirmations TO agentx_backup;
