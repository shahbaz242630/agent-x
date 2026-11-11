-- A membership's grant summary (OR1; ADR-012 §1, SEC-PAY-04; CF Phase 1
-- E3-1 (b)): who granted or confirmed the membership's role, and when it last
-- stopped being a verifier's, signed, so the two-person rule reads one row a
-- member rather than the organisation's whole history of memberships and
-- invitations (until now capped at 10,000 events, failing closed past it).
--
-- identity.membership_grants is a membership's own: an authority table
-- (ADR-012 §2), since the rule's verdict on who may verify a supplier or
-- confirm a payment mark rests on it; at the membership's level in the lock
-- order (ADR-006 §6: 2a), after its membership. A row is addressed by its
-- organisation and its own ID, which is its membership's (`id_is_its_membership`),
-- as a supplier's remittance setting is its supplier's (0061). Sealed:
-- - `granted_by`: the people (user IDs, lower case, sorted, comma-joined;
--   empty for none) who granted or confirmed the role, by adding, inviting,
--   opening or confirming the invitation, bringing the member back, or changing
--   the role; never the member themselves
-- - `verifier_changed_at`: when the membership, an admin's or approver's, was
--   last deactivated or had its role changed; null for never
-- - `membership_version`: the membership's signed version it was kept in step
--   with, so a summary left behind by a change of its membership (or a
--   membership moved past it) disagrees with it at the next read
-- Each membership change writes it in the same transaction as the change.
--
-- A membership added before this migration has no row yet, and the rule reads
-- the history for its organisation as it always has, until the API's job
-- builds and signs the row from that history (signing takes the app's keys, so
-- no SQL can). A row once built is never missing: one deleted is found by its
-- signed state.
--
-- The app adds rows and reads them, and changes only the sealed fields and the
-- two signed-state columns, which the audit module's record writes and seals
-- together; never its key, and never deletes (no grant). The backup role reads
-- everything.

CREATE TABLE identity.membership_grants (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  granted_by text NOT NULL
    CHECK (granted_by ~ '^([0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}(,[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12})*)?$'),
  verifier_changed_at timestamptz CHECK (pg_catalog.isfinite(verifier_changed_at)),
  membership_version integer NOT NULL CHECK (membership_version >= 1),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  -- No role but the owner can delete a membership; one deleted takes its summary with it, and each is then found
  -- by its own signed state, as before (`deleted`).
  CONSTRAINT id_is_its_membership FOREIGN KEY (org_id, id) REFERENCES identity.memberships (org_id, id)
    ON DELETE CASCADE
);

ALTER TABLE identity.membership_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.membership_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity.membership_grants
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON identity.membership_grants TO agentx_app;
GRANT UPDATE (granted_by, verifier_changed_at, membership_version, state_version, state_event_id)
  ON identity.membership_grants TO agentx_app;
GRANT SELECT ON identity.membership_grants TO agentx_backup;
