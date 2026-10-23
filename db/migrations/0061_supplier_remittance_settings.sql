-- Whether a supplier is emailed when it is paid (Phase 4 C2a; partner
-- decision 34b, S139): the remittance email, with the invoice number, the
-- bank reference it became and the amount (decision 8, S93), is sent once a
-- payment to it SUCCEEDED (C2b), only while its setting is `on`.
--
-- suppliers.remittance_settings is a supplier's setting: an authority table
-- (ADR-012 §2), since it decides whether Agent X writes to someone outside
-- the organisation; at the supplier's level in the lock order (ADR-006 §6:
-- 6), after its versions. Sealed: `remittance_email`, `on` or `off`. A row
-- is addressed by its organisation and its own ID, which is its supplier's
-- (`id_is_its_supplier`), as an agent's zone is its agent's (0054).
--
-- Its own table, not a field of the supplier: a change of the supplier's
-- details takes it back to UNVERIFIED (E3), and this setting must not stop
-- its payments; and the suppliers' rows already signed name no such field.
-- A supplier added from here is added with its setting, chosen by the admin
-- (Rule Book §1.9: no hidden default; `on` offered first). One added before
-- has no row: it is read as `on`, the default the partner chose, until an
-- admin sets it, which adds the row. The app never deletes a row (no grant).
--
-- The app adds rows and reads them, and changes only the sealed field and the
-- two signed-state columns, which the audit module's record writes and seals
-- together. The backup role reads everything.
--
-- A change after adding goes as the supplier's other details do (decision
-- 34d): a passkey step-up, and every member and counting contact told by one
-- notice kind, `supplier_remittance_changed`, `aboutId` the supplier's ID.

CREATE TABLE suppliers.remittance_settings (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  remittance_email text NOT NULL CHECK (remittance_email IN ('on', 'off')),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT id_is_its_supplier FOREIGN KEY (org_id, id) REFERENCES suppliers.suppliers (org_id, id)
);

ALTER TABLE suppliers.remittance_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppliers.remittance_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON suppliers.remittance_settings
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON suppliers.remittance_settings TO agentx_app;
GRANT UPDATE (remittance_email, state_version, state_event_id) ON suppliers.remittance_settings TO agentx_app;
GRANT SELECT ON suppliers.remittance_settings TO agentx_backup;

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
        'access_log_exported',
        'handoff_paused',
        'handoff_resumed',
        'spend_request_stopped',
        'supplier_remittance_changed'
      )
    );
