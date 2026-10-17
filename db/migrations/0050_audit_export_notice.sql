-- Agent X's own team exported an organisation's audit log for a case (a
-- dispute or a regulator's request), told to every admin of the organisation
-- (Phase 3 E10c; partner decision 24, ADR-005 §6's second exception). One
-- notice kind: audit_log_exported, `aboutId` the `audit_log.exported` event
-- the export recorded on the organisation's own chain, written in the same
-- transaction as that event. The email names the entry by its ID alone: the
-- case reference, the dates and the count are read in the audit log, signed
-- in, as the activity log is for admins only (decision 26).

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
        'audit_log_exported'
      )
    );
