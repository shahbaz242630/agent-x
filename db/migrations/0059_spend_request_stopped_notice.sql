-- An approved spend request stopped before it reached the bank, told to every
-- admin of its organisation (Phase 4 B4b; partner decision 3, S135): denied
-- by the hand-off's last check (a key ended at once, the payee changed, a
-- stop found) or by the voids job, whichever reaches it first, its holdings
-- freed. One notice kind, `spend_request_stopped`, `aboutId` the request's
-- ID, written in the same transaction as the denial and fanned out to the
-- admins as it is sent.

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
        'spend_request_stopped'
      )
    );
