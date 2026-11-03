-- A payment the bank says it can't find, told to its organisation (4D2e;
-- partner S170, decision 38): one handed to the bank (SUBMITTED or
-- PROCESSING) that its check still can't find past UNKNOWN_AFTER_MS. Kept in
-- the organisation's audit log (`payment.bank_lost`) and every admin is
-- emailed once a payment, in the same transaction as the bank's word that
-- raised it, by the path 0065's alerts take.
--
-- Notice kind: `payment_bank_lost`, to every admin, `aboutId` the payment's
-- transaction.

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
        'supplier_remittance_changed',
        'payment_remittance',
        'payment_remittance_no_email',
        'payment_marked_failed',
        'payment_contradicted',
        'payment_unproven',
        'payment_still_unknown',
        'payment_mark_proposed',
        'payment_mark_withdrawn',
        'payment_mark_ended',
        'payment_bank_lost'
      )
    );
