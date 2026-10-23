-- The supplier's remittance email (Phase 4 C2b; partner decision 34a/c,
-- S139): once a payment to it SUCCEEDED, the supplier is emailed the payer's
-- name, the invoice number, the bank reference and the amount, at most once
-- a payment, only while its setting (0061) is `on`.
--
-- Two notice kinds, each `aboutId` the payment's transaction:
-- - `payment_remittance`, to the supplier itself: written in the transaction
--   that moves the payment to SUCCEEDED, to no person and no contact; the
--   sender reads the address from the supplier version the instruction names,
--   and the setting, at send time. One a transaction (`one_remittance_a_payment`).
-- - `payment_remittance_no_email`, to the organisation's admins: written by
--   the sender in place of the first when that version holds no email
--   (decision 34c), so they know the supplier wasn't told.

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
        'payment_remittance_no_email'
      )
    ),
  ADD CONSTRAINT remittance_to_its_supplier
    CHECK (kind <> 'payment_remittance' OR (recipient_user_id IS NULL AND recipient_contact_id IS NULL AND NOT to_contacts));

CREATE UNIQUE INDEX one_remittance_a_payment ON notifications.outbox (org_id, about_id) WHERE kind = 'payment_remittance';
