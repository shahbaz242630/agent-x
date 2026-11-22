-- S210 (the R2 review): the login's phone number changed at the login service
-- (Zitadel's `user.human.phone.changed`, read from the pinned image's binary)
-- is a change to how a person signs in: codes sent by SMS go to the new number
-- from then on. It is copied as the email's change is (idp-event.ts), and told
-- to the person and their organisations' admins as a sign-in notice.
--
-- Notice kind: `sign_in_phone_changed`, `aboutId` the person's user ID.
--
-- The new list is checked against every row the outbox holds as it is made: the
-- outbox keeps 30 days of notices (OUTBOX_RETENTION_DAYS), as each notice kind
-- before this one did (0087). No right changes. The image before this
-- migration never writes the new kind, so it reads and writes on.

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
        'sign_in_phone_changed',
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
        'payment_bank_lost',
        'factor_reset_by_support'
      )
    );
