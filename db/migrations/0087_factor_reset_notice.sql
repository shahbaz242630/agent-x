-- OR2 (playbook K; CF Before production "The only-admin runbook's tools"): Agent
-- X's own team resetting a person's second factor, when no admin can ask the
-- product's own reset (the organisation's only admin lost theirs, or the person
-- is in more than one organisation), tells every member of the organisation,
-- and its registered contacts that count now, that it is under way: anyone may
-- stop it within the 24 hours the team waits. Written by the operator's
-- factor-reset-notice, in the same transaction as its entry on the
-- organisation's audit log and the platform's; sent by the API's sender, which
-- finds the members and the contacts as it sends, as for a notice about a
-- supplier.
--
-- Notice kind: `factor_reset_by_support`, `aboutId` the person's user ID.
--
-- The new list is checked against every row the outbox holds as it is made: the
-- outbox keeps 30 days of notices (OUTBOX_RETENTION_DAYS), as each notice kind
-- before this one did (0071). The operator's role may already add notices
-- (0079); no right changes.

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
        'payment_bank_lost',
        'factor_reset_by_support'
      )
    );
