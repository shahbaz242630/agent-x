-- A policy's change told to every admin and approver of its organisation
-- (Phase 2 C3a; partner decision 5, S91: a policy takes effect at once, with
-- an admin's passkey, and every admin and approver is told). Two notice kinds,
-- each with `aboutId` the policy's ID: the organisation's own policy (its ID
-- the organisation's) or a mandate's (its ID the mandate's, 0037). Each is
-- written to the group and fanned out as it is sent, to the admins and
-- approvers active then, as a mandate's moves are (0036).

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
        'mandate_policy_changed'
      )
    );
