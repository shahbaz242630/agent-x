-- A spend request waiting for approval, and the organisation frozen or
-- unfrozen, told to every admin and approver of its organisation (Phase 3
-- B1; partner decisions 2 and 3, S104). Three notice kinds:
-- spend_request_waiting, `aboutId` the request's ID, written with the
-- decision that sends a request to approval (B2); organization_frozen and
-- organization_unfrozen, `aboutId` the organisation's ID (D1). Each is written
-- to the group and fanned out as it is sent, to the admins and approvers
-- active then, as a mandate's moves are (0036). The email names the request
-- by its ID alone and carries no approval power (SEC-HA-11): the decision is
-- made in the console, with a passkey.

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
        'organization_unfrozen'
      )
    );
