-- Notices of a person's sign-in changed at the login service (ADR-003 §4,
-- SEC-OPS-02; Phase 1 B6-2a): what the login service's own admin events copied
-- into our audit trail (B6-2b) tell the person and their organisations'
-- admins. Five kinds, each about the person (`about_id`, their Agent X user
-- ID; 0023's rule for any notice not about a membership):
--
-- - `second_factor_removed`: an authenticator app, a security key or a
--   passkey taken off their login;
-- - `password_changed`: their password changed, or a reset asked for;
-- - `sign_in_email_changed`: the email address their login verifies;
-- - `sign_in_blocked`: their login locked, deactivated or removed;
-- - `sign_in_restored`: unlocked or reactivated.
--
-- The checks change; no column does, so the running image's live guard is
-- unaffected during the release (0023 added the columns for all of B6).

ALTER TABLE notifications.outbox DROP CONSTRAINT outbox_kind_check;
ALTER TABLE notifications.outbox
  ADD CONSTRAINT outbox_kind_check
    CHECK (
      kind IN (
        'role_granted',
        'member_rejoined',
        'contact_added',
        'contact_removed',
        'second_factor_removed',
        'password_changed',
        'sign_in_email_changed',
        'sign_in_blocked',
        'sign_in_restored'
      )
    );
