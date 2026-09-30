-- A notice of a second factor added to a person's login at the login service
-- (the S68 security audit; ADR-003 §4, SEC-OPS-02): until now only removals
-- were copied and told, so a phished session that enrolled its own security
-- key or passkey went unseen. `second_factor_added` is about the person
-- (`about_id`, their Agent X user ID), told to them and their organisations'
-- admins, as 0024's five are.
--
-- The check changes; no column does, so the running image's live guard is
-- unaffected during the release.

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
        'factor_reset_completed'
      )
    );
