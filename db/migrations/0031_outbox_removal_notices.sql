-- Notices of a member removed, or of an admin's or finance approver's role
-- taken away (the S68 audit): until now only grants were told, so a
-- compromised admin removing or demoting the others one by one went unseen
-- but for the audit trail. Both are about a membership, told to the
-- organisation's admins, as 0021's two are:
--
-- - `member_removed`: a member deactivated, with the role they held (any AI
--   agents they own keep running, and the notice says so, for an admin to
--   hand over or suspend);
-- - `role_removed`: an admin or finance approver given a lesser role, with
--   the role taken away.
--
-- The checks change; no column does, so the running image's live guard is
-- unaffected during the release.

ALTER TABLE notifications.outbox DROP CONSTRAINT outbox_kind_check;
ALTER TABLE notifications.outbox DROP CONSTRAINT about_what_its_kind_says;
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
        'factor_reset_completed'
      )
    ),
  ADD CONSTRAINT about_what_its_kind_says
    CHECK (
      CASE
        WHEN kind IN ('role_granted', 'member_rejoined', 'member_removed', 'role_removed')
          THEN membership_id IS NOT NULL AND role IS NOT NULL AND about_id IS NULL
        ELSE membership_id IS NULL AND role IS NULL AND about_id IS NOT NULL
      END
    );
