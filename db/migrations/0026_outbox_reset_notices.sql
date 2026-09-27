-- Notices of a lost second factor's reset (ADR-003 §4, ADR-012 §8;
-- SEC-OPS-04; Phase 1 B6-3b): whom a reset (0025) tells, and the one notice
-- that carries a link.
--
-- - `factor_reset_link`: to one registered contact that counts, about the
--   reset (`about_id`, its ID), asking it to confirm. The sender reads the
--   secret written for that reset and contact (0025) at send time and puts
--   the link in the email, so the outbox holds IDs only, never the secret. The
--   one documented exception to a notice doing nothing (SEC-HA-11 is payment
--   approvals, untouched): it goes to one contact, never to a group.
-- - `factor_reset_asked`, `factor_reset_confirmed`, `factor_reset_cancelled`,
--   `factor_reset_expired`, `factor_reset_completed`: each about the person
--   whose second factor it is (`about_id`, their Agent X user ID, as a
--   sign-in notice is, 0024), told to them, their organisation's admins and,
--   once a contact was asked, its contacts. `factor_reset_completed` is sent
--   from B6-3c, when the factor is removed.
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
        'sign_in_restored',
        'factor_reset_link',
        'factor_reset_asked',
        'factor_reset_confirmed',
        'factor_reset_cancelled',
        'factor_reset_expired',
        'factor_reset_completed'
      )
    ),
  ADD CONSTRAINT reset_link_to_one_contact
    CHECK (kind <> 'factor_reset_link' OR recipient_contact_id IS NOT NULL);
