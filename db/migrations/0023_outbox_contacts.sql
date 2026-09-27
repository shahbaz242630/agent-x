-- Notices to registered contacts (ADR-012 §1, §8; SEC-OPS-06; Phase 1
-- B6-1b): the outbox (0021) learns to tell an organisation's registered
-- contacts (0022), and to be about something other than a membership.
--
-- - `recipient_contact_id`: one registered contact, whose address the sender
--   reads from the contact's own verified, encrypted row at send time (a
--   removed contact is told of its own removal).
-- - `to_contacts`: the organisation's ACTIVE contacts, found as it is sent,
--   as a notice with no recipient is to its admins. A notice has at most one
--   of the three: a user, a contact, or the contacts (none: the admins).
-- - `about_id`: what a notice is about when it isn't a membership: here a
--   registered contact; the reset and the login service's events that B6
--   adds next are about a person or a request. A membership notice keeps its
--   membership and role; any other names `about_id` and neither.
--
-- Added once, with room for B6's later kinds, since a new column on a global
-- table is a problem to the running image's live guard until the release
-- replaces it (Container-Image.md "Known limits"); a later kind changes only
-- the checks below. Still IDs and constants only: never an address.

ALTER TABLE notifications.outbox
  ADD COLUMN recipient_contact_id uuid,
  ADD COLUMN to_contacts boolean NOT NULL DEFAULT false,
  ADD COLUMN about_id uuid,
  ALTER COLUMN membership_id DROP NOT NULL,
  ALTER COLUMN role DROP NOT NULL;

ALTER TABLE notifications.outbox DROP CONSTRAINT outbox_kind_check;
ALTER TABLE notifications.outbox
  ADD CONSTRAINT outbox_kind_check
    CHECK (kind IN ('role_granted', 'member_rejoined', 'contact_added', 'contact_removed')),
  ADD CONSTRAINT one_recipient
    CHECK (pg_catalog.num_nonnulls(recipient_user_id, recipient_contact_id) + to_contacts::integer <= 1),
  ADD CONSTRAINT about_what_its_kind_says
    CHECK (
      CASE
        WHEN kind IN ('role_granted', 'member_rejoined')
          THEN membership_id IS NOT NULL AND role IS NOT NULL AND about_id IS NULL
        ELSE membership_id IS NULL AND role IS NULL AND about_id IS NOT NULL
      END
    );
