-- A notice sealed as it is queued and as it ends, and named on its
-- organisation's audit chain (S206 V4, Threat-Model R-15; ADR-012 §2).
--
-- notifications.outbox is global and holds no signed state, and the
-- sender reads whom to tell from the row itself: until now the database's
-- owner, holding none of the app's keys, could delete a queued warning (a
-- sign-in changed, a factor added, a reset, a removal, a contact changed)
-- before it was sent, mark it sent, or move it to another person or contact,
-- and so hide their own act from the person it warns.
--
-- Now (notifications/infrastructure/notice-seals.ts, outbox.ts):
--
-- - each notice is MACed as it is queued with `audit-mac` (held by the API
--   and the operator's command, both of which queue notices) under a label of
--   its own (`notice-v1`): its ID, organisation, recipient (a person, a
--   contact or a group), kind, membership, role, what it is about and when it
--   was queued (mac, mac_key_version). The sender sends only a notice whose
--   MAC holds; any other is given up unsent and raises the integrity alarm.
-- - the same transaction records `notice.queued` about it on the
--   organisation's chain, so a notice deleted leaves its signed record behind.
-- - as a notice ends, sent or given up, the app MACs that end (`notice-end-v1`:
--   its ID, how it ended and why: end_mac, end_key_version). A row marked sent
--   by anyone else has none that holds.
-- - the API's notice check (packages/core/.../notice-check.ts, job-list.ts)
--   walks each organisation's chain from where it last stopped (its own
--   chained record, `notice_check.passed`) to the head, through the trail's
--   ranged check, and raises the alarm for any notice it walked past, or
--   carried, that is gone, sealed wrongly, ended without the app's end seal,
--   given up because its tries were spent, or still unsent a day on.
--
-- A notice queued before this migration has no MAC and no record. The API's
-- first start seals those still to be sent that have no record, once ever,
-- saying so in its start's record on the platform chain
-- (apps/api/src/notice-legacy.ts); after that, one with no MAC is the owner's,
-- never taken to be sent. No backfill here: an UPDATE here would be the
-- owner's, and no MAC can be made in SQL.
--
-- While this release rolls out (deploy note): the release before still runs
-- its API and, until this one's jobs take the lease, its sender. Two checks
-- make it fail rather than write what this release would take for tampering:
-- a notice written with no MAC, and a notice marked sent or given up with no
-- end seal, are refused. The rows from before stand: `before_seals` is true
-- for every row this migration finds and false for every row written after
-- (its default, which the release before doesn't know to set), so the checks
-- hold validated, as the live schema check needs every check to be. So the release
-- before's change that queues a notice (an admin's or agent's change telling
-- people) fails whole, with nothing of it kept, and its caller is told to try
-- again (a 500 to the console or agent, for the minutes of the overlap); its
-- sender's mark-sent, give-up and fan-out fail and roll back, so the notice
-- stays due and this release's sender sends it (one already emailed by the
-- release before may be emailed twice). Nothing is lost or forged-looking.
-- This release's sender takes only a notice with a MAC (claimDue), so a row
-- from before is sent only once the start has sealed it.

ALTER TABLE notifications.outbox
  ADD COLUMN mac bytea CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT a_notice_mac_with_its_version CHECK ((mac IS NULL) = (mac_key_version IS NULL)),
  ADD COLUMN end_mac bytea CHECK (pg_catalog.octet_length(end_mac) = 32),
  ADD COLUMN end_key_version integer CHECK (end_key_version >= 1),
  ADD CONSTRAINT an_end_mac_with_its_version CHECK ((end_mac IS NULL) = (end_key_version IS NULL)),
  -- True for each row there now: the default fills them, before it is set to false for every row after.
  ADD COLUMN before_seals boolean NOT NULL DEFAULT true;

ALTER TABLE notifications.outbox
  ALTER COLUMN before_seals SET DEFAULT false,
  ADD CONSTRAINT a_notice_is_sealed CHECK (mac IS NOT NULL OR before_seals),
  ADD CONSTRAINT an_end_is_sealed CHECK ((sent_at IS NULL AND given_up_at IS NULL) OR end_mac IS NOT NULL OR before_seals);

-- Written with the row (INSERT, granted already); the end's seal as the notice ends; the queued seal only by the
-- once-ever pass over the notices from before (sealLegacyNotices, over rows with none).
GRANT UPDATE (mac, mac_key_version, end_mac, end_key_version) ON notifications.outbox TO agentx_app;
