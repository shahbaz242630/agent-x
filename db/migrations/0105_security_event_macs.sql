-- A MAC on every security event (S206 V6, Threat-Model R-15; ADR-012 §2).
--
-- `security.events` (0012) and `security.org_events` (0091) hold the failed
-- sign-ins and rate-limit hits, the evidence of an attack. They were unsealed:
-- the database's owner, who holds none of the app's keys, could plant, edit or
-- delete a row unseen. Now each row carries a MAC with the app's `session-mac`
-- key, under a label of its own, over every column and the key version
-- (security-events/infrastructure/event-seals.ts), and each closed UTC day of
-- rows is digested and the digest sealed on an audit chain by the API's job: a
-- global day on the platform chain, an organisation's on its own. A row
-- planted or edited before its day is sealed fails its MAC when the day is
-- sealed; one deleted, edited or slipped in after, the day's digest when the
-- seal is checked. Either raises the integrity alarm.
--
-- The write stays one INSERT with no lock beyond its own rows: the MAC is
-- made in the app, and the chaining happens after the fact, a day at a time.
--
-- The partner's refused messages kept as evidence (0063) get a MAC too, over
-- every column but the body, which the AEAD already binds to the row's ID: the
-- hour's caps count only rows whose MAC holds and that are dated no later
-- than now, so rows planted ahead can't stop evidence being kept
-- (provider-events.ts).
--
-- The rows already here have no MAC, and none can be made for them here: the
-- key isn't the database's. As 0100's people were, the first API to start on
-- this gives each its MAC, once, and records on the platform chain that every
-- row is sealed (legacy-seal.ts); from then on a row with no MAC is never
-- believed. So the columns stay nullable, set together or not at all, and the
-- app may write those two columns of a row, and only to do that.

ALTER TABLE security.events
  ADD COLUMN mac bytea CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT event_mac_whole CHECK ((mac IS NULL) = (mac_key_version IS NULL));

ALTER TABLE security.org_events
  ADD COLUMN mac bytea CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT org_event_mac_whole CHECK ((mac IS NULL) = (mac_key_version IS NULL));

ALTER TABLE security.partner_event_evidence
  ADD COLUMN mac bytea CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT evidence_mac_whole CHECK ((mac IS NULL) = (mac_key_version IS NULL));

-- Every row written from now on must carry its MAC. The rows already here are
-- marked `before_macs` (the column added true for them, its default false for
-- every row after), and the check exempts those alone, so it holds validated
-- from the start: the live schema guard refuses a check NOT VALID, and a time
-- in the check would differ in every database. The first start's sealing
-- gives the marked rows their MACs. The mark grants nothing: a row without a
-- MAC is never believed, marked or not; it is here only so the release
-- before, still running while this one rolls out, can't add a row without a
-- MAC: its write is refused, never planted for a false alarm. What that does
-- to it:
-- - Failed sign-ins and rate-limit hits are written by its recorder in the
--   background, never on a request's path: the batch is refused, the recorder
--   logs `security.events_write_failed`, keeps it in memory and tries again
--   each minute, until that copy stops and the batch is lost. Sign-in and
--   every request go on unchanged; only those counts, for the overlap, are
--   not kept.
-- - A partner's refused message kept as evidence is written on the webhook's
--   path: its write refused, that one webhook is answered 500 instead of 401,
--   and the partner sends it again. No partner is live before Phase 5.
-- The column added with its default true fills the rows already here without
-- an update (none reaches a FORCE-RLS table's rows as the owner); the default
-- is then false for every row after.
ALTER TABLE security.events ADD COLUMN before_macs boolean NOT NULL DEFAULT true;
ALTER TABLE security.events ALTER COLUMN before_macs SET DEFAULT false;
ALTER TABLE security.events ADD CONSTRAINT event_mac_required CHECK (mac IS NOT NULL OR before_macs);

ALTER TABLE security.org_events ADD COLUMN before_macs boolean NOT NULL DEFAULT true;
ALTER TABLE security.org_events ALTER COLUMN before_macs SET DEFAULT false;
ALTER TABLE security.org_events ADD CONSTRAINT org_event_mac_required CHECK (mac IS NOT NULL OR before_macs);

ALTER TABLE security.partner_event_evidence ADD COLUMN before_macs boolean NOT NULL DEFAULT true;
ALTER TABLE security.partner_event_evidence ALTER COLUMN before_macs SET DEFAULT false;
ALTER TABLE security.partner_event_evidence
  ADD CONSTRAINT evidence_mac_required CHECK (mac IS NOT NULL OR before_macs);

GRANT UPDATE (mac, mac_key_version) ON security.events TO agentx_app;
GRANT UPDATE (mac, mac_key_version) ON security.org_events TO agentx_app;
GRANT UPDATE (mac, mac_key_version) ON security.partner_event_evidence TO agentx_app;
