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
-- The rows already here have no MAC, and none can be made for them here: the
-- key isn't the database's. They stay, the columns nullable: a row without one
-- is believed only if its ID was made before a fixed cutoff in the code
-- (event-seals.ts MAC_REQUIRED_FROM), and they are all swept within the
-- retention period. Both columns are set together, or neither.
--
-- The app writes the MAC with the row, as INSERT already allows; it never
-- changes one.

ALTER TABLE security.events
  ADD COLUMN mac bytea CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT event_mac_whole CHECK ((mac IS NULL) = (mac_key_version IS NULL));

ALTER TABLE security.org_events
  ADD COLUMN mac bytea CHECK (pg_catalog.octet_length(mac) = 32),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT org_event_mac_whole CHECK ((mac IS NULL) = (mac_key_version IS NULL));
