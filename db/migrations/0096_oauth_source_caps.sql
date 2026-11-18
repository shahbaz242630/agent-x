-- One source can't fill the OAuth caps for every organisation (Phase 6 6F1
-- gate, G4). The flows' cap (oauth/flows.ts MOST_OPEN_FLOWS) and the day's
-- registrations (oauth/clients.ts MOST_REGISTRATIONS_A_DAY) are one each for
-- the whole server; a browser sending no cookie is a fresh browser every time,
-- and each address's own limit is a count in one process's memory. So a few
-- addresses could hold either cap full, and every organisation's people
-- connecting an app were refused. Now each is also held per source, in the
-- same transaction as the server's count, which stays as the backstop:
--
-- - oauth.flows.source_key: the client address that opened the flow, as the
--   rate limit keys it (an IPv4 address; an IPv6 /64 as one): at most 20 flows
--   not yet ended from one source.
-- - oauth.clients.network: the network that registered the client (an IPv4
--   /24, an IPv6 /48): at most 150 registrations a day from one network.
--
-- Kept plainly, as the security events keep an address (0012; ADR-011 §7):
-- in-country, here alone, never in a log line. A keyed hash would hide little
-- (IPv4 has 2^32 addresses) and need a key of its own. A flow's goes with the
-- flow, swept a day after it ends; a client's network with the client,
-- swept a day after it registered if it never connected, 90 days after it
-- last connected if it did. Old rows have none (NULL), counted against no
-- source: a flow ends within 15 minutes, and a day's registrations are
-- counted by the server's cap alone until their day is past.
--
-- Written once, as the row is added (the app's INSERT on both tables); the
-- app may never change either (no UPDATE granted), and the backup role reads
-- them as it reads every column.

ALTER TABLE oauth.flows
  ADD COLUMN source_key text CHECK (pg_catalog.char_length(source_key) BETWEEN 1 AND 64);

ALTER TABLE oauth.clients
  ADD COLUMN network text CHECK (pg_catalog.char_length(network) BETWEEN 1 AND 64);

-- One source's flows not yet ended, counted as one opens.
CREATE INDEX flows_by_source ON oauth.flows (source_key, ends_at);

-- A network's registrations need no index of their own: they are counted among the last day's, which the server's
-- cap holds to 500 (clients_by_time), in the same statement.
