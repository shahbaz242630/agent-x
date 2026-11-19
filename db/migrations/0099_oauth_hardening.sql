-- OAuth hardening from the Phase 6 security audit (6F1, AG8).
--
-- - oauth.flows.network_key: the network that opened the flow, an IPv4
--   address alone or an IPv6 /48 (a site's whole allocation): at most 100
--   flows not yet ended from one network, beside each source's 20 (0096). An
--   IPv6 source is a /64, and one /48 holds 65,536 of them, so a single site
--   could otherwise fill the server's cap one /64 at a time. Kept plainly, as
--   0096 keeps the source, and swept with the flow a day after it ends. Old
--   rows have none (NULL), counted against no network: a flow ends within 15
--   minutes.
-- - oauth.flows.person_hash: the SHA-256 of the signed-in person who claimed
--   a device's flow by its user code, beside the browser's (0095): only that
--   person, on that browser, reads or decides it. A hash, as the browser's
--   is: the flow comes before any organisation is chosen.
-- - oauth.flows.failed_claims: how often someone else typed the user code of
--   a flow already claimed. Its code is then known to more than one person;
--   at the third the flow is denied, so neither can finish it.
-- - oauth.clients.network: cleared a day after the client registered, once
--   its day's count is past (oauth/clients.ts sweepClientNetworks). The app
--   is given UPDATE on that one column for it, and only ever sets it to NULL.

ALTER TABLE oauth.flows
  ADD COLUMN network_key text CHECK (pg_catalog.char_length(network_key) BETWEEN 1 AND 64),
  ADD COLUMN person_hash text CHECK (person_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN failed_claims integer NOT NULL DEFAULT 0 CHECK (failed_claims BETWEEN 0 AND 1000);

-- One network's flows not yet ended, counted as one opens.
CREATE INDEX flows_by_network ON oauth.flows (network_key, ends_at);

-- Only to claim a device flow for its person, and to count the claims of anyone else (oauth/flows.ts deviceClaimed).
GRANT UPDATE (person_hash, failed_claims) ON oauth.flows TO agentx_app;

-- Only to clear the network a client registered from, a day on.
GRANT UPDATE (network) ON oauth.clients TO agentx_app;
