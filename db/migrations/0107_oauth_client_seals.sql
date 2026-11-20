-- The facts of an MCP client that decide where its codes go, sealed by a key
-- the database never holds (Phase 6 6F1, S207 review H3; SEC-OAUTH-17;
-- Threat-Model R-15, ADR-012 §2).
--
-- oauth.clients (0093) and oauth.client_metadata (0095) are global and hold
-- no signed state: until now a client was believed as kept. The database's
-- owner, holding none of the app's keys, could add its own address to a
-- known client's redirect addresses (a cached document's, which the consent
-- page shows "verified by" the document's host, claude.ai's among them),
-- widen its grant types to the device flow, or keep a document long past its
-- day; a person allowing that client's request would send their code there.
--
-- Now the app MACs each with the agent-key pepper (the key that already MACs
-- every agent key, connection token and OAuth flow, 0101), under labels of
-- their own (oauth/infrastructure/client-seals.ts):
--
-- - a registered client (`oauth-client-v1`), as it registers: its ID, name,
--   application type, redirect addresses, grant types, software ID and
--   version, and when it registered; written once, by the INSERT;
-- - a kept document (`oauth-client-metadata-v1`), as it is kept: its client
--   ID, name, redirect addresses, grant types, and when it was fetched and
--   until when it is kept; written with them, by the INSERT or the upsert's
--   UPDATE that keeps it again.
--
-- A row whose MAC isn't its own (changed in any field, planted, or copied
-- from another client) is never believed and raises the integrity alarm. A
-- row with none, from before this migration or kept by the release before
-- while this one rolls out, is never believed either, with a warning, and no
-- start-up ever seals one after the fact: a document is fetched again from
-- its own address (the cache holds nothing that can't be fetched again); a
-- client that registered itself is unknown, and registers again. Each key
-- version is kept beside its MAC, as a token's is, for the pepper's rotation.

ALTER TABLE oauth.clients
  ADD COLUMN mac text CHECK (mac ~ '^[0-9a-f]{64}$'),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT a_mac_with_its_version CHECK ((mac IS NULL) = (mac_key_version IS NULL));

ALTER TABLE oauth.client_metadata
  ADD COLUMN mac text CHECK (mac ~ '^[0-9a-f]{64}$'),
  ADD COLUMN mac_key_version integer CHECK (mac_key_version >= 1),
  ADD CONSTRAINT a_mac_with_its_version CHECK ((mac IS NULL) = (mac_key_version IS NULL));

-- Only as a document is kept again over its own row (oauth/client-metadata-cache.ts keepClientMetadata).
GRANT UPDATE (mac, mac_key_version) ON oauth.client_metadata TO agentx_app;
