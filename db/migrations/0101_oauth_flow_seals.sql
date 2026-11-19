-- A flow sealed, as it opens and as it is decided, by a key the database
-- never holds (Phase 6 6F1 gate, tamper pass S205; SEC-OAUTH-13; Threat-Model
-- row 13, ADR-012 §2).
--
-- oauth.flows is global and holds no signed state: until now a token was
-- issued for whatever organisation and connection key an allowed flow named,
-- to whoever showed the code (or device code) whose SHA-256 it kept, with the
-- redirect address and PKCE challenge it kept. The database's owner, holding
-- none of the app's keys, could so plant an allowed flow for any live
-- connection; rewrite a real one's code, challenge or redirect address; or
-- rewrite a pending one's device code hash, redirect address or challenge
-- before its person allowed it, and take the connection's tokens: authority
-- granted without anyone's consent.
--
-- Now the app MACs each flow with the agent-key pepper (the key that already
-- MACs every agent key and connection token), under labels of its own
-- (oauth/infrastructure/flow-seals.ts):
--
-- - as it opens (`oauth-flow-open-v1`: open_mac, open_key_version), over its
--   ID, kind, client, redirect address, PKCE challenge, device code hash,
--   scopes asked, resource and end; checked wherever a pending flow is read
--   for a person's consent, so a flow rewritten is never shown or decided;
-- - as a person's consent decides it (`oauth-flow-decision-v1`:
--   decision_mac, decision_key_version), over the same, the organisation,
--   connection key, code hash, decided time and code end; checked by the token
--   endpoint before any token is issued: a flow that doesn't match is refused
--   `invalid_grant`, as any other code is, and raises the integrity alarm.
--
-- Each key version is kept beside its MAC, as a token's is, for the pepper's
-- rotation. The open seal is written by the flow's INSERT; the decision's by
-- the decision's own UPDATE (the app's UPDATE on those two columns alone). A
-- flow opened or decided before this migration, or by the release before
-- while this one rolls out, has none and is refused with a warning: a flow
-- lives 15 minutes, a code 60 seconds, and its person connects again.

ALTER TABLE oauth.flows
  ADD COLUMN open_mac text CHECK (open_mac ~ '^[0-9a-f]{64}$'),
  ADD COLUMN open_key_version integer CHECK (open_key_version >= 1),
  ADD CONSTRAINT an_open_mac_with_its_version CHECK ((open_mac IS NULL) = (open_key_version IS NULL)),
  ADD COLUMN decision_mac text CHECK (decision_mac ~ '^[0-9a-f]{64}$'),
  ADD COLUMN decision_key_version integer CHECK (decision_key_version >= 1),
  ADD CONSTRAINT a_decision_mac_with_its_version CHECK ((decision_mac IS NULL) = (decision_key_version IS NULL));

-- Only as the decision is made (oauth/flows.ts flowDecided).
GRANT UPDATE (decision_mac, decision_key_version) ON oauth.flows TO agentx_app;
