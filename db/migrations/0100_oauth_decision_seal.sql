-- A flow's decision sealed by a key the database never holds (Phase 6 6F1
-- gate, tamper pass S205; SEC-OAUTH-13; Threat-Model row 13, ADR-012 §2).
--
-- oauth.flows is global and holds no signed state: until now a token was
-- issued for whatever organisation and connection key an allowed flow named,
-- to whoever showed the code (or device code) whose SHA-256 it kept, with the
-- redirect address and PKCE challenge it kept. The database's owner, holding
-- none of the app's keys, could so plant an allowed flow for any live
-- connection, or rewrite a real one's code, challenge or redirect address, and
-- take the connection's tokens: authority granted without anyone's consent.
--
-- Now, as a person's consent decides a flow, the app MACs the decision with
-- the agent-key pepper (the key that already MACs every agent key and
-- connection token), under its own label, `oauth-flow-decision-v1`, over the
-- flow's ID, kind, organisation, connection key, client, redirect address,
-- PKCE challenge, code hash, device code hash, scopes asked, resource, end,
-- decided time and code end (oauth/infrastructure/decision-seal.ts). The
-- token endpoint recomputes it before any token is issued: a flow that doesn't
-- match is refused `invalid_grant`, as any other code is, and raises the
-- integrity alarm for the connection it named. The key's version is kept
-- beside it, as a token's is, for the pepper's rotation.
--
-- Written once, by the decision's own UPDATE (the app's UPDATE on these two
-- columns, beside the decision's). A flow decided before this migration has
-- none and is refused: a code lives 60 seconds and a device's flow 15
-- minutes, and its person connects again.

ALTER TABLE oauth.flows
  ADD COLUMN decision_mac text CHECK (decision_mac ~ '^[0-9a-f]{64}$'),
  ADD COLUMN decision_key_version integer CHECK (decision_key_version >= 1),
  ADD CONSTRAINT a_decision_mac_with_its_version CHECK ((decision_mac IS NULL) = (decision_key_version IS NULL));

-- Only as the decision is made (oauth/flows.ts flowDecided).
GRANT UPDATE (decision_mac, decision_key_version) ON oauth.flows TO agentx_app;
