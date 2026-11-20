-- The sign-in flows under way held to a cap (S206 V8), as the OAuth flows are
-- (0096; oauth/flows.ts MOST_OPEN_FLOWS). Anyone can start a sign-in with an
-- anonymous GET (GET /v1/auth/sign-in), and each start adds a row to
-- identity.login_flows (0011) for its ten minutes. Until now only the per-
-- address rate limit bounded them, a count in one process's memory, so many
-- addresses, or a picture on a busy page, could grow the table without end.
-- Now a sign-in is refused, SIGN_IN_UNAVAILABLE, while too many are under way:
-- every network's together, or this network's own (login-flows.ts).
--
-- - network_key: the network that started the flow, as the OAuth flows count
--   theirs (AG8): an IPv4 address alone, an IPv6 address's /48. Kept plainly,
--   as the OAuth flows keep theirs (0096): in-country, here alone, never in a
--   log line, gone with the flow, which is taken at its callback or swept
--   once its ten minutes are over. A step-up's flow has none: it is started
--   only from a live session, for that session's own pending challenge, and
--   is never counted (a flood of anonymous sign-ins can't stop a signed-in
--   person's step-up). Old rows have none, counted against no network: they
--   end within ten minutes.
--
-- Written once, as the row is added (the app's INSERT, granted on the whole
-- table in 0011); the app may never change it (no UPDATE granted), and the
-- backup role reads it as it reads every column.

ALTER TABLE identity.login_flows
  ADD COLUMN network_key text CHECK (pg_catalog.char_length(network_key) BETWEEN 1 AND 64);

-- The sign-ins not yet ended, every network's together, counted as one starts (a step-up's are never counted).
CREATE INDEX login_flows_sign_ins_open ON identity.login_flows (ends_at) WHERE step_up_challenge_id IS NULL;

-- One network's sign-ins not yet ended, counted as one starts.
CREATE INDEX login_flows_by_network ON identity.login_flows (network_key, ends_at)
  WHERE step_up_challenge_id IS NULL;
