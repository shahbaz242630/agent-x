-- OR2b (playbook K; CF Before production "The only-admin runbook's tools"): the
-- operator's command lists an organisation's registered contacts that count now
-- (counting-contacts), so our team's out-of-band check before resetting a
-- person's second factor reads them from Agent X, never from a break-glass
-- session. Its role reads exactly the columns that list needs, no more:
-- - each contact's ID and organisation, to list and judge it
-- - its signed fields (status, added_by, counts_from, step_up_challenge_id)
--   and its signed state's two columns, to judge it as verifiedState does
-- - its encrypted address and key version, to mask it (the field key is the
--   operator's already, for a first admin's invitation)
-- Never created_at, and nothing else: no write, and no lock (a lock needs a
-- right to change a row), so the list is read unlocked and decides nothing on
-- its own. Every contact the table or the log knows of must verify, or no list.
--
-- Runs only once the image before it carries these rights as coming
-- (coming.json's operatorRights, decision 49): a right more is the tamper alarm
-- at once to an image that doesn't know it.

GRANT SELECT (
  org_id,
  id,
  status,
  added_by,
  counts_from,
  step_up_challenge_id,
  state_version,
  state_event_id,
  email_ciphertext,
  email_key_version
) ON identity.registered_contacts TO agentx_operator;
