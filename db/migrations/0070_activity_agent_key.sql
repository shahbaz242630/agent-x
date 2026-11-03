-- 4D2e Stage F, Claude's decision 2 (partner S119, "everything logged"): an
-- activity row names the key an agent's request came with. A request line may
-- be sampled from now on (AGENTX_LOG_SUCCESS_SAMPLE_ONE_IN), so this row becomes
-- the one place a read's key is always kept.
--
-- Null on a person's row, and on an agent's row written before this: what those
-- requests' key was isn't known now, and nothing is made up for them. So the
-- check holds only the one way: a key on an agent's row alone.
--
-- Sealed with its row from here on, the line of a row with no key staying as it
-- was, so every seal already made still holds (activity-seal.ts). The app's grant
-- on the table covers the new column; it still adds rows and never changes one.

ALTER TABLE access.requests
  ADD COLUMN agent_key_id uuid,
  ADD CONSTRAINT key_on_an_agents_row_alone CHECK (agent_key_id IS NULL OR actor_type = 'agent');
