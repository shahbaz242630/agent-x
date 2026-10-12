-- An agent's own cancels (partner decision 11b, S101; Phase 2 G6a): an agent
-- may cancel its own waiting requests at most 10 times in 24 hours, so it
-- can't ask, read the decision and cancel, again and again, to find its
-- hidden approval line. A person's cancels never count.
--
-- The count is of the `spend_request.cancelled` events the agent itself
-- signed (actor `agent`, its ID): the chain-sealed record of who cancelled.
-- One partial index holding those events alone, by organisation, agent and
-- time, so the count is a short scan however long the organisation's log.
-- No table, column or grant changes.

CREATE INDEX agent_cancels ON audit.events (org_id, actor_id, recorded_at)
  WHERE action = 'spend_request.cancelled' AND actor_type = 'agent';
