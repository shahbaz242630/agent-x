-- The organisation's audit log filtered to one actor (Phase 3 L1, decision
-- 26: "per organisation and per person, one click"): every event one person,
-- agent or part of Agent X recorded, in chain order (seq) for paging, so a
-- page or a download's batch of one actor is a short scan however long the
-- log. As 0048, the time filters and seq orders.
--
-- 0044's agent_cancels (org_id, actor_id, recorded_at) can't serve it: it
-- orders by time, not seq, and leaves the actor's type out.
--
-- An index adds nothing the app can write: the schema stays append-only for
-- the app, and the CI-06 checks are unchanged (org_id leads, as ADR-005 §1
-- asks of every tenant index). It waits for its lock at most as the runner
-- allows (#364): no lock_timeout of its own.

CREATE INDEX events_by_actor ON audit.events (org_id, actor_type, actor_id, seq);
