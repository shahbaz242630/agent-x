-- The organisation's audit log, read and downloaded whole by its admins
-- (Phase 3 E10, partner rule S119 and decision 24): filtered by a date range
-- and by event type, newest first. Two indexes, so a page or a download's
-- batch is a short scan however long the log: by the time each event was
-- recorded, and by its action, each in chain order (seq) for paging. The time
-- isn't guaranteed to rise with seq (clock_timestamp()), so the time filters
-- and seq orders.
--
-- An index adds nothing the app can write: the schema stays append-only for
-- the app, and the CI-06 checks are unchanged (org_id leads, as ADR-005 §1
-- asks of every tenant index). Each waits for its lock at most as the runner
-- allows (#364): no lock_timeout of its own.

CREATE INDEX events_by_time ON audit.events (org_id, recorded_at, seq);

CREATE INDEX events_by_action ON audit.events (org_id, action, seq);
