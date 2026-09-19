-- Finding an object's events (ADR-012 §2): verifiedState reads an object's
-- latest signed-state event from the log itself, on every security-path read,
-- so the organisation's events are indexed by the object they are about, in
-- chain order. The audit module's latestSignedState reads it newest first.
--
-- An index adds nothing the app can write: the schema stays append-only for
-- the app, and the CI-06 checks are unchanged (org_id leads, as ADR-005 §1
-- asks of every tenant index).

CREATE INDEX events_by_subject ON audit.events (org_id, subject_type, subject_id, seq);
