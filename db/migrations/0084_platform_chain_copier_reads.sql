-- agentx: no transaction (concurrent index)
-- S186 (SA2): the login events copier's reads of the platform chain, and the restriction's,
-- from indexes. Each read named an action (0057's audit_events_by_action) and then looked
-- in the JSON of every event of it: the copier's check for an event copied already (twice
-- an event an organisation), where it got to (the latest `at` copied), the swap check and
-- the 7-day restriction (by person) all grew with every login event ever copied, and the
-- restriction is read on admin requests.
--
-- Each index leads with the action, which the reads always name, and keys one fact of the
-- details as the reads compare it (platform-events.ts: `(details::jsonb ->> '<name>')`,
-- the name written into the SQL):
-- - `event`: the copier's check for an event copied already;
-- - `person`: the restriction and the swap check, by Agent X user;
-- - `subject`: the restriction for a removal made before the person first signed in, by
--   the login service's own ID for them (recorded from S186 on);
-- - `at`, in byte order ("C"): where the copier got to, the greatest time it copied. Every
--   `at` is written by toISOString (24 characters, UTC), so byte order is time order; the
--   reader casts the one it picks.
-- An event without the fact has a null there. The platform chain is a global table, of no
-- organisation (0003), so there is no org_id to lead with; no table, column or grant changes.
--
-- Built concurrently, outside a transaction (the first line; migrate.ts), as 0074's and
-- 0081's: events go on being recorded while each builds, at any size; its lock (SHARE
-- UPDATE EXCLUSIVE) holds back only other changes to the table's shape or a VACUUM. A
-- build that fails leaves its index not valid, which the guard reads as speed, not drift
-- (schema-guard.ts), and the next run drops it and builds it again.
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_by_event ON platform_controls.audit_events (action, (details::jsonb ->> 'event'));
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_by_person ON platform_controls.audit_events (action, (details::jsonb ->> 'person'));
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_by_subject ON platform_controls.audit_events (action, (details::jsonb ->> 'subject'));
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_by_at ON platform_controls.audit_events (action, ((details::jsonb ->> 'at') COLLATE "C"));
