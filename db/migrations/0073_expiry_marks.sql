-- 4D2e D8: the request expiry and the mandate expiry follow marks (0072) instead of
-- visiting every organisation every five minutes. Runs only once the image before it
-- knows its two triggers exactly (D8a, schema-guard.ts COMING_TRIGGERS). The expiry's
-- index is 0074's, so nothing here reads the requests' table whole.
--
-- Its locks, in the order the app's transactions take them, so it can't deadlock with
-- one: mandates, then requests (ADR-006's levels 4 and 8), both whole, then org_work,
-- which a transaction marks only as it commits (0072's deferred triggers). Taken the
-- other way, a request transaction committing would wait for org_work behind this file
-- while this file waited for that transaction: one of them aborted. Each wait is the
-- runner's lock limit, tried again after a pause; while it waits, new reads and writes
-- of a table it waits for queue behind it, for that limit at most. Once it has them,
-- it holds all three until it commits: no table is read whole but org_work (its CHECK)
-- and directory.orgs (the first marks), so a few milliseconds.
LOCK TABLE mandates.mandates, spend_requests.requests IN ACCESS EXCLUSIVE MODE;

-- Two more jobs a mark may name.
ALTER TABLE directory.org_work DROP CONSTRAINT org_work_job_check,
  ADD CONSTRAINT org_work_job_check
    CHECK (job IN ('hand_off', 'hand_off_sweep', 'payment_check', 'request_expiry', 'mandate_expiry'));

-- When a request waiting for approval may expire, written by its decision's own insert
-- (the database's clock then, plus the wait it seals): its decision's sealed time comes
-- a moment later, so this is never after the time it expires by. Unsealed: it only
-- chooses when to look, and each request is judged by its sealed decision before it
-- moves. One moved later past the app would hide it, so the holdings check holds it to
-- the sealed wait. Null for every other decision, and for a request made before this
-- migration or by the image before it, read by created_at as before; those drain within
-- 72 hours. No CHECK: one on a column added would read the whole table under its lock.
ALTER TABLE spend_requests.requests ADD COLUMN waits_until timestamptz;

-- A request waiting: due a day on, the shortest wait; the job's visit then moves the
-- mark to when the request's own wait ends, read from waits_until.
CREATE CONSTRAINT TRIGGER marks_request_expiry AFTER INSERT OR UPDATE ON spend_requests.requests
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status = 'APPROVAL_REQUIRED')
  EXECUTE FUNCTION directory.mark_org_work('request_expiry', '24 hours');

-- A mandate open or suspended, its version in force made or changed: due at once; the
-- visit moves the mark to the soonest end of a version in force, or takes it away.
CREATE CONSTRAINT TRIGGER marks_mandate_expiry AFTER INSERT OR UPDATE ON mandates.mandates
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status IN ('ACTIVE', 'SUSPENDED'))
  EXECUTE FUNCTION directory.mark_org_work('mandate_expiry', '0 seconds');

-- Rows from before these triggers have no mark, and the tenant wall keeps their rows
-- from this owner. So every organisation is marked due now for both jobs: the first
-- runs visit each once, as every run did before, and settle it to what its rows say.
-- directory.orgs is global, IDs only.
INSERT INTO directory.org_work (org_id, job, due_at)
SELECT o.org_id, j.job, pg_catalog.now()
FROM directory.orgs o CROSS JOIN (VALUES ('request_expiry'), ('mandate_expiry')) AS j (job)
ON CONFLICT (org_id, job) DO NOTHING;
