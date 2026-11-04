-- 4D2e D8: the request expiry's index, apart from 0073 so that file's locks stay brief.
-- The expiry's two reads, both of the requests still waiting: the soonest of those due
-- (requestExpiryDue) and the candidates due by now (requestsDueToExpire); nulls, the
-- rows made before 0073, sort last in it. It replaces 0042's, which read by created_at
-- alone and which nothing reads now.
--
-- What it locks: building the index holds spend_requests.requests in SHARE mode while it
-- reads the table, so reads go on and writes (decisions, approvals, the jobs' moves)
-- wait for the build, under the runner's lock limit. Not CONCURRENTLY: every migration
-- file runs in one transaction (migrate.ts), where Postgres refuses it. Then 0042's
-- index is dropped, which takes the table whole for a moment, the build already done.
CREATE INDEX requests_waiting_until ON spend_requests.requests (org_id, waits_until)
  WHERE status = 'APPROVAL_REQUIRED';
DROP INDEX spend_requests.waiting_for_approval;
