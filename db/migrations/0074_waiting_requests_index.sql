-- agentx: no transaction (concurrent index)
-- 4D2e D8: the request expiry's index, apart from 0073 so that file's locks stay brief.
-- The expiry's two reads, both of the requests still waiting: the soonest of those due
-- (requestExpiryDue) and the candidates due by now (requestsDueToExpire); nulls, the
-- rows made before 0073, sort last in it. It replaces 0042's, which read by created_at
-- alone and which nothing reads now.
--
-- Built concurrently, outside a transaction (the first line; migrate.ts): reads and
-- writes of spend_requests.requests go on while it builds, at any size. It waits, under
-- the runner's lock limit, for transactions already open on the table, and its lock
-- (SHARE UPDATE EXCLUSIVE) holds back only other changes to the table's shape or a
-- VACUUM. While it builds, the index is listed as not valid, which the guard reads as
-- speed, not drift (schema-guard.ts); a build that fails leaves it so, and the next
-- run drops it and builds it again. Then 0042's index goes, concurrently too.
CREATE INDEX CONCURRENTLY IF NOT EXISTS requests_waiting_until ON spend_requests.requests (org_id, waits_until)
  WHERE status = 'APPROVAL_REQUIRED';
DROP INDEX CONCURRENTLY IF EXISTS spend_requests.waiting_for_approval;
