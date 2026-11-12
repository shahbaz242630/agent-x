-- PM4 (CF Before production "E6 review"; PL-30): every request waiting for approval
-- carries when it may expire, so the request expiry reads only its index. 0073 added
-- `waits_until` and 0074 its partial index on the waiting rows, but a request made
-- before 0073 had none, so the job's read also took every waiting row with no
-- `waits_until` and judged it by its age: a second branch the index can't bound. This
-- fills those rows, and the code after it reads `waits_until` alone, in pages that
-- stop at their size (requestsDueToExpire).
--
-- The value is the one the job read them by: `created_at` plus the shortest wait (24
-- hours, SHORTEST_APPROVAL_WAIT_MS), so which requests expire, and when, is unchanged.
-- Never later than the wait the decision sealed, as the decision comes after the row
-- is made and every wait is 24 hours or more. Unsealed, as 0073's is: it only chooses
-- when to look; each request is judged by its sealed decision before it moves, so one
-- read too soon waits on, and the holdings check holds it to the sealed wait (and,
-- from this migration, a waiting request with none is a mismatch).
--
-- The tenant wall binds the owner too (FORCE), so an UPDATE with no organisation named
-- reaches no row (S135). Rather than lift the wall, which takes the hot table's
-- ACCESS EXCLUSIVE lock, each organisation is named in turn, for its one statement,
-- through the same setting the app uses; the wall stays up throughout, and only the
-- rows filled are locked. directory.orgs is global, IDs only. The marks' deferred
-- trigger (0073) then marks each organisation with a filled row due a day on at the
-- latest, which never moves a mark later (LEAST).
DO $$
DECLARE
  org uuid;
BEGIN
  FOR org IN SELECT o.org_id FROM directory.orgs o ORDER BY o.org_id LOOP
    PERFORM pg_catalog.set_config('app.org_id', org::text, true);
    UPDATE spend_requests.requests
      SET waits_until = created_at + pg_catalog.make_interval(hours => 24)
      WHERE org_id = org AND status = 'APPROVAL_REQUIRED' AND waits_until IS NULL;
  END LOOP;
  PERFORM pg_catalog.set_config('app.org_id', '', true);
END
$$;
