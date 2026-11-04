-- 4D2e D9: 0075's first marks, in a file of their own so that no write to the six
-- tables 0075 locks waits on three rows for every organisation.
--
-- Rows from before 0075's triggers have no mark, and the tenant wall keeps their rows
-- from this owner. So every organisation is marked due now for the three jobs: the
-- first runs visit each once, as every run did before, and settle it to what its rows
-- say. directory.orgs is global, IDs only. Its only locks are the insert's own: org_work
-- in ROW EXCLUSIVE, which writers marking at their commit share, and each new row's. A
-- committing transaction marking the same organisation and job may wait for one of its
-- rows, or it for that transaction's; each wait here is 500 ms, as 0073's and 0075's, so
-- in any deadlock this file gives up first and is tried again. A mark already there
-- stands.
SET LOCAL lock_timeout = '500ms';
INSERT INTO directory.org_work (org_id, job, due_at)
SELECT o.org_id, j.job, pg_catalog.now()
FROM directory.orgs o
  CROSS JOIN (VALUES ('request_voids'), ('waiting_rejections'), ('carry_rest')) AS j (job)
ON CONFLICT (org_id, job) DO NOTHING;
