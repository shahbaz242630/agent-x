-- 4D2e D6: which organisation has work of which kind, so a job can stop visiting
-- all of them. Watching only: no job reads this yet to decide anything.
--
-- Global because the question comes before any organisation is chosen. So it holds
-- an ID, a job's name and a time, nothing of the organisation's. A row chooses when
-- to look and nothing is believed from it: the job reads and acts inside withTenant.
-- A forged row only causes a visit; a row deleted is found again within the hour
-- (org-work.ts).
--
-- `marks` moves with every mark. A job reads it, does its work, then deletes or
-- updates only where it still reads the same, so a mark made meanwhile is never
-- lost. It starts from the clock, not from 1: a row deleted and made again must
-- not read as the one read before it.
CREATE TABLE directory.org_work (
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id),
  job text NOT NULL CHECK (job IN ('hand_off', 'hand_off_sweep', 'payment_check')),
  due_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(due_at)),
  marks bigint NOT NULL DEFAULT ((pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000000)::bigint),
  PRIMARY KEY (org_id, job)
) WITH (fillfactor = 70);

CREATE INDEX org_work_due ON directory.org_work (job, due_at, org_id);

GRANT SELECT, INSERT, DELETE ON directory.org_work TO agentx_app;
GRANT UPDATE (due_at, marks) ON directory.org_work TO agentx_app;
GRANT SELECT ON directory.org_work TO agentx_backup;

-- Runs as whoever wrote the row, with no rights of its own (ADR-005). The first
-- argument is the job, the second how long until it is due.
CREATE FUNCTION directory.mark_org_work() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog AS $$ BEGIN
  INSERT INTO directory.org_work (org_id, job, due_at)
  VALUES (NEW.org_id, TG_ARGV[0], pg_catalog.now() + TG_ARGV[1]::interval)
  ON CONFLICT (org_id, job) DO UPDATE SET marks = org_work.marks + 1,
    due_at = LEAST(org_work.due_at, EXCLUDED.due_at);
  RETURN NULL;
END $$;

-- Deferred: each fires inside COMMIT, so after every lock ADR-006 orders, on no trip
-- of its own, and whichever image wrote the row. WHEN is read as the row is written.
CREATE CONSTRAINT TRIGGER marks_hand_off AFTER INSERT OR UPDATE ON spend_requests.requests
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status IN ('APPROVED', 'INSTRUCTION_READY'))
  EXECUTE FUNCTION directory.mark_org_work('hand_off', '0 seconds');

-- Due when the sweep would mark it UNKNOWN (handoff.ts: UNKNOWN_AFTER_MS).
CREATE CONSTRAINT TRIGGER marks_hand_off_sweep AFTER INSERT OR UPDATE ON transactions.transactions
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status = 'SUBMISSION_PENDING')
  EXECUTE FUNCTION directory.mark_org_work('hand_off_sweep', '10 minutes');

CREATE CONSTRAINT TRIGGER marks_payment_check AFTER INSERT OR UPDATE ON transactions.transactions
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status IN ('SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN'))
  EXECUTE FUNCTION directory.mark_org_work('payment_check', '0 seconds');

-- What the hand-off's job asks of an organisation: has it one to hand off?
CREATE INDEX requests_to_hand_off ON spend_requests.requests (org_id, id)
  WHERE status IN ('APPROVED', 'INSTRUCTION_READY');
