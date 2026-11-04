-- 4D2e D9: the request voids, the waiting rejections and the carry rest follow marks
-- (0072) instead of visiting every organisation every five minutes. Runs only once the
-- image before it knows its seven triggers exactly (D9a, schema-guard.ts
-- COMING_TRIGGERS). No index: each job's due read is its own candidates' read, LIMIT 1,
-- on the indexes those already use (0046's pending requests).
--
-- Its locks: the six tables it adds triggers to, in ADR-006's order (organisations 2,
-- agents 3, mandates and their policies 4, sources 5, suppliers 6), each in the mode
-- CREATE TRIGGER takes, so no lock is raised later: writes wait for it, reads and FOR
-- SHARE don't. Then org_work, which a transaction marks only as it commits (0072's
-- deferred triggers): taken last, so no committing transaction waits for it while this
-- file waits for that transaction. Each wait is 500 ms, under Postgres's 1 s
-- deadlock_timeout, as 0073's: in any deadlock this file gives up first and is tried
-- again after a pause, and the app's transaction is never the one aborted. Once it has
-- them, it holds all until it commits: nothing is read whole but org_work (its CHECK),
-- so a few milliseconds. The first marks, a row for each organisation and job, are
-- 0076's, outside these locks.
SET LOCAL lock_timeout = '500ms';
LOCK TABLE organizations.organizations, agents.agents, mandates.mandates, mandates.policies,
  funding_sources.sources, suppliers.suppliers IN SHARE ROW EXCLUSIVE MODE;

-- Three more jobs a mark may name.
ALTER TABLE directory.org_work DROP CONSTRAINT org_work_job_check,
  ADD CONSTRAINT org_work_job_check
    CHECK (job IN ('hand_off', 'hand_off_sweep', 'payment_check', 'request_expiry', 'mandate_expiry',
      'request_voids', 'waiting_rejections', 'carry_rest'));

-- The request voids, due at once as what a pending request was decided under is
-- written: an organisation, agent or mandate while not active, a supplier while not
-- verified (a stop, or a choice made again under it), an organisation or supplier lifted
-- (an unfreeze or a reactivation chosen to cancel voids only its first 20 itself), and a
-- mandate moved to a new version. A supplier's new version is always written while it is not verified: 0032's
-- verified_rests_on_its_version holds a verified one to its version. The visit judges
-- each request by its signed states; a stop that paused finds none.
--
-- Every trigger here is on updates alone: every signed write, a new row's too, points
-- its row at its event with an update in the same transaction (pointSignedRow).
CREATE CONSTRAINT TRIGGER marks_request_voids AFTER UPDATE ON organizations.organizations
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status <> 'ACTIVE' OR OLD.status <> 'ACTIVE')
  EXECUTE FUNCTION directory.mark_org_work('request_voids', '0 seconds');

CREATE CONSTRAINT TRIGGER marks_request_voids AFTER UPDATE ON agents.agents
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status <> 'ACTIVE')
  EXECUTE FUNCTION directory.mark_org_work('request_voids', '0 seconds');

CREATE CONSTRAINT TRIGGER marks_request_voids AFTER UPDATE ON mandates.mandates
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status <> 'ACTIVE' OR NEW.current_version_id IS DISTINCT FROM OLD.current_version_id)
  EXECUTE FUNCTION directory.mark_org_work('request_voids', '0 seconds');

-- A source on any write, a new one too: its consent's end is the job's to log and act
-- on as it comes, so the visit settles the mark to the soonest end of a consent.
CREATE CONSTRAINT TRIGGER marks_request_voids AFTER UPDATE ON funding_sources.sources
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  EXECUTE FUNCTION directory.mark_org_work('request_voids', '0 seconds');

CREATE CONSTRAINT TRIGGER marks_request_voids AFTER UPDATE ON suppliers.suppliers
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status <> 'VERIFIED' OR OLD.status <> 'VERIFIED')
  EXECUTE FUNCTION directory.mark_org_work('request_voids', '0 seconds');

-- The waiting rejections, at once as a policy is written: a policy's row moves only as a
-- version is made, whose event names the rest an admin chose to reject.
CREATE CONSTRAINT TRIGGER marks_waiting_rejections AFTER UPDATE ON mandates.policies
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  EXECUTE FUNCTION directory.mark_org_work('waiting_rejections', '0 seconds');

-- The carry rest, at once as a mandate's new version comes into force: an acceptance
-- that carried past 20 leaves the rest on the version it replaced.
CREATE CONSTRAINT TRIGGER marks_carry_rest AFTER UPDATE ON mandates.mandates
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.current_version_id IS DISTINCT FROM OLD.current_version_id)
  EXECUTE FUNCTION directory.mark_org_work('carry_rest', '0 seconds');

