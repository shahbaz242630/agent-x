-- 4D2e D10: the factor removals, the background downloads and the hold history follow
-- marks (0072) instead of visiting every organisation each run. Runs only once the
-- image before it knows its two triggers exactly (D10a, schema-guard.ts
-- COMING_TRIGGERS). No index: the removals' due read is an organisation's resets (at
-- most 500, MOST_RESET_RECORDS), the downloads' 0053's files_to_build, and the hold
-- history's 0005's events_by_subject. The hold history has no trigger here: a hold is
-- an audit event, and no trigger goes on the audit tables, so the hold's own
-- transaction writes its mark (with-signed-states.ts).
--
-- Its locks: the two tables it adds triggers to, in ADR-006's order (the resets at the
-- memberships' level, 2, then the downloads' months, 2c), each in the mode CREATE
-- TRIGGER takes, so no lock is raised later: writes wait for it, reads and FOR SHARE
-- don't. Then org_work, which a transaction marks only as it commits (0072's deferred
-- triggers): taken last, so no committing transaction waits for it while this file waits
-- for that transaction. Each wait is 500 ms, under Postgres's 1 s deadlock_timeout, as
-- 0073's and 0075's: in any deadlock this file gives up first and is tried again after a
-- pause, and the app's transaction is never the one aborted. The first marks are 0078's,
-- outside these locks.
SET LOCAL lock_timeout = '500ms';
LOCK TABLE identity.factor_resets, activity_exports.files IN SHARE ROW EXCLUSIVE MODE;

-- Three more jobs a mark may name.
ALTER TABLE directory.org_work DROP CONSTRAINT org_work_job_check,
  ADD CONSTRAINT org_work_job_check
    CHECK (job IN ('hand_off', 'hand_off_sweep', 'payment_check', 'request_expiry', 'mandate_expiry',
      'request_voids', 'waiting_rejections', 'carry_rest', 'factor_removals', 'background_downloads',
      'hold_history'));

-- The factor removals, a day on as a reset comes to cool off: its cooling-off's length
-- (RESET_COOLING_OFF_HOURS), so never after the reset is due. The visit settles the mark
-- to the soonest cooling-off's end. On updates alone: a reset is born a draft, and moves
-- to COOLING_OFF by an update; nothing moves it back.
CREATE CONSTRAINT TRIGGER marks_factor_removals AFTER UPDATE ON identity.factor_resets
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.status = 'COOLING_OFF')
  EXECUTE FUNCTION directory.mark_org_work('factor_removals', '24 hours');

-- The background downloads, at once as a month is asked for: a month is born waiting
-- (0053's guard_file), one row a month, each marking the same organisation's one row.
-- Every later move of a month (claimed, given back, made ready, failed) is the builder's
-- own, which settles the mark after its run to what is left.
CREATE CONSTRAINT TRIGGER marks_background_downloads AFTER INSERT ON activity_exports.files
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  EXECUTE FUNCTION directory.mark_org_work('background_downloads', '0 seconds');
