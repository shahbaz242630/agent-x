-- CO8b (Phase 6, decision 26's L8; D2): the operator's command exports one
-- person's own activity log for a case (person-activity-export), so its role
-- reads `access.person_requests` (0052). The whole table, not a column list:
-- before its file, the export checks each sealed day of the range against its
-- seal on the platform chain, and a day's digest is every person's rows of
-- that day, every sealed column (person-seal.ts in core's activity module).
-- Each read of rows for the file names the one person (person-reads.ts).
-- No write, and no lock (a lock needs a right to change a row). The person is
-- told: the export is recorded first on the platform chain as
-- `operator.person_log_exported`, which their My activity page lists.
--
-- Runs only once the image before it carries this right as coming
-- (coming.json's operatorRights, decision 49): a right more is the tamper alarm
-- at once to an image that doesn't know it.

GRANT SELECT ON access.person_requests TO agentx_operator;
