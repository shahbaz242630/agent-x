-- The app can no longer rewrite a security row's or a queued notice's MAC
-- (Phase 6 6F1, S208; R-15).
--
-- 0104 and 0105 let the app write `mac` and `mac_key_version` on the outbox
-- and the security tables only so the API could give one, once, to each row
-- made before them (the notice seal backfill and the security events' legacy
-- sealing pass). Both passes were deleted in S208 (#757, in the S208 batch):
-- every row now gets its MAC as it is added, and no code changes it after. A
-- right nothing uses is one more thing a stolen app login could do: wipe a MAC
-- to raise false alarms, or rewrite one under a key it reached some other way.
-- So it is taken back. The app keeps INSERT, SELECT and DELETE on each, and
-- on the outbox UPDATE of its tries, its outcome and its end's seal
-- (end_mac, end_key_version), which every notice's end still writes.
--
-- The release before this one must already be the one without the passes, or
-- that API would be refused the write at its start: the S208 batch merges
-- first.

REVOKE UPDATE (mac, mac_key_version) ON notifications.outbox FROM agentx_app;
REVOKE UPDATE (mac, mac_key_version) ON security.events FROM agentx_app;
REVOKE UPDATE (mac, mac_key_version) ON security.org_events FROM agentx_app;
REVOKE UPDATE (mac, mac_key_version) ON security.partner_event_evidence FROM agentx_app;
