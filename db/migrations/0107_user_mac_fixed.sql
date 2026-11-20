-- A person's MAC can no longer be changed by the app (Phase 6 6F1, S207; R-15).
--
-- 0100 let the app write a person's MAC and its key's version
-- (identity.users), only so the API could give one, at its start, to each
-- person made before 0100 (users.ts backfillUserMacs). That pass was deleted
-- in S207 (#740): every person now gets their MAC once, as they are added
-- (userForSubject's INSERT), and no code changes it after. A right nothing
-- uses is one more thing a stolen app login could do: rewrite a person's MAC
-- under a key it reached some other way, or wipe it so a real admin is no
-- longer believed. So it is taken back; the app keeps INSERT and SELECT, and
-- UPDATE on sessions_ended_at alone (0098, AG10).
--
-- The release before this one must already be the one without the pass, or
-- that API would be refused the write at its start: #740 merges first.

REVOKE UPDATE (mac, mac_key_version) ON identity.users FROM agentx_app;
