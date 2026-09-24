-- A sign-in flow that is a step-up (ADR-003 §9, B3-3a): the flow names the
-- step-up challenge (0013) it was started for, so the callback checks the
-- fresh sign-in against that challenge and records its evidence there,
-- rather than opening a session. Null for an ordinary sign-in.
--
-- No foreign key: a flow outlives its challenge by up to five minutes (ten
-- against five), and a flow naming a challenge that is gone finds nothing to
-- confirm. The callback reads the challenge only through the session the
-- browser brings, so the ID alone confirms nothing.

ALTER TABLE identity.login_flows ADD COLUMN step_up_challenge_id uuid;
