-- When a person's sessions were last all ended (Phase 6 6F1 gate, AG10): by
-- their removal or a role change (membership-changes), a reset of their second
-- factor (reset-removals), or a change at the login service that ends them
-- (idp-copier). A sign-in already has to be made after its own flow began
-- (the S68 audit), but a flow begun before such an end and finished after it
-- would still open a session made from a sign-in that predates it. Now a
-- sign-in whose auth_time is before this moment is refused, as stale.
--
-- Written by the same statement series that ends the sessions, in the same
-- transaction, never moved backwards (GREATEST); null for a person whose
-- sessions were never all ended. The app may change this column alone: a
-- user's issuer and subject still never change. A sign-in reads it locking
-- the row (FOR SHARE, which needs this column's UPDATE right), so an end
-- committing at the same moment is waited for, never read past; and an end
-- writes it before deleting the sessions, so it waits for a sign-in that read
-- it first, then deletes the session that sign-in opened too.

ALTER TABLE identity.users
  ADD COLUMN sessions_ended_at timestamptz CHECK (pg_catalog.isfinite(sessions_ended_at));

GRANT UPDATE (sessions_ended_at) ON identity.users TO agentx_app;
