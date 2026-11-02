-- One copy of the API's jobs at a time (4D2e D): a one-row lease, on the
-- database's clock. A policy of one `jobs` copy isn't enough: a deploy overlaps
-- two, and the login service's event copier can copy twice.
--
-- - `holder`: the process that leads, or null; `until`: when its lease ends. A
--   process takes the row where it is the holder or the lease has ended, every
--   20 seconds, for 60 seconds, and clears it as it stops. Not a session advisory
--   lock: that needs a pinned connection outside the checked pool.
-- - `beating_at`: moved only while the hand-off and the payment checks beat
--   (ADR-013's heartbeat), for /health on a `web` copy, which runs neither.
--
-- A global table, of no organisation: no tenant wall. It says only which process
-- leads, and when. A forged row can delay the jobs, which the dead-man rules see,
-- and never decides anything: each job re-judges under its own row locks. Its
-- schema is append-only for the app, so it is an exception there with its reason
-- (schema-policy.ts): the app reads it and moves those four columns alone, never
-- adding or deleting a row.
CREATE TABLE platform_controls.job_lease (
  name text NOT NULL PRIMARY KEY CHECK (name = 'jobs'),
  holder uuid,
  until timestamptz NOT NULL,
  renewed_at timestamptz,
  beating_at timestamptz
);

INSERT INTO platform_controls.job_lease (name, holder, until) VALUES ('jobs', NULL, '-infinity');

GRANT SELECT ON platform_controls.job_lease TO agentx_app;
GRANT UPDATE (holder, until, renewed_at, beating_at) ON platform_controls.job_lease TO agentx_app;
GRANT SELECT ON platform_controls.job_lease TO agentx_backup;
