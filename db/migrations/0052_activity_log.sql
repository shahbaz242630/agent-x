-- The activity log (Phase 3 L2, partner decision 26: "everything logged",
-- reads and refusals too, per organisation and per person; ADR-005 §6 and §9,
-- ADR-011 §7 as amended S126). The audit chain already holds every change
-- made; this holds every request a known caller made, one row each, the ones
-- that changed nothing or were refused among them.
--
-- Two tables, in their own append-only schema (the app adds rows and reads
-- them, never changes or deletes one):
--
-- - `access.requests`: a request of a verified member or agent of one
--   organisation, a tenant table walled by row-level security like every
--   other, read by its admins alone.
-- - `access.person_requests`: a signed-in person's request that names no
--   organisation they are verified in (their profile, their session, an
--   invitation, or an organisation they turned out not to be in, kept as
--   `claimed_org` and only ever as a claim). Global, on the CI-06 list: no
--   organisation's log may hold it, so a header can't write into another's.
--
-- Each row holds the time (UTC, exact), the method, the route's pattern and
-- the IDs in its path (never a query string, a header or a body), the status
-- and reason code, the correlation ID (on the request's own log lines and in
-- the chain events it wrote, so the logs link), how long it took; then the
-- personal columns, kept as clues, not proof: the client's IP address, its
-- approximate country and city, and a time zone with where it came from (the
-- browser's own report, or the organisation's when none). The daily seal
-- (L6) covers every column but these, so a lawful erasure can blank them.
--
-- Kept as long as the law allows (decision 26, PL-42): no sweep, no DELETE
-- for the app. Not partitioned until the keeping period is set (ADR-005 §9).
-- The backup role reads everything, as it must for a logical backup.

CREATE SCHEMA access;
GRANT USAGE ON SCHEMA access TO agentx_app, agentx_backup;

CREATE TABLE access.requests (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  recorded_at timestamptz NOT NULL,
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'agent')),
  actor_id uuid NOT NULL,
  method text NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
  route text NOT NULL CHECK (route ~ '^/[A-Za-z0-9/:_.-]{0,200}$'),
  path_ids uuid[] NOT NULL CHECK (pg_catalog.cardinality(path_ids) <= 4),
  status smallint NOT NULL CHECK (status BETWEEN 100 AND 599),
  reason text CHECK (reason ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  correlation_id uuid NOT NULL,
  duration_ms integer NOT NULL CHECK (duration_ms >= 0),
  ip inet,
  country text CHECK (country ~ '^[A-Z]{2}$'),
  city text CHECK (pg_catalog.char_length(city) BETWEEN 1 AND 120),
  time_zone text CHECK (time_zone ~ '^[A-Za-z][A-Za-z0-9_+/-]{0,63}$'),
  time_zone_from text CHECK (time_zone_from IN ('browser', 'organisation')),
  PRIMARY KEY (org_id, id),
  CONSTRAINT time_zone_with_its_source CHECK ((time_zone IS NULL) = (time_zone_from IS NULL)),
  CONSTRAINT city_with_its_country CHECK (city IS NULL OR country IS NOT NULL)
);

ALTER TABLE access.requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON access.requests
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- A page by time, newest first, and the same for one person or agent (L5).
CREATE INDEX requests_by_time ON access.requests (org_id, recorded_at, id);
CREATE INDEX requests_by_actor ON access.requests (org_id, actor_type, actor_id, recorded_at, id);

GRANT SELECT, INSERT ON access.requests TO agentx_app;
GRANT SELECT ON access.requests TO agentx_backup;

CREATE TABLE access.person_requests (
  id uuid PRIMARY KEY,
  recorded_at timestamptz NOT NULL,
  user_id uuid NOT NULL,
  -- The organisation the request's header named, when the person wasn't
  -- verified in it: a claim, never shown to that organisation.
  claimed_org uuid,
  method text NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
  route text NOT NULL CHECK (route ~ '^/[A-Za-z0-9/:_.-]{0,200}$'),
  path_ids uuid[] NOT NULL CHECK (pg_catalog.cardinality(path_ids) <= 4),
  status smallint NOT NULL CHECK (status BETWEEN 100 AND 599),
  reason text CHECK (reason ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  correlation_id uuid NOT NULL,
  duration_ms integer NOT NULL CHECK (duration_ms >= 0),
  ip inet,
  country text CHECK (country ~ '^[A-Z]{2}$'),
  city text CHECK (pg_catalog.char_length(city) BETWEEN 1 AND 120),
  time_zone text CHECK (time_zone ~ '^[A-Za-z][A-Za-z0-9_+/-]{0,63}$'),
  time_zone_from text CHECK (time_zone_from IN ('browser', 'organisation')),
  CONSTRAINT time_zone_with_its_source CHECK ((time_zone IS NULL) = (time_zone_from IS NULL)),
  CONSTRAINT city_with_its_country CHECK (city IS NULL OR country IS NOT NULL)
);

-- One person's requests by time, newest first (their own view and ours, L8).
CREATE INDEX person_requests_by_person ON access.person_requests (user_id, recorded_at, id);

GRANT SELECT, INSERT ON access.person_requests TO agentx_app;
GRANT SELECT ON access.person_requests TO agentx_backup;
