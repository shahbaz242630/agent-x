-- The agent's month time zone becomes a signed record (ADR-012 §2; PL-40;
-- Phase 2 gate G3b, the partner's choice: before Phase 4's hand-off).
-- limit_reservations.agent_zones (0040) names the zone an agent's months are
-- counted in, kept for good from its first reservation. Unsigned, someone
-- with owner-level access could change it and move one agent's month edge by
-- up to a day, starting a fresh monthly limit early. From here it is an
-- authority table: its zone and the time it was kept must equal its signed
-- event (`agent_zone.kept`), every read a decision rests on goes through
-- verifiedState, and the holdings check holds every decision's sealed month
-- to it.
--
-- A signed row is addressed by its organisation and its own ID: an agent has
-- one zone, so the row's ID is its agent's (`id_is_its_agent`). A release
-- still running the code before this one while it rolls out names no ID, so
-- its agent's first decision is refused (fails closed) until it stops. It is
-- made once and never changed (0032's `made_once`, as a
-- supplier's version): the app may write its fields only while its first
-- signed state is being recorded. Rows kept before this migration have no
-- event yet: the API seals each (`sealKeptZone`) before it serves, and on a
-- timer after, and only to the zone of the signed mandate
-- its agent's first request was decided under, which is the zone that
-- decision kept; one that differs is tampering, alarmed and left unsealed, so
-- every read of it is refused.

ALTER TABLE limit_reservations.agent_zones
  ADD COLUMN id uuid,
  ADD COLUMN state_version integer NOT NULL DEFAULT 1,
  ADD COLUMN state_event_id uuid;

-- The rows kept before this migration, every organisation's: the table's
-- tenant wall binds its owner too (FORCE), and this runs as the owner with no
-- organisation named, so the wall is lifted for this one statement and put
-- back, all in the migration's own transaction.
ALTER TABLE limit_reservations.agent_zones NO FORCE ROW LEVEL SECURITY;
UPDATE limit_reservations.agent_zones SET id = agent_id;
ALTER TABLE limit_reservations.agent_zones FORCE ROW LEVEL SECURITY;

ALTER TABLE limit_reservations.agent_zones
  ALTER COLUMN id SET NOT NULL,
  ADD CONSTRAINT id_is_its_agent CHECK (id = agent_id),
  ADD CONSTRAINT one_zone_by_id UNIQUE (org_id, id);

CREATE TRIGGER made_once BEFORE UPDATE ON limit_reservations.agent_zones
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_made_once();

-- Only as the audit module's record seals a new zone: `made_once` refuses any change after.
GRANT UPDATE (time_zone, created_at, state_version, state_event_id) ON limit_reservations.agent_zones TO agentx_app;
