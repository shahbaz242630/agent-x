-- Carrying past 20 (Phase 4 A3; PRD §4.1; BR-05, BR-09; partner decision 6,
-- S135; PL-47): an admin accepting a new version who chose to carry the old
-- one's pending requests has the oldest 20 weighed and carried in the
-- acceptance's own transaction, to the version waiting, as 0047 allows. The
-- rest stay on the version replaced, and the carry job weighs them the same
-- way under the version now in force, 20 at a time, and carries those that
-- stand to it.
--
-- So `carried_version` also allows the move to the mandate's version in
-- force, from another of its versions: still pending, its status unchanged by
-- the same change. Which requests may go is the app's to decide, from the
-- acceptance's signed event (`carryRest`); this guard keeps any other move
-- out, as 0047's did.

CREATE OR REPLACE FUNCTION spend_requests.guard_carried_version() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  waiting uuid;
  in_force uuid;
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP <> 'UPDATE' OR TG_TABLE_SCHEMA <> 'spend_requests'
     OR TG_TABLE_NAME <> 'requests' THEN
    RAISE EXCEPTION 'spend_requests.guard_carried_version must run BEFORE UPDATE, FOR EACH ROW, on spend_requests.requests'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  IF OLD.mandate_version_id IS NOT DISTINCT FROM NEW.mandate_version_id THEN
    RETURN NEW;
  END IF;
  SELECT m.pending_version_id, m.current_version_id INTO waiting, in_force
  FROM mandates.mandates m
  WHERE m.org_id = OLD.org_id AND m.id = OLD.mandate_id;
  IF OLD.status NOT IN ('APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY')
     OR NEW.status IS DISTINCT FROM OLD.status
     OR OLD.mandate_version_id IS NULL
     OR NEW.mandate_version_id IS NULL
     OR (NEW.mandate_version_id IS DISTINCT FROM waiting AND NEW.mandate_version_id IS DISTINCT FROM in_force) THEN
    RAISE EXCEPTION 'a spend request in %.% moves only, still pending, to its mandate''s waiting version or its version in force',
      TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = 'check_violation', CONSTRAINT = 'carried_version';
  END IF;
  RETURN NEW;
END;
$$;
