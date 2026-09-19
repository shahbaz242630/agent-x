-- The status guard (ADR-007 §1): the database's own copy of each state
-- machine's rules. Every table with a status runs this trigger function before
-- each row it inserts or updates, with its machine's rules as the trigger's
-- arguments: first the status a new row starts in, then each allowed move
-- written FROM>TO. A new row in any other status, a status changed along a
-- move not listed, or a row given another org_id or id, is refused, whatever
-- code or statement tried it.
--
--   CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON agents.agents
--     FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('ACTIVE', 'ACTIVE>SUSPENDED', ...);
--
-- What each status table must also have, since the guard can't see it (A3c
-- checks these in CI):
-- - `org_id`, `id` and `status` columns, and a key on (org_id, id);
-- - no DELETE for the app role: a row deleted and inserted again would be
--   born in the first status, which the guard allows;
-- - no partitions: moving a row to another partition inserts it there;
-- - no other BEFORE ROW trigger named after `status_guard`: Postgres runs them
--   in name order, so one running later could change the status after the
--   check.
--
-- The app decides every move with the same machine (the shared-kernel's
-- defineStateMachine) and changes a status only through createStatusChanger,
-- so the guard is the second wall, for a bug or a statement past that step.
-- It stops the app role; the table's owner can drop it, which is what the
-- signed state (ADR-012 §2) is for.
--
-- The function holds no rights of its own: it runs as whoever changes the row
-- (not SECURITY DEFINER), and no one is granted EXECUTE (0001 takes it from
-- PUBLIC), since Postgres checks that right only when a trigger is created,
-- by the owner. Its search_path is pg_catalog alone, so no function or
-- operator planted in another schema can stand in for the ones it uses. It
-- refuses to run as anything but a BEFORE trigger for each row, where its
-- verdict decides what is written.

CREATE SCHEMA state_rules;

CREATE FUNCTION state_rules.guard_status() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'UPDATE') THEN
    RAISE EXCEPTION 'state_rules.guard_status must run BEFORE INSERT OR UPDATE, FOR EACH ROW'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  -- A missing status, or no rules at all, is refused like any other status.
  IF TG_OP = 'INSERT' THEN
    IF (NEW.status = TG_ARGV[0]) IS NOT TRUE THEN
      RAISE EXCEPTION 'a new row in %.% must start as %', TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_ARGV[0]
        USING ERRCODE = 'check_violation', CONSTRAINT = 'status_guard';
    END IF;
    RETURN NEW;
  END IF;
  -- A row keeps its key: given another, it could leave its history behind.
  IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id THEN
    RAISE EXCEPTION 'a row in %.% keeps its org_id and id', TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = 'check_violation', CONSTRAINT = 'status_guard';
  END IF;
  -- The first argument is a status, never a move, so it can't match one.
  IF NEW.status IS DISTINCT FROM OLD.status
     AND (OLD.status || '>' || NEW.status = ANY (TG_ARGV)) IS NOT TRUE THEN
    RAISE EXCEPTION 'the status of a row in %.% can''t move from % to %',
      TG_TABLE_SCHEMA, TG_TABLE_NAME, OLD.status, NEW.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'status_guard';
  END IF;
  RETURN NEW;
END;
$$;
