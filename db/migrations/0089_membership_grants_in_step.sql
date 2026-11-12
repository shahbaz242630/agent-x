-- OR1 step 2 (OR1b; ADR-012 §1, SEC-PAY-04): a membership's grant summary
-- (0085) is kept in the same transaction as each change of its membership. This
-- makes the database hold the product to it: a commit is refused when a
-- membership's signed version moved and its summary, in step with the version
-- the change started from, is not in step with the membership as the commit ends.
--
-- Deferred to the commit, so the change may write its membership, then its
-- summary, in its own order. Lenient, as OR1 is until OR1c: a summary not built
-- yet (a membership from before 0085, which the API's job builds from the
-- history) or one left behind by an image from before OR1 is never refused
-- here; OR1c makes one left behind the alarm. The owner's role is let through:
-- a state repair puts original rows back as it (E10, PL-29), and it could drop
-- this trigger anyway; the threat this closes is the API's role writing a
-- membership past its summary.
--
-- Runs only once the image before it knows the trigger exactly (coming.json,
-- decision 49): a trigger on a table already built is otherwise the tamper alarm
-- at once to the image running as this ends.
--
-- Its lock: CREATE TRIGGER takes the memberships' SHARE ROW EXCLUSIVE briefly.
-- The wait is 500 ms, under Postgres's 1 s deadlock_timeout, as 0080's: in any
-- deadlock this file gives up first and is tried again after a pause.
SET LOCAL lock_timeout = '500ms';

CREATE FUNCTION identity.grants_in_step() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
declare
  kept integer;
  now_at integer;
begin
  if current_user = 'agentx_owner' then
    return null;
  end if;
  -- The row was just changed and no role but the owner deletes one, so a membership not seen here is hidden by the
  -- tenant wall: the organisation's setting changed before the commit. Refused, as nothing here can be judged.
  select m.state_version into now_at from identity.memberships m
    where m.org_id = new.org_id and m.id = new.id;
  if now_at is null then
    raise exception 'a membership changed out of sight of its own organisation'
      using errcode = 'check_violation', constraint = 'grants_in_step';
  end if;
  select g.membership_version into kept from identity.membership_grants g
    where g.org_id = new.org_id and g.id = new.id;
  -- None built yet, or one an older image left behind before this change (OR1c's): let through.
  if kept is null or kept < old.state_version or kept = now_at then
    return null;
  end if;
  raise exception 'a membership changed without its grant summary kept in step'
    using errcode = 'check_violation', constraint = 'grants_in_step';
end
$$;

CREATE CONSTRAINT TRIGGER grants_in_step AFTER UPDATE OF state_version ON identity.memberships
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (old.state_version IS DISTINCT FROM new.state_version)
  EXECUTE FUNCTION identity.grants_in_step();
