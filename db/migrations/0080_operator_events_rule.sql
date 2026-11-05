-- PL-57 (follow-up): the operator's events are added by its role alone. On both
-- audit chains, an event in the operator's name from any role but the operator's
-- and the owner's is refused as it is inserted, before a reader ever has to refuse
-- it unsigned. The owner is allowed because E10's repair puts a chain's original
-- rows back (an operator's event among them) as the owner, who could drop the
-- trigger anyway: the threat this closes is the API's role.
--
-- Runs only once the image before it knows both triggers exactly (0079's image,
-- schema-guard.ts, then COMING_TRIGGERS): a trigger on a table already built is
-- otherwise the tamper alarm at once to the image running as this ends.
--
-- Its locks: each CREATE TRIGGER takes its table's events briefly (SHARE ROW
-- EXCLUSIVE, which every audit insert waits behind). Each wait is 500 ms, under
-- Postgres's 1 s deadlock_timeout, as 0073's: in any deadlock this file gives up
-- first and is tried again after a pause, and the app's transaction is never the
-- one aborted.
SET LOCAL lock_timeout = '500ms';

CREATE FUNCTION audit.operator_events_by_operator() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
begin
  if current_user not in ('agentx_operator', 'agentx_owner') then
    raise exception 'only the operator''s role records an event in its name' using errcode = 'insufficient_privilege';
  end if;
  return new;
end
$$;

CREATE TRIGGER operator_events_by_operator BEFORE INSERT ON audit.events
  FOR EACH ROW WHEN (new.actor_id = 'operator') EXECUTE FUNCTION audit.operator_events_by_operator();

CREATE TRIGGER operator_events_by_operator BEFORE INSERT ON platform_controls.audit_events
  FOR EACH ROW WHEN (new.actor_id = 'operator') EXECUTE FUNCTION audit.operator_events_by_operator();
