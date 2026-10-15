-- A pending spend request carried to its mandate's new version (PRD §4.1,
-- §11; BR-05, BR-09; Phase 3 E4; partner decisions 15 and 17): an admin
-- accepting a new version may choose to carry the old one's pending requests
-- over, each weighed again under the new terms first. One that still stands
-- names the new version from then on, so everything that compares a request's
-- version with the one in force (the voids, the job, approval, the hand-off)
-- goes on comparing as it does.
--
-- 0039 keeps the version as the request was made (`fixed_at_creation`). Here
-- it may move, and only this way (`carried_version`): while the request is
-- pending (waiting, approved or ready), its status unchanged by the same
-- change, from a version to the version its own mandate has waiting for
-- acceptance. That waiting version is the one being accepted: acceptance
-- carries the requests in its transaction before it makes the version
-- current. 0039's `from_its_mandates_source` still holds: the new version
-- must fund from the source the request holds. Its mandate, policies and
-- everything else stay fixed. The function runs with its caller's rights, so
-- the mandate is read through its tenant wall.

DROP TRIGGER fixed_at_creation ON spend_requests.requests;

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON spend_requests.requests
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed(
    'agent_id', 'agent_key_id', 'mandate_id', 'organization_policy_version_id', 'mandate_policy_version_id',
    'supplier_id', 'supplier_version_id', 'funding_source_id', 'amount_minor', 'currency', 'purpose',
    'order_reference', 'idempotency_key', 'input_hash', 'input_hash_key_version', 'decision', 'reason_codes'
  );

CREATE FUNCTION spend_requests.guard_carried_version() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  waiting uuid;
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP <> 'UPDATE' OR TG_TABLE_SCHEMA <> 'spend_requests'
     OR TG_TABLE_NAME <> 'requests' THEN
    RAISE EXCEPTION 'spend_requests.guard_carried_version must run BEFORE UPDATE, FOR EACH ROW, on spend_requests.requests'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  IF OLD.mandate_version_id IS NOT DISTINCT FROM NEW.mandate_version_id THEN
    RETURN NEW;
  END IF;
  SELECT m.pending_version_id INTO waiting
  FROM mandates.mandates m
  WHERE m.org_id = OLD.org_id AND m.id = OLD.mandate_id;
  IF OLD.status NOT IN ('APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY')
     OR NEW.status IS DISTINCT FROM OLD.status
     OR OLD.mandate_version_id IS NULL
     OR NEW.mandate_version_id IS DISTINCT FROM waiting THEN
    RAISE EXCEPTION 'a spend request in %.% moves only, still pending, to its mandate''s waiting version',
      TG_TABLE_SCHEMA, TG_TABLE_NAME
      USING ERRCODE = 'check_violation', CONSTRAINT = 'carried_version';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER carried_version BEFORE UPDATE ON spend_requests.requests
  FOR EACH ROW EXECUTE FUNCTION spend_requests.guard_carried_version();
