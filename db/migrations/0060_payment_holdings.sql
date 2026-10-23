-- A handed-off request's reservation and order claim follow its payment
-- (Phase 4 C3; ADR-006 §10–§11; PRD §3.1), here as well as in the app (the
-- outcomes module) and the holdings check: a reservation is FINALISED only
-- once its payment SUCCEEDED (a REVERSED one keeps it: no capacity back in
-- the MVP), BLOCKED_UNKNOWN only while it is UNKNOWN, and RELEASED, as its
-- claim is, only after a verified FAILED or CANCELLED. The payment is the
-- request's one instruction's transaction (0058), which the transaction that
-- settles the holdings has moved first; none reads as not paid at all.
-- Everything else each guard holds is as 0039 and 0040 wrote it.

CREATE OR REPLACE FUNCTION spend_requests.guard_held_for_request() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  request record;
  payment text;
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'UPDATE')
     OR TG_TABLE_SCHEMA <> 'limit_reservations' OR TG_TABLE_NAME <> 'reservations' THEN
    RAISE EXCEPTION 'spend_requests.guard_held_for_request must run BEFORE INSERT OR UPDATE, FOR EACH ROW, on limit_reservations.reservations'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  SELECT r.agent_id, r.mandate_id, r.supplier_id, r.amount_minor, r.currency, r.decision, r.status INTO request
    FROM spend_requests.requests r
    WHERE r.org_id = NEW.org_id AND r.id = NEW.request_id;
  IF TG_OP = 'INSERT' THEN
    IF request.status IS DISTINCT FROM 'VALIDATING'
       OR request.decision IS DISTINCT FROM 'ALLOW' AND request.decision IS DISTINCT FROM 'REQUIRE_APPROVAL' THEN
      RAISE EXCEPTION 'only a request just decided to hold capacity is reserved for'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
    END IF;
    IF (request.agent_id, request.mandate_id, request.supplier_id, request.amount_minor, request.currency)
       IS DISTINCT FROM (NEW.agent_id, NEW.mandate_id, NEW.supplier_id, NEW.amount_minor, NEW.currency) THEN
      RAISE EXCEPTION 'a reservation holds exactly what its request asked'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
    END IF;
    IF NEW.payee_key IS DISTINCT FROM (
      SELECT s.payee_key FROM suppliers.suppliers s WHERE s.org_id = NEW.org_id AND s.id = NEW.supplier_id
    ) THEN
      RAISE EXCEPTION 'a reservation keeps its supplier''s payee key as it is'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
    RETURN NEW;
  END IF;
  IF NEW.state = 'RELEASED' AND request.status IN ('VALIDATING', 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY') THEN
    RAISE EXCEPTION 'a reservation is released only once its request has ended, not while %', request.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
  END IF;
  IF NEW.state IN ('BLOCKED_UNKNOWN', 'FINALISED') AND request.status IS DISTINCT FROM 'HANDED_OFF' THEN
    RAISE EXCEPTION 'a reservation follows a payment only once its request is handed off, not while %', request.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
  END IF;
  IF request.status = 'HANDED_OFF' THEN
    SELECT t.status INTO payment
      FROM instructions.instructions i
      JOIN transactions.transactions t ON t.org_id = i.org_id AND t.instruction_id = i.id
      WHERE i.org_id = NEW.org_id AND i.spend_request_id = NEW.request_id;
    IF NEW.state = 'FINALISED' AND payment IS DISTINCT FROM 'SUCCEEDED'
       OR NEW.state = 'BLOCKED_UNKNOWN' AND payment IS DISTINCT FROM 'UNKNOWN'
       OR NEW.state = 'RELEASED' AND payment IS DISTINCT FROM 'FAILED' AND payment IS DISTINCT FROM 'CANCELLED' THEN
      RAISE EXCEPTION 'a handed-off request''s reservation becomes % only as its payment does, not while %', NEW.state, payment
        USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION spend_requests.guard_claim() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  request record;
  payment text;
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'UPDATE')
     OR TG_TABLE_SCHEMA <> 'spend_requests' OR TG_TABLE_NAME <> 'order_claims' THEN
    RAISE EXCEPTION 'spend_requests.guard_claim must run BEFORE INSERT OR UPDATE, FOR EACH ROW, on spend_requests.order_claims'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  SELECT r.decision, r.status INTO request
    FROM spend_requests.requests r
    WHERE r.org_id = NEW.org_id AND r.id = NEW.request_id;
  IF TG_OP = 'INSERT' THEN
    IF request.decision IS DISTINCT FROM 'ALLOW' AND request.decision IS DISTINCT FROM 'REQUIRE_APPROVAL' THEN
      RAISE EXCEPTION 'only a request holding capacity claims its order'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
    END IF;
    IF NEW.payee_key IS DISTINCT FROM (
      SELECT s.payee_key FROM suppliers.suppliers s WHERE s.org_id = NEW.org_id AND s.id = NEW.supplier_id
    ) THEN
      RAISE EXCEPTION 'a claim keeps its supplier''s payee key as it is'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at THEN
    RAISE EXCEPTION 'a claim is released once'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
  END IF;
  IF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL
     AND request.status IN ('VALIDATING', 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY') THEN
    RAISE EXCEPTION 'a claim is released only once its request has ended, not while %', request.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
  END IF;
  IF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL AND request.status = 'HANDED_OFF' THEN
    SELECT t.status INTO payment
      FROM instructions.instructions i
      JOIN transactions.transactions t ON t.org_id = i.org_id AND t.instruction_id = i.id
      WHERE i.org_id = NEW.org_id AND i.spend_request_id = NEW.request_id;
    IF payment IS DISTINCT FROM 'FAILED' AND payment IS DISTINCT FROM 'CANCELLED' THEN
      RAISE EXCEPTION 'a handed-off request''s claim is released only after its payment failed or was cancelled, not while %', payment
        USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
