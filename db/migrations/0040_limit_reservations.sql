-- An agent's monthly periods and the reservations held against its limits
-- (PRD §3.1–3.2; ADR-006 §6–§10, as amended for partner decision 4; BR-08,
-- BR-22; Phase 2 D2): the lock every monthly check serialises on, and the
-- rows that are the monthly total and the split total, with no running sum
-- that could drift (ADR-006 §8). The limit-reservations module owns both
-- (ADR-004), in a schema of its own. Reserving through them comes with D4.
--
-- Partner decision 4 (S87): revoking a mandate and starting another must not
-- reset the monthly total, so the month is the agent's, not the lineage's.
-- limit_reservations.agent_zones holds the time zone an agent's months are
-- named in: its first reservation's mandate's (`periodOf`, ADR-006 §4), kept
-- for good. A later mandate may name another zone, but the agent's month
-- edges never move with it: otherwise a new mandate in a zone already in the
-- next month would start a fresh monthly limit hours early (D2's review).
-- Added once, never changed (no UPDATE granted).
--
-- limit_reservations.agent_periods is only a lock target (ADR-006 §6: 7), one
-- row an agent a month, by the month's name in the agent's zone: a request
-- locks its agent's month FOR NO KEY UPDATE, then sums every reservation of
-- the agent in that month, under any of its mandates. The row is added on the
-- month's first request (an insert that does nothing if it is there) and
-- never changed: `period_lock_only` refuses every UPDATE. The app is granted
-- UPDATE on one column only because Postgres asks for it before a row lock
-- (SELECT … FOR NO KEY UPDATE).
--
-- limit_reservations.reservations is the capacity one request holds (ADR-006
-- §7–§10): its amount and currency, its agent, its mandate (the lineage), the
-- agent's month it was reserved in (whose period row it points at, so none is
-- made without its lock target, and which is the month of `reserved_at` in
-- the agent's zone), and its supplier and payee key for the split total (D5).
-- One reservation a request. Its request is referred to by ID alone:
-- limit-reservations comes before spend-requests in the module map, so no
-- foreign key runs to it (ADR-004 §4).
--
-- spend-requests, which may depend on limit-reservations, guards the tie
-- instead, as `claim_guard` guards a claim (D2's review):
-- `held_for_its_request` (spend_requests.guard_held_for_request) lets a
-- reservation be made only for a request just decided to hold capacity
-- (VALIDATING, ALLOW or REQUIRE_APPROVAL), holding exactly its agent, mandate,
-- supplier, amount and currency, with the supplier's payee key as it is; and
-- lets it be released only once its request has ended, blocked or finalised
-- only once its request is handed off. So the app can't give capacity back
-- while the request may still be paid.
--
-- Its state (ADR-006 §8, §10): HELD when reserved; FINALISED when its payment
-- succeeds; RELEASED on a deny, reject, expiry, cancel or a verified failure;
-- BLOCKED_UNKNOWN while its payment's result is unknown, which still holds the
-- capacity and later finalises or releases. FINALISED and RELEASED are ends (a
-- reversal restores no capacity in the MVP). `reservation_moves` holds those
-- moves, a reservation born HELD, and `settled_at` written only as it reaches
-- an end. The monthly total counts every state but RELEASED.
--
-- Both are of the organisation they belong to, row-level security forced. The
-- app adds rows and reads them; a reservation it changes only in its state and
-- when it settled. Never a delete: a reservation deleted would give its
-- capacity back unseen. Not authority tables: like order claims, reservations
-- are checked against the signed decision and outcome events by the scheduled
-- reconciliation (ADR-012 §2; E1). The backup role reads everything.
--
-- The three guards, like 0039's: no rights of their own, no EXECUTE granted,
-- search_path pg_catalog alone, refusing to run as anything but the trigger
-- they were written for.

CREATE SCHEMA limit_reservations;
GRANT USAGE ON SCHEMA limit_reservations TO agentx_app, agentx_backup;

CREATE TABLE limit_reservations.agent_zones (
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  -- As mandates.mandates keeps it (0035).
  time_zone text NOT NULL CHECK (time_zone ~ '^[A-Za-z][A-Za-z0-9_+/-]{0,63}$'),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  PRIMARY KEY (org_id, agent_id)
);

ALTER TABLE limit_reservations.agent_zones ENABLE ROW LEVEL SECURITY;
ALTER TABLE limit_reservations.agent_zones FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON limit_reservations.agent_zones
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON limit_reservations.agent_zones TO agentx_app;
GRANT SELECT ON limit_reservations.agent_zones TO agentx_backup;

CREATE TABLE limit_reservations.agent_periods (
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  -- `YYYY-MM`, as `periodOf` names the month in the agent's zone.
  month text NOT NULL CHECK (month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  PRIMARY KEY (org_id, agent_id, month),
  CONSTRAINT of_an_agents_zone FOREIGN KEY (org_id, agent_id) REFERENCES limit_reservations.agent_zones (org_id, agent_id)
);

ALTER TABLE limit_reservations.agent_periods ENABLE ROW LEVEL SECURITY;
ALTER TABLE limit_reservations.agent_periods FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON limit_reservations.agent_periods
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- Locked, never changed.
CREATE FUNCTION limit_reservations.guard_period() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP <> 'UPDATE' OR TG_TABLE_SCHEMA <> 'limit_reservations'
     OR TG_TABLE_NAME <> 'agent_periods' THEN
    RAISE EXCEPTION 'limit_reservations.guard_period must run BEFORE UPDATE, FOR EACH ROW, on limit_reservations.agent_periods'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  RAISE EXCEPTION 'an agent''s period is only locked, never changed'
    USING ERRCODE = 'check_violation', CONSTRAINT = 'period_lock_only';
END;
$$;

CREATE TRIGGER period_lock_only BEFORE UPDATE ON limit_reservations.agent_periods
  FOR EACH ROW EXECUTE FUNCTION limit_reservations.guard_period();

GRANT SELECT, INSERT ON limit_reservations.agent_periods TO agentx_app;
-- Only for the row lock: `period_lock_only` refuses every UPDATE.
GRANT UPDATE (created_at) ON limit_reservations.agent_periods TO agentx_app;
GRANT SELECT ON limit_reservations.agent_periods TO agentx_backup;

CREATE TABLE limit_reservations.reservations (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  request_id uuid NOT NULL,
  -- Its agent, mandate, supplier, payee key, amount and currency: as its request
  -- holds them, which `held_for_its_request` checks (so none needs its own key here).
  agent_id uuid NOT NULL,
  mandate_id uuid NOT NULL,
  month text NOT NULL,
  supplier_id uuid NOT NULL,
  payee_key text,
  amount_minor bigint NOT NULL,
  currency text NOT NULL,
  state text NOT NULL CHECK (state IN ('HELD', 'FINALISED', 'RELEASED', 'BLOCKED_UNKNOWN')),
  reserved_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(reserved_at)),
  settled_at timestamptz CHECK (pg_catalog.isfinite(settled_at)),
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_reservation_a_request UNIQUE (org_id, request_id),
  CONSTRAINT in_its_agents_period FOREIGN KEY (org_id, agent_id, month)
    REFERENCES limit_reservations.agent_periods (org_id, agent_id, month),
  -- Settled exactly when it reaches an end, never before it was reserved.
  CONSTRAINT settled_at_its_end CHECK ((state IN ('FINALISED', 'RELEASED')) = (settled_at IS NOT NULL)),
  CONSTRAINT settled_after_reserved CHECK (settled_at IS NULL OR settled_at >= reserved_at)
);

-- The monthly total (ADR-006 §8): an agent's month, every state but RELEASED.
CREATE INDEX held_in_an_agents_month ON limit_reservations.reservations (org_id, agent_id, month)
  WHERE state <> 'RELEASED';

ALTER TABLE limit_reservations.reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE limit_reservations.reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON limit_reservations.reservations
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- Born HELD; HELD or BLOCKED_UNKNOWN moves on, FINALISED and RELEASED are ends;
-- settled_at written only as it reaches one.
CREATE FUNCTION limit_reservations.guard_reservation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'UPDATE')
     OR TG_TABLE_SCHEMA <> 'limit_reservations' OR TG_TABLE_NAME <> 'reservations' THEN
    RAISE EXCEPTION 'limit_reservations.guard_reservation must run BEFORE INSERT OR UPDATE, FOR EACH ROW, on limit_reservations.reservations'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state IS DISTINCT FROM 'HELD' THEN
      RAISE EXCEPTION 'a reservation is born HELD, not %', NEW.state
        USING ERRCODE = 'check_violation', CONSTRAINT = 'reservation_moves';
    END IF;
    IF NEW.month IS DISTINCT FROM (
      SELECT to_char(NEW.reserved_at AT TIME ZONE z.time_zone, 'YYYY-MM')
        FROM limit_reservations.agent_zones z
        WHERE z.org_id = NEW.org_id AND z.agent_id = NEW.agent_id
    ) THEN
      RAISE EXCEPTION 'a reservation counts in the agent''s month it was made in'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'reservation_moves';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
    IF NEW.settled_at IS DISTINCT FROM OLD.settled_at THEN
      RAISE EXCEPTION 'a reservation settles once, as it reaches its end'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'reservation_moves';
    END IF;
    RETURN NEW;
  END IF;
  IF (OLD.state, NEW.state) NOT IN (
    ('HELD', 'FINALISED'), ('HELD', 'RELEASED'), ('HELD', 'BLOCKED_UNKNOWN'),
    ('BLOCKED_UNKNOWN', 'FINALISED'), ('BLOCKED_UNKNOWN', 'RELEASED')
  ) THEN
    RAISE EXCEPTION 'a reservation does not move from % to %', OLD.state, NEW.state
      USING ERRCODE = 'check_violation', CONSTRAINT = 'reservation_moves';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER reservation_moves BEFORE INSERT OR UPDATE ON limit_reservations.reservations
  FOR EACH ROW EXECUTE FUNCTION limit_reservations.guard_reservation();

GRANT SELECT, INSERT ON limit_reservations.reservations TO agentx_app;
GRANT UPDATE (state, settled_at) ON limit_reservations.reservations TO agentx_app;
GRANT SELECT ON limit_reservations.reservations TO agentx_backup;

-- spend-requests' own rule on the reservation of each of its requests (see
-- above): made for a request just decided to hold capacity, holding exactly
-- what it asked; released only once it has ended; blocked or finalised only
-- once it is handed off (its payment's outcome, Phase 4).
CREATE FUNCTION spend_requests.guard_held_for_request() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  request record;
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
  IF NEW.state = 'RELEASED' AND (request.status IS NULL
     OR request.status IN ('VALIDATING', 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY')) THEN
    RAISE EXCEPTION 'a reservation is released only once its request has ended, not while %', request.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
  END IF;
  IF NEW.state IN ('BLOCKED_UNKNOWN', 'FINALISED') AND request.status IS DISTINCT FROM 'HANDED_OFF' THEN
    RAISE EXCEPTION 'a reservation follows a payment only once its request is handed off, not while %', request.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'held_for_its_request';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER held_for_its_request BEFORE INSERT OR UPDATE ON limit_reservations.reservations
  FOR EACH ROW EXECUTE FUNCTION spend_requests.guard_held_for_request();
