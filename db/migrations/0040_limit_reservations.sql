-- An agent's monthly periods and the reservations held against its limits
-- (PRD §3.1–3.2; ADR-006 §6–§10, as amended for partner decision 4; BR-08,
-- BR-22; Phase 2 D2): the lock every monthly check serialises on, and the
-- rows that are the monthly total and the split total, with no running sum
-- that could drift (ADR-006 §8). The limit-reservations module owns both
-- (ADR-004), in a schema of its own. Reserving through them comes with D4.
--
-- limit_reservations.agent_periods is only a lock target (ADR-006 §6: 7), one
-- row an agent a month, by the month's name in its mandate's time zone
-- (`periodOf`, ADR-006 §4). Partner decision 4 (S87): revoking a mandate and
-- starting another must not reset the monthly total, so the period is the
-- agent's, not the lineage's: a request locks its agent's month FOR NO KEY
-- UPDATE, then sums every reservation of the agent in that month, under any of
-- its mandates. The row is added on the month's first request (an insert that
-- does nothing if it is there) and never changed: `period_lock_only` refuses
-- every UPDATE. The app is granted UPDATE on one column only because Postgres
-- asks for it before a row lock (SELECT … FOR NO KEY UPDATE).
--
-- limit_reservations.reservations is the capacity one request holds (ADR-006
-- §7–§10): its amount and currency, its agent, its mandate (the lineage), the
-- agent's month it was reserved in (whose period row it points at, so none is
-- made without its lock target), and its supplier and payee key for the split
-- total (D5). Its request is referred to by ID alone: limit-reservations comes
-- before spend-requests in the module map, so no foreign key runs to it
-- (ADR-004 §4); the scheduled check (E1) matches each reservation to its
-- request's signed decision. One reservation a request.
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
-- The two guards, like 0039's: no rights of their own, no EXECUTE granted,
-- search_path pg_catalog alone, refusing to run as anything but the trigger
-- they were written for.

CREATE SCHEMA limit_reservations;
GRANT USAGE ON SCHEMA limit_reservations TO agentx_app, agentx_backup;

CREATE TABLE limit_reservations.agent_periods (
  org_id uuid NOT NULL,
  agent_id uuid NOT NULL,
  -- `YYYY-MM`, as `periodOf` names the month in the agent's mandate's time zone.
  month text NOT NULL CHECK (month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  PRIMARY KEY (org_id, agent_id, month)
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
  agent_id uuid NOT NULL,
  mandate_id uuid NOT NULL,
  month text NOT NULL,
  supplier_id uuid NOT NULL,
  payee_key text CHECK (payee_key ~ '^[!-~]{1,128}$'),
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL REFERENCES mandates.allowed_currencies (code),
  state text NOT NULL CHECK (state IN ('HELD', 'FINALISED', 'RELEASED', 'BLOCKED_UNKNOWN')),
  reserved_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(reserved_at)),
  settled_at timestamptz CHECK (pg_catalog.isfinite(settled_at)),
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_reservation_a_request UNIQUE (org_id, request_id),
  CONSTRAINT under_its_agents_mandate FOREIGN KEY (org_id, mandate_id, agent_id)
    REFERENCES mandates.mandates (org_id, id, agent_id),
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
