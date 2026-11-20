-- An agent's monthly total kept as a signed running total (GM-1a; Threat-Model
-- R-15, gap map 20 Nov; ADR-006 §8, as amended; ADR-012 §2).
--
-- Until now a decision summed the agent's unreleased reservations for its month
-- (0040, 0081). Reservations are unsealed: the database's owner could delete or
-- zero them, and an over-limit request was then approved and handed off, found
-- only by the holdings check 15 minutes to an hour later.
--
-- limit_reservations.month_totals is what a month's reservations hold, one row an
-- agent, month and currency: an authority table, read and changed through its
-- signed state, kept in the same transactions that reserve and release
-- (a decision adds its amount, an ending or a payment's release takes it off).
-- Sealed: its agent, month and currency, `held_minor` (the minor units held,
-- never below nothing) and when it was made. Its ID is named by its organisation,
-- agent, month and currency (a SHA-256, the app's `namedId`), so a row deleted
-- reads as deleted, never as a month with nothing held. At level 11a in the lock
-- order (ADR-006 §6): after a request (8) and its reservation (11), before the
-- audit head (12).
--
-- A row points at its agent's month (agent_periods, 0040), the lock every
-- monthly check serialises on, so none is made without it. Its agent, month and
-- currency never change (`fixed_at_creation`, 0035's guard): the app may write
-- them only as the audit module's record seals a new row, with the same values.
-- The organisation's months held before it was moved to these totals are opened
-- by the API from its signed spend requests, never from its reservations.
--
-- The app adds rows and reads them, and changes only the sealed fields and the
-- two signed-state columns, which the audit module's record writes and seals
-- together. It never deletes one (no grant). The backup role reads everything.

CREATE TABLE limit_reservations.month_totals (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  agent_id uuid NOT NULL,
  -- `YYYY-MM`, as `periodOf` names the month in the agent's zone (0040).
  month text NOT NULL CHECK (month ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  -- Minor units: never a float, never below nothing.
  held_minor bigint NOT NULL CHECK (held_minor >= 0),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_total_a_month UNIQUE (org_id, agent_id, month, currency),
  CONSTRAINT in_its_agents_period FOREIGN KEY (org_id, agent_id, month)
    REFERENCES limit_reservations.agent_periods (org_id, agent_id, month)
);

ALTER TABLE limit_reservations.month_totals ENABLE ROW LEVEL SECURITY;
ALTER TABLE limit_reservations.month_totals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON limit_reservations.month_totals
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON limit_reservations.month_totals
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed('agent_id', 'month', 'currency', 'created_at');

GRANT SELECT, INSERT ON limit_reservations.month_totals TO agentx_app;
-- agent_id, month, currency and created_at only as the audit module's record seals a new total, unchanged:
-- `fixed_at_creation`.
GRANT UPDATE (agent_id, month, currency, held_minor, created_at, state_version, state_event_id)
  ON limit_reservations.month_totals TO agentx_app;
GRANT SELECT ON limit_reservations.month_totals TO agentx_backup;
