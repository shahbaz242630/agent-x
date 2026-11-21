-- A payee's split window kept as signed hourly totals (GM-1b; Threat-Model
-- R-15, gap map 20 Nov; ADR-006 §8 and §9, as amended; ADR-014 §5; ADR-012 §2).
--
-- Until now a decision with its mandate's split check on summed the payee's
-- unreleased reservations reserved in the mandate's rolling window, across the
-- organisation's agents (0040, 0041). Reservations are unsealed: the database's
-- owner could delete, zero or release a payee's reservations, and a payment
-- split to stay under the approval threshold went through without its approval,
-- found only by the holdings check 15 minutes to an hour later.
--
-- limit_reservations.payee_windows is what a payee's reservations hold, hour by
-- hour, for as far back as any split window reaches (31 days and an hour): an
-- authority table, read and changed through its signed state, kept in the same
-- transactions that reserve and release. A decision adds its amount at its own
-- hour; an ending or a payment's release takes it off the hour it was added at.
-- The split check counts the payee as before (ADR-014 §3): its supplier, or its
-- payee key where it has one. Each reservation is counted in three rows: its
-- supplier's (`payee_key` null), its key's (`supplier_id` null) and the pair's
-- (both), so a payee's window is its supplier's and its key's, less the pair's
-- counted in both. A supplier with no key is counted in its own row alone.
--
-- Sealed: whose window it is (its supplier, its key, either or both), its
-- currency, `held_by_hour` (each hour since 1970 that holds anything, in
-- order, with the minor units it holds: `hour:amount`, comma between, none
-- for an hour holding nothing), and when it was made. Its ID is named by its
-- organisation, supplier, key and currency (a SHA-256, the app's `namedId`), so
-- a row deleted reads as deleted, never as a payee with nothing held. At level
-- 11b in the lock order (ADR-006 §6): after a request (8), its reservation (11)
-- and its agent's month total (11a), before the audit head (12).
--
-- Its supplier, key and currency never change (`fixed_at_creation`, 0035's
-- guard): the app may write them only as the audit module's record seals a new
-- row, with the same values. The organisation's windows held before it was
-- moved to these rows are opened by the API from its signed spend requests,
-- never from its reservations.
--
-- The app adds rows and reads them, and changes only the sealed fields and the
-- two signed-state columns, which the audit module's record writes and seals
-- together. It never deletes one (no grant). The backup role reads everything.

CREATE TABLE limit_reservations.payee_windows (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  supplier_id uuid,
  -- As a supplier's (0032): our keyed fingerprint of the payee, printable ASCII.
  payee_key text CHECK (payee_key ~ '^[!-~]{1,128}$'),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  -- `hour:amount` pairs, comma between, each amount at least 1 minor unit; the app holds them in order, each once.
  held_by_hour text NOT NULL CHECK (
    held_by_hour ~ '^([0-9]{1,9}:[1-9][0-9]{0,18}(,[0-9]{1,9}:[1-9][0-9]{0,18})*)?$'
    AND pg_catalog.length(held_by_hour) <= 32768
  ),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT a_payee_named CHECK (supplier_id IS NOT NULL OR payee_key IS NOT NULL),
  CONSTRAINT one_window_a_payee UNIQUE NULLS NOT DISTINCT (org_id, supplier_id, payee_key, currency)
);

ALTER TABLE limit_reservations.payee_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE limit_reservations.payee_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON limit_reservations.payee_windows
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON limit_reservations.payee_windows
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed('supplier_id', 'payee_key', 'currency', 'created_at');

GRANT SELECT, INSERT ON limit_reservations.payee_windows TO agentx_app;
-- supplier_id, payee_key, currency and created_at only as the audit module's record seals a new window, unchanged:
-- `fixed_at_creation`.
GRANT UPDATE (supplier_id, payee_key, currency, held_by_hour, created_at, state_version, state_event_id)
  ON limit_reservations.payee_windows TO agentx_app;
GRANT SELECT ON limit_reservations.payee_windows TO agentx_backup;
