-- An order's claim kept as a signed slot (TR-2; Threat-Model R-15, gap map
-- 21 Nov; ADR-006 §6 and §11, as amended; ADR-014 §3; ADR-012 §2).
--
-- Until now a decision looked for a duplicate order among the open order claims
-- (0039, 0043). Claims are unsealed: the database's owner could release or
-- delete the claim of an order already paid, and the same invoice was then
-- decided, approved and handed off again, found only by the holdings check 15
-- minutes to an hour later. Sealing the claim rows themselves can't catch that:
-- a claim deleted is simply absent, and absent is what an order never claimed
-- looks like.
--
-- spend_requests.order_slots names each place an order can be claimed, so a
-- slot deleted reads as deleted, never as free: an authority table, read and
-- changed through its signed state in the same transactions that claim and
-- release. Four kinds, as the claims are looked at:
-- - `supplier_order`: the supplier and the order's canonical form (0067);
-- - `payee_order`: the payee key and the order's canonical form (ADR-014 §3);
-- - `supplier_bank`: the supplier and the order as the bank would carry it
--   (0043's bank key, decision 11a);
-- - `payee_bank`: the payee key and that bank key.
-- `key_hash` is the SHA-256 of the canonical form (or the bank key), in hex: the
-- reference itself never goes in a seal. `holders` is who holds the slot: for
-- an order kind, '' or the one request that claims it (one open claim an order,
-- as 0039's partial unique indexes); for a bank kind, every request claiming an
-- order the bank would carry alike, each as the first 16 hex of its order's
-- hash and its ID, in order, comma between, so a lookalike in another form is
-- seen (a possible duplicate). A request paid holds its slots for good; only
-- an ending without a payment, or a payment's verified failure, lets go.
--
-- Sealed: its kind, supplier or payee key, key hash, holders and when it was
-- made. Its ID is named by its organisation, kind, supplier or key and key hash
-- (a SHA-256, the app's `namedId`), so a row deleted reads as deleted (its signed
-- events are still in the log), never as an order no one claims. At level 11c in
-- the lock order (ADR-006 §6): after a request (8), its reservation and claim
-- (11), its agent's month total (11a) and its payee's windows (11b), before the
-- audit head (12); a holder of several takes them in order of ID.
--
-- Its kind, supplier, key, key hash and making never change (`fixed_at_creation`,
-- 0035's guard): the app may write them only as the audit module's record seals
-- a new row, with the same values. The organisation's slots held before it was
-- moved to these rows are opened by the API from its signed spend requests,
-- never from its claims.
--
-- The app adds rows and reads them, and changes only the sealed fields and the
-- two signed-state columns, which the audit module's record writes and seals
-- together. It never deletes one (no grant). The backup role reads everything.

CREATE TABLE spend_requests.order_slots (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('supplier_order', 'payee_order', 'supplier_bank', 'payee_bank')),
  supplier_id uuid,
  -- As a supplier's (0032): our keyed fingerprint of the payee, printable ASCII.
  payee_key text CHECK (payee_key ~ '^[!-~]{1,128}$'),
  -- SHA-256 in lower-case hex: text, as a signed field is read as text, a uuid, a whole number or a time alone.
  key_hash text NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
  holders text NOT NULL CHECK (
    holders ~ '^(|[0-9a-f-]{36}|[0-9a-f]{16}:[0-9a-f-]{36}(,[0-9a-f]{16}:[0-9a-f-]{36})*)$'
    AND pg_catalog.length(holders) <= 4096
  ),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT a_supplier_or_a_payee CHECK (
    (kind IN ('supplier_order', 'supplier_bank') AND supplier_id IS NOT NULL AND payee_key IS NULL)
    OR (kind IN ('payee_order', 'payee_bank') AND supplier_id IS NULL AND payee_key IS NOT NULL)
  ),
  CONSTRAINT one_slot_an_order UNIQUE NULLS NOT DISTINCT (org_id, kind, supplier_id, payee_key, key_hash),
  CONSTRAINT on_a_supplier FOREIGN KEY (org_id, supplier_id) REFERENCES suppliers.suppliers (org_id, id)
);

ALTER TABLE spend_requests.order_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_requests.order_slots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON spend_requests.order_slots
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON spend_requests.order_slots
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed('kind', 'supplier_id', 'payee_key', 'key_hash', 'created_at');

GRANT SELECT, INSERT ON spend_requests.order_slots TO agentx_app;
-- kind, supplier_id, payee_key, key_hash and created_at only as the audit module's record seals a new slot,
-- unchanged: `fixed_at_creation`.
GRANT UPDATE (kind, supplier_id, payee_key, key_hash, holders, created_at, state_version, state_event_id)
  ON spend_requests.order_slots TO agentx_app;
GRANT SELECT ON spend_requests.order_slots TO agentx_backup;
