-- The split total's reads (PRD §3.2; ADR-006 §9, ADR-012 §4, ADR-014 §3 and
-- §5; BR-22; SEC-LIM-04; Phase 2 D5a): with a mandate's split check on, a
-- decision adds up the same payee's reservations still holding capacity
-- (every state but RELEASED) reserved within the mandate's rolling window,
-- across every agent of the organisation. The payee is its payee key where
-- the supplier has one, and its supplier otherwise; a decision reads both, so
-- a supplier's reservations made before it had a key still count.
--
-- Two indexes, one for each way a payee is named, each holding only what can
-- still count, so the read stays a short range scan however many requests an
-- organisation has made. No table, column or grant changes.

CREATE INDEX held_for_a_supplier ON limit_reservations.reservations (org_id, supplier_id, reserved_at)
  WHERE state <> 'RELEASED';

CREATE INDEX held_for_a_payee ON limit_reservations.reservations (org_id, payee_key, reserved_at)
  WHERE state <> 'RELEASED' AND payee_key IS NOT NULL;
