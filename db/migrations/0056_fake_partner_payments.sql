-- The fake partner's payments (Phase 4 B2; ADR-004 §8; rail map §3–§4): the
-- fake adapter now takes a policy-approved payment intent and holds the
-- payment it made, as a partner would, by our instruction ID (the rail's
-- idempotency key) with the partner's own reference as its alias. A record
-- like the others (0028): the partner's, never Agent X's; staging's alone, as
-- the fake is never chosen in production; behind the tenant walls; never
-- deleted. A payment's body names the consent, the payee's reference, the
-- amount and the payment reference: no account number.

ALTER TABLE fake_partner.records
  DROP CONSTRAINT records_kind_check,
  ADD CONSTRAINT records_kind_check CHECK (kind IN ('link', 'source', 'registration', 'payment'));
