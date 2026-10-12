-- Possible duplicate orders (partner decision 11a, S101; Phase 2 G5a): a
-- request whose order reference becomes the same bank reference as an open
-- claim's, on the same supplier or payee key, goes to approval as a possible
-- duplicate (`INV_22` and `INV-22`; Arabic and ASCII digits). The exact
-- duplicate, by `order_reference` (the canonical form), stays refused.
--
-- `bank_key` is the claim's order reference as the rail would carry it, in
-- lower case (the app's `bankKeyOf`, as the bank reference is the app's: the
-- mapping takes Unicode digits and accents apart, which SQL doesn't); null
-- when no letter or digit is left, so the request would be paid under its own
-- ID and no other can look like it. Claims made before it have none.
--
-- Not unique: a possible duplicate is claimed beside the open claim it looks
-- like, while it waits for approval. Two partial indexes, as 0039's keys, so
-- the look stays a short scan; a release stays a no-key write (ADR-006 §6),
-- as `released_at` is in neither. The holdings check compares each claim's
-- `bank_key` with its request's, as the app makes it, so one changed past
-- the app raises the alarm. No grant changes: the app's INSERT is the
-- table's, its UPDATE `released_at` alone.

ALTER TABLE spend_requests.order_claims
  ADD COLUMN bank_key text CHECK (bank_key ~ '^[a-z0-9 /?:().,''+-]{1,35}$');

CREATE INDEX open_claims_a_supplier_bank_key ON spend_requests.order_claims (org_id, supplier_id, bank_key)
  WHERE released_at IS NULL AND bank_key IS NOT NULL;
CREATE INDEX open_claims_a_payee_bank_key ON spend_requests.order_claims (org_id, payee_key, bank_key)
  WHERE released_at IS NULL AND payee_key IS NOT NULL AND bank_key IS NOT NULL;
