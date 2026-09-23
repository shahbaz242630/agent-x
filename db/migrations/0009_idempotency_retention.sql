-- The idempotency keys' retention (B1e, ADR-014 §3: 30 days by default). A
-- key is kept 30 days after its claim, then the retention sweep deletes it,
-- one organisation at a time inside its own withTenant.
--
-- The app may delete a key only once it is past its retention, never before:
-- a key deleted early would let a retry do its write again. The rule is the
-- database's own, a restrictive policy for DELETE beside the tenant policy,
-- so a DELETE the app sends is held to both: its own organisation's rows,
-- and only those claimed more than 30 days ago. created_at is written with
-- the claim (the app can't change it afterwards: it may update only a key's
-- result), so no key reaches its retention early.
--
-- CI-06 and the live schema guard hold this table to exactly these two
-- policies, the retention one reading exactly so (the schema policy's
-- `sweptAfter`).

CREATE POLICY retention ON idempotency.keys AS RESTRICTIVE FOR DELETE
  USING (created_at < pg_catalog.now() - pg_catalog.make_interval(days => 30));

GRANT DELETE ON idempotency.keys TO agentx_app;
