-- No organisation may have the nil ID (Phase 6 6F1 gate, AG10). The code
-- reads 00000000-0000-0000-0000-000000000000 as no organisation at all: a
-- person's own idempotency keys are kept under it (my-activity.ts
-- PERSON_KEYS_TENANT), and an agent key's or connection's check reads under it
-- when its organisation isn't listed, so that nothing is found. An
-- organisation listed with that ID would see those keys and rows as its own.
-- Its ID comes from our own generator today; this holds it in the database,
-- whatever writes the row. A database already holding the row fails here,
-- loudly, rather than carrying on.

ALTER TABLE directory.orgs
  ADD CONSTRAINT orgs_not_the_nil_id CHECK (org_id <> '00000000-0000-0000-0000-000000000000'::uuid);
