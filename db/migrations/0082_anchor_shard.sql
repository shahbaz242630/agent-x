-- PL-65 PR4: each organisation's shard in the anchors' store, kept beside its ID, so the
-- anchor check's list comes shard by shard (anchor-check.ts's walk): the first byte of
-- the SHA-256 of its chain's name, `organisation:<id>`, as shards.ts's shardOf gives it.
-- A golden test holds the two to the same vectors on every Postgres the suite runs.
-- The ID as Postgres prints a uuid (lower case, hyphens) is what the anchors name: ASCII
-- alone, so its bytes are the same in any encoding, and the cast to bytea reads no escape
-- in it. Every function here is immutable, as a generated column needs.
--
-- STORED, as Postgres 16 has no other kind, and an index needs one on 18 too. Adding it
-- rewrites directory.orgs, holding it to itself for that time. Judged and taken: the table
-- is IDs only (about 40 bytes a row, some 180 rows a page), so at the ~10,000 organisations
-- this must carry before Phase 6 the rewrite is some 60 pages, a few milliseconds, and at a
-- million about a second; production is not live yet, so it runs there on a near-empty
-- table. The wait for the lock is the runner's own (migrate.ts: 2 s a try, 5 tries), so it
-- never queues behind a long read for longer than that, and the app's statements never
-- queue behind it for longer either. The index is built concurrently in 0083, holding no
-- write back at any size.
--
-- No grant changes: the app's SELECT and INSERT on the table cover the column, and a
-- generated column can't be written. CI-06's list of the table's columns names it
-- (schema-policy.ts).
ALTER TABLE directory.orgs
  ADD COLUMN anchor_shard smallint NOT NULL
  GENERATED ALWAYS AS (
    pg_catalog.get_byte(pg_catalog.sha256(('organisation:' || org_id::text)::bytea), 0)::smallint
  ) STORED;
