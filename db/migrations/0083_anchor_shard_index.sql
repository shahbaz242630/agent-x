-- agentx: no transaction (concurrent index)
-- PL-65 PR4: the anchor check's list read shard by shard, in pages along this index
-- (listedByShard): its shard, then its ID, so each page is a range of it and no read
-- sorts the table. Built concurrently, outside a transaction (the first line; migrate.ts),
-- as 0074's and 0081's: organisations are added while it builds, at any size; its lock
-- holds back only other changes to the table's shape or a VACUUM. directory.orgs is
-- global, IDs only: no tenant wall to lead with. No table, column or grant changes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS orgs_by_anchor_shard ON directory.orgs (anchor_shard, org_id);
