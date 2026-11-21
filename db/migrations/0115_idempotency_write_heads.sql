-- Each idempotent write's own chain heads, kept with its answer (TR-1, Threat-Model R-16; plan Section 1).
--
-- A write's answer goes out only once its chain heads are outside the database (the witness log); a head that couldn't
-- be written answers 503, the change saved. Sent again under its key, the write is answered from this row, writing
-- nothing: before it may say "done", the app holds the chains to the heads the first write left. So the row keeps them:
-- the organisation's chain at the write's last event (`head_seq`, `head_hash`), and the platform chain's where the write
-- recorded there too (`platform_head_seq`, `platform_head_hash`), with a MAC over both and the key's own names
-- (`head_mac`, the app's `request-hash` key, which the database never holds, at `head_mac_key_version`). A replay whose
-- head is gone from its chain, or another event there, is the chain cut back: the alarm and the hold, and 503, never
-- the stored answer. A write that recorded no chain event keeps the MAC of none.
--
-- Every row made from this release on has its request hash over a versioned message (`v2`), and must carry the MAC: one
-- whose request verifies as v2 with the MAC taken away is tampering at once. Only a row whose request verifies as the
-- message before (v1), made before this release, is answered as it was (packages/platform/src/db/idempotency.ts).
--
-- Filled in once, with the result, by the claiming transaction.

ALTER TABLE idempotency.keys
  ADD COLUMN head_seq bigint CHECK (head_seq >= 1),
  ADD COLUMN head_hash bytea CHECK (pg_catalog.octet_length(head_hash) = 32),
  ADD COLUMN platform_head_seq bigint CHECK (platform_head_seq >= 1),
  ADD COLUMN platform_head_hash bytea CHECK (pg_catalog.octet_length(platform_head_hash) = 32),
  ADD COLUMN head_mac bytea CHECK (pg_catalog.octet_length(head_mac) = 32),
  ADD COLUMN head_mac_key_version integer CHECK (head_mac_key_version >= 1),
  ADD CHECK ((head_seq IS NULL) = (head_hash IS NULL)),
  ADD CHECK ((platform_head_seq IS NULL) = (platform_head_hash IS NULL)),
  ADD CHECK ((head_mac IS NULL) = (head_mac_key_version IS NULL));

GRANT UPDATE (head_seq, head_hash, platform_head_seq, platform_head_hash, head_mac, head_mac_key_version)
  ON idempotency.keys TO agentx_app;
