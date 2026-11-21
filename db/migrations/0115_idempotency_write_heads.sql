-- Each idempotent write's own chain head, kept with its answer (TR-1, Threat-Model R-16; plan Section 1).
--
-- A write's answer goes out only once its chain head is outside the database (the witness log); a head that couldn't
-- be written answers 503, the change saved. Sent again under its key, the write is answered from this row, writing
-- nothing: before it may say "done", the app holds the chain to the head the first write left. So the row keeps that
-- head: its place (`head_seq`) and its event's hash (`head_hash`), the organisation's chain at the write's last event,
-- and a MAC over them and the key's own names (`head_mac`, the app's `request-hash` key, which the database never holds,
-- at `head_mac_key_version`). A replay whose head is gone from the chain, or another event there, is the chain cut
-- back: the alarm and the hold, and 503, never the stored answer. A write that recorded no chain event keeps the MAC of
-- none, so a head taken away from a row reads as tampering too.
--
-- Filled in once, with the result, by the claiming transaction. Rows from before this migration have none: they are
-- answered as before, the head as it then stands witnessed (packages/platform/src/db/idempotency.ts).

ALTER TABLE idempotency.keys
  ADD COLUMN head_seq bigint CHECK (head_seq >= 1),
  ADD COLUMN head_hash bytea CHECK (pg_catalog.octet_length(head_hash) = 32),
  ADD COLUMN head_mac bytea CHECK (pg_catalog.octet_length(head_mac) = 32),
  ADD COLUMN head_mac_key_version integer CHECK (head_mac_key_version >= 1),
  ADD CHECK ((head_seq IS NULL) = (head_hash IS NULL)),
  ADD CHECK ((head_mac IS NULL) = (head_mac_key_version IS NULL));

GRANT UPDATE (head_seq, head_hash, head_mac, head_mac_key_version) ON idempotency.keys TO agentx_app;
