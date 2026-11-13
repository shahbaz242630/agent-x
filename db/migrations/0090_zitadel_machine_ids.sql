-- SA3e: the 16-bit machine IDs Zitadel's copies tell their own IDs apart by. Zitadel
-- (v4.17.3, internal/id/sonyflake.go) mints each ID from the time, a counter and its
-- process's machine ID; two copies holding the same machine ID can mint the same ID in
-- the same 10 ms, which may merge two of its records. Hashing each copy's hostname into
-- 16 bits (S19) lets two copies collide by chance. So each Zitadel process asks the API
-- for one at start (apps/api/src/machine-ids.ts), and the API hands them out in turn
-- from this sequence: two live copies share one only after 65,536 starts.
--
-- A sequence, not a table: no row to wall in, no organisation's data. It cycles over the
-- 16 bits itself, so a value is a machine ID as it is. The app draws from it (USAGE gives
-- nextval) and nothing else; the backup role reads it, as a logical backup reads every
-- object. Drawing a number changes no row, so the append-only schema's rule holds.
CREATE SEQUENCE platform_controls.zitadel_machine_ids AS integer MINVALUE 0 MAXVALUE 65535 START WITH 0 CYCLE;

GRANT USAGE ON SEQUENCE platform_controls.zitadel_machine_ids TO agentx_app;
GRANT SELECT ON SEQUENCE platform_controls.zitadel_machine_ids TO agentx_backup;
