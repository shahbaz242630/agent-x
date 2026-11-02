-- 4D2e D5: an integrity hold that couldn't be written, kept outside the process.
--
-- A hold's transaction can fail (the chain head locked past 5 s, a chain that
-- refuses new events). Until now the hold then waited in that one process's
-- memory: a second process read the hold as clear, and a restart forgot it. Now
-- it also leaves a row here, read by the hand-off's Tx A under the head's lock
-- and polled by every process, and goes in the transaction that records the hold.
--
-- Global because the work reaching it runs before any organisation is chosen:
-- a poll across organisations, with no tenant wall to read behind. So it holds
-- IDs and words the app chose: the organisation, the record's type and ID, and
-- how the tampering showed. Those two name the record as a hold found directly
-- names it, as clearing checks what the hold names, whichever process recorded it.
--
-- One row a record: a second finding on another record is a row of its own,
-- written in the transaction that finds the hold names another. A hold names one
-- record, so that row stays while the hold stands, and becomes the next hold once
-- it is cleared: its own investigation, and its own check.
--
-- A row only adds caution, and that caution is real: a row forged really sets the
-- hold, stopping the organisation's hand-offs. One foothold as the app role can so
-- hold every organisation. No payment passes because of a row; each hold set from
-- one raises the integrity alarm, as does each row a process first finds on a record
-- not the one held; and each clear needs an investigation and a passkey. A forged
-- row naming a record that never was can still be cleared: nothing to repair.
-- No read treats a row's absence as a hold lifted: that is the signed
-- state's. A row deleted past the app is seen by each process that held it
-- (with-signed-states.ts); once every such process has restarted too, it is gone,
-- leaving the alarm's line, and the tampering sets its hold when next found.
--
-- The key to the directory's list: a forged row can't start a chain for an
-- organisation that doesn't exist. The checks hold a row to what the app can
-- write: every finding names a UUID in lower case (a record's own, or the
-- organisation's for its chain) and a type as the audit log holds one. A row
-- past them could never be recorded, so stop payments for good; one that still
-- arrives, these checks dropped, is recorded under a fixed name instead.
CREATE TABLE directory.holds_waiting (
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id),
  subject_type text NOT NULL CHECK (subject_type ~ '^[a-z][a-z_]{0,62}$'),
  object_id text NOT NULL CHECK (object_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  reason text NOT NULL CHECK (reason ~ '^[a-z][a-z_]{0,31}$'),
  PRIMARY KEY (org_id, subject_type, object_id)
);

GRANT SELECT, INSERT, DELETE ON directory.holds_waiting TO agentx_app;
GRANT SELECT ON directory.holds_waiting TO agentx_backup;
