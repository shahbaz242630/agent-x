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
-- an ID and how the tampering showed, nothing of the organisation's: what was
-- found, and on which record, stays in the alarm's own log line.
--
-- A row can only add caution. It is never read as clear, and no read treats its
-- absence as a hold lifted: that is the signed state's. A forged row causes a
-- hold attempt and a wait, never a payment. A row deleted past the app is seen
-- by each process that held it (with-signed-states.ts); once every such process
-- has restarted too, it is gone, leaving the alarm's line, and the tampering sets
-- its hold when next found.
--
-- The key to the directory's list: a forged row can't start a chain for an
-- organisation that doesn't exist.
CREATE TABLE directory.holds_waiting (
  org_id uuid PRIMARY KEY REFERENCES directory.orgs (org_id),
  reason text NOT NULL CHECK (reason ~ '^[a-z][a-z_]{0,31}$')
);

GRANT SELECT, INSERT, DELETE ON directory.holds_waiting TO agentx_app;
GRANT SELECT ON directory.holds_waiting TO agentx_backup;
