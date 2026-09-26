-- The notifications outbox (ADR-003 §10, ADR-005 §8, ADR-007; Phase 1 B5-1a):
-- a notice to one person, written in the same transaction as the change it
-- tells of, so it is never lost and never told of a change that rolled back.
-- The API's sender takes the due ones, sends each, and marks it sent; one
-- that fails is tried again later, and given up after a bounded number of
-- tries.
--
-- A row holds IDs and constants only: whom to tell (a user, whose address the
-- sender asks the login service for at send time, since Agent X keeps none),
-- in which organisation, what kind of notice, and about which membership and
-- role. Never an address, a name or free text.
--
-- A global table, on the CI-06 list (ADR-005 §8 names the job queue as one):
-- the sender works across every organisation. The app adds notices, reads
-- them, moves a notice's tries on and marks it sent or given up, and deletes
-- it once done and past its retention; it never changes whom or what a notice
-- is about. The backup role reads it, as it reads everything.

CREATE SCHEMA notifications;
GRANT USAGE ON SCHEMA notifications TO agentx_app, agentx_backup;

CREATE TABLE notifications.outbox (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id),
  recipient_user_id uuid NOT NULL REFERENCES identity.users (id),
  kind text NOT NULL CHECK (kind IN ('role_granted', 'member_rejoined')),
  -- The membership the notice is about, and the role it holds now.
  membership_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'approver', 'developer', 'viewer')),
  created_at timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts BETWEEN 0 AND 32),
  next_attempt_at timestamptz NOT NULL,
  sent_at timestamptz,
  given_up_at timestamptz,
  -- Why the last try failed, as a short constant; never the provider's words.
  last_failure text CHECK (last_failure ~ '^[a-z][a-z_]{0,63}$'),
  CONSTRAINT sent_or_given_up CHECK (sent_at IS NULL OR given_up_at IS NULL)
);

-- The sender takes the due notices, soonest first.
CREATE INDEX outbox_due ON notifications.outbox (next_attempt_at) WHERE sent_at IS NULL AND given_up_at IS NULL;
-- The sweep takes the oldest first.
CREATE INDEX outbox_by_age ON notifications.outbox (created_at);

GRANT SELECT, INSERT, DELETE ON notifications.outbox TO agentx_app;
GRANT UPDATE (attempts, next_attempt_at, sent_at, given_up_at, last_failure) ON notifications.outbox TO agentx_app;
GRANT SELECT ON notifications.outbox TO agentx_backup;
