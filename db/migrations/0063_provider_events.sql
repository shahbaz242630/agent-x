-- The front door for the partner's messages (Phase 4 E1b; ADR-007 §12–13;
-- rail map §1.8; SEC-PTR-01–06). A message from the partner is only a nudge:
-- its signature is checked over the raw body first, then the bank's status
-- query (E1a's check) decides what the payment is, never the message.
--
-- - `provider_events.inbox`: one row per verified message, keyed by the
--   partner and the message's dedupe key (its event ID where it has one,
--   otherwise the SHA-256 of its verified body: the rail's messages carry no
--   ID), so a replay adds nothing (SEC-PTR-03). It holds what the message
--   names (our instruction ID, or a consent alone) and the organisation it
--   was routed to; none where the reference is unknown (SEC-PTR-05), whose
--   body alone is kept, encrypted, for investigation. E1a's check takes each
--   row once (`taken_at`), trying it at most 5 times (`attempts`). Global: a message arrives before any organisation
--   is known. Kept for the security events' retention, then swept.
-- - `security.partner_event_evidence`: a refused message (a bad signature, a
--   time outside the window, a malformed body) kept as security evidence,
--   encrypted, size-capped, the first few an hour per network and a few
--   dozen from all (SEC-PTR-01);
--   the rest are counted in `security.events` (`partner_event_refused`).
-- - `fake_partner.event_keys`: the fake partner's own signing key, made by
--   the API the first time it is needed, so no key sits in the code. Read by
--   the fake's verifier and its test sender alone; the real partner's keys
--   come with Phase 5.
-- - `directory.instructions.account_consent_id`: the consent an instruction
--   pays under, written with it in Tx A, so a message naming the consent alone
--   finds its payments. No fill: no environment has handed a payment off yet
--   (staging's log, S138); one written before this is left without it and
--   found by its instruction ID alone.
-- - Two partial indexes on the transactions under way: E1a's listing, and
--   the hand-off's sweep of SUBMISSION_PENDING (Carry-Forward).

CREATE SCHEMA provider_events;
GRANT USAGE ON SCHEMA provider_events TO agentx_app, agentx_backup;

CREATE TABLE provider_events.inbox (
  id uuid PRIMARY KEY,
  partner text NOT NULL CHECK (partner ~ '^[a-z][a-z0-9_-]{0,31}$'),
  dedupe_key text NOT NULL CHECK (pg_catalog.length(dedupe_key) BETWEEN 1 AND 200),
  event_type text NOT NULL CHECK (pg_catalog.length(event_type) BETWEEN 1 AND 100),
  reference_kind text NOT NULL CHECK (reference_kind IN ('instruction', 'consent')),
  reference text NOT NULL CHECK (pg_catalog.length(reference) BETWEEN 1 AND 200),
  -- The organisation it was routed to; null where the reference is unknown.
  org_id uuid,
  received_at timestamptz NOT NULL,
  -- When E1a's check took it; null until then, and for ever for one unknown.
  taken_at timestamptz,
  -- How many runs tried to take it: past 5 it is left to the regular check, never holding up the rest.
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000),
  -- An unknown reference's body, encrypted (field-encryption, bound to the row's ID).
  body_ciphertext bytea CHECK (pg_catalog.octet_length(body_ciphertext) BETWEEN 29 AND 65600),
  body_key_version integer CHECK (body_key_version >= 1),
  CONSTRAINT one_a_message UNIQUE (partner, dedupe_key),
  CONSTRAINT body_with_its_key CHECK ((body_ciphertext IS NULL) = (body_key_version IS NULL)),
  CONSTRAINT body_only_when_unknown CHECK (body_ciphertext IS NULL OR org_id IS NULL),
  CONSTRAINT unknown_never_taken CHECK (org_id IS NOT NULL OR taken_at IS NULL),
  CONSTRAINT taken_after_received CHECK (taken_at IS NULL OR taken_at >= received_at)
);

-- E1a's check takes the routed rows not yet taken, oldest first; the sweep the oldest.
CREATE INDEX inbox_waiting ON provider_events.inbox (received_at) WHERE taken_at IS NULL AND org_id IS NOT NULL;
CREATE INDEX inbox_by_age ON provider_events.inbox (received_at);

GRANT SELECT, INSERT, DELETE ON provider_events.inbox TO agentx_app;
GRANT UPDATE (taken_at, attempts) ON provider_events.inbox TO agentx_app;
GRANT SELECT ON provider_events.inbox TO agentx_backup;

CREATE TABLE security.partner_event_evidence (
  id uuid PRIMARY KEY,
  reason text NOT NULL CHECK (reason IN ('signature', 'stale', 'malformed')),
  -- The client's address as the API saw it; null if it had none it could read.
  ip inet,
  -- The refused body, encrypted (field-encryption, bound to the row's ID); at most 16 KiB before it.
  body_ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(body_ciphertext) BETWEEN 28 AND 16412),
  body_key_version integer NOT NULL CHECK (body_key_version >= 1),
  body_bytes integer NOT NULL CHECK (body_bytes BETWEEN 0 AND 16384),
  received_at timestamptz NOT NULL
);

-- The caps count the last hour; the sweep takes the oldest.
CREATE INDEX evidence_by_age ON security.partner_event_evidence (received_at);

GRANT SELECT, INSERT, DELETE ON security.partner_event_evidence TO agentx_app;
GRANT SELECT ON security.partner_event_evidence TO agentx_backup;

ALTER TABLE security.events DROP CONSTRAINT events_kind_check;
ALTER TABLE security.events
  ADD CONSTRAINT events_kind_check CHECK (kind IN ('sign_in_failed', 'rate_limited', 'partner_event_refused'));

CREATE TABLE fake_partner.event_keys (
  partner text PRIMARY KEY CHECK (partner ~ '^[a-z][a-z0-9_-]{0,31}$'),
  key bytea NOT NULL CHECK (pg_catalog.octet_length(key) = 32),
  created_at timestamptz NOT NULL
);

GRANT SELECT, INSERT ON fake_partner.event_keys TO agentx_app;
GRANT SELECT ON fake_partner.event_keys TO agentx_backup;

ALTER TABLE directory.instructions
  ADD COLUMN account_consent_id text CHECK (pg_catalog.length(account_consent_id) BETWEEN 1 AND 200);
CREATE INDEX instructions_by_consent ON directory.instructions (account_consent_id)
  WHERE account_consent_id IS NOT NULL;

CREATE INDEX transactions_under_way ON transactions.transactions (org_id, id)
  WHERE status IN ('SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN');
CREATE INDEX transactions_submission_pending ON transactions.transactions (org_id, created_at)
  WHERE status = 'SUBMISSION_PENDING';
