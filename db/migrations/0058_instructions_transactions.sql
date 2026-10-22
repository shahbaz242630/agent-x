-- The one logical instruction a spend request hands to the partner, and the
-- transaction that follows its outcome (PRD §3 `ProviderInstruction`,
-- `Transaction`, §4.3; ADR-007 §7–§13; ADR-014 §1–§2; BR-12–BR-14; Phase 4
-- B3). The hand-off (B4) writes both in its Tx A, with the request's move to
-- HANDED_OFF; nothing else makes either.
--
-- instructions.instructions: the approved intent as it was handed off, made
-- once and never changed (0032's `made_once`, as a supplier's version), an
-- authority table whose every field is its signed event's
-- (`instruction.made`): the route and its reason, the partner and its legal
-- entity and licence references copied at hand-off (so a later config change
-- can't rewrite evidence, PRD §3), the consent, the payee's reference from the
-- verified supplier version (never from the request), the amount, the rail's
-- payment reference, and the intent's SHA-256. Its ID is ours and the
-- partner's idempotency key. **One a spend request** (`one_instruction_a_request`):
-- however many workers run the same hand-off, a second instruction for a
-- request can't be made (ADR-007 §7, SEC-DP-01).
--
-- transactions.transactions: the single source of truth for the outcome
-- (PRD §3, §4.2: after HANDED_OFF the request's outcome is its transaction's),
-- one an instruction, an authority table with its status machine (PRD §4.3)
-- held by the status guard: born SUBMISSION_PENDING (ADR-007 §7 step 5; PRD's
-- CREATED is never stored, as the instruction and its transaction are made
-- together), then as the partner's answers and events move it. The partner's
-- own status, its reference for the instruction, its reject code and when it
-- says the status changed are kept beside it (PRD §6.2), signed too.
--
-- directory.instructions: an instruction's ID and its organisation, added in
-- Tx A, so a partner's event naming only our instruction ID can be routed to
-- its organisation before any organisation is known (ADR-005; ADR-007 §7 step
-- 6, §12), as an agent key's is (0027).

CREATE SCHEMA instructions;
GRANT USAGE ON SCHEMA instructions TO agentx_app, agentx_backup;

CREATE TABLE instructions.instructions (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  spend_request_id uuid NOT NULL,
  route text NOT NULL CHECK (route IN ('push')),
  route_reason text NOT NULL CHECK (route_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
  funding_source_id uuid NOT NULL,
  partner text NOT NULL CHECK (partner ~ '^[a-z][a-z0-9_]{0,31}$'),
  partner_legal_entity_id text NOT NULL CHECK (partner_legal_entity_id ~ '^[!-~]{1,128}$'),
  partner_licence_ref text NOT NULL CHECK (partner_licence_ref ~ '^[!-~]{1,128}$'),
  account_consent_id text NOT NULL CHECK (account_consent_id ~ '^[!-~]{1,128}$'),
  beneficiary_ref text NOT NULL CHECK (beneficiary_ref ~ '^[!-~]{1,128}$'),
  supplier_version_id uuid NOT NULL,
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  payment_reference text NOT NULL CHECK (payment_reference ~ '^[A-Za-z0-9 /?:().,''+-]{1,35}$'),
  intent_hash text NOT NULL CHECK (intent_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_instruction_a_request UNIQUE (org_id, spend_request_id),
  CONSTRAINT of_a_spend_request FOREIGN KEY (org_id, spend_request_id) REFERENCES spend_requests.requests (org_id, id)
);

ALTER TABLE instructions.instructions ENABLE ROW LEVEL SECURITY;
ALTER TABLE instructions.instructions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON instructions.instructions
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER made_once BEFORE UPDATE ON instructions.instructions
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_made_once();

GRANT SELECT, INSERT ON instructions.instructions TO agentx_app;
-- Only as the audit module's record seals a new instruction: `made_once` refuses any change after.
GRANT UPDATE (
  spend_request_id, route, route_reason, funding_source_id, partner, partner_legal_entity_id, partner_licence_ref,
  account_consent_id, beneficiary_ref, supplier_version_id, amount_minor, currency, payment_reference, intent_hash,
  created_at, state_version, state_event_id
) ON instructions.instructions TO agentx_app;
GRANT SELECT ON instructions.instructions TO agentx_backup;

CREATE SCHEMA transactions;
GRANT USAGE ON SCHEMA transactions TO agentx_app, agentx_backup;

CREATE TABLE transactions.transactions (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  instruction_id uuid NOT NULL,
  status text NOT NULL CHECK (
    status IN ('SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'UNKNOWN', 'REVERSED')
  ),
  provider_status text CHECK (provider_status ~ '^[A-Za-z]{1,64}$'),
  payment_instruction_ref text CHECK (payment_instruction_ref ~ '^[!-~]{1,128}$'),
  reject_code text CHECK (reject_code ~ '^[!-~]{1,64}$'),
  provider_changed_at timestamptz CHECK (pg_catalog.isfinite(provider_changed_at)),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_transaction_an_instruction UNIQUE (org_id, instruction_id),
  CONSTRAINT of_an_instruction FOREIGN KEY (org_id, instruction_id) REFERENCES instructions.instructions (org_id, id)
);

ALTER TABLE transactions.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions.transactions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON transactions.transactions
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON transactions.transactions
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed('instruction_id', 'created_at');

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON transactions.transactions
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'SUBMISSION_PENDING', 'SUBMISSION_PENDING>SUBMITTED', 'SUBMITTED>PROCESSING',
    'SUBMITTED>SUCCEEDED', 'PROCESSING>SUCCEEDED', 'UNKNOWN>SUCCEEDED',
    'SUBMISSION_PENDING>FAILED', 'SUBMITTED>FAILED', 'PROCESSING>FAILED', 'UNKNOWN>FAILED',
    'SUBMITTED>CANCELLED', 'PROCESSING>CANCELLED', 'UNKNOWN>CANCELLED',
    'SUBMISSION_PENDING>UNKNOWN', 'SUBMITTED>UNKNOWN', 'PROCESSING>UNKNOWN',
    'SUCCEEDED>REVERSED'
  );

GRANT SELECT, INSERT ON transactions.transactions TO agentx_app;
GRANT UPDATE (
  instruction_id, status, provider_status, payment_instruction_ref, reject_code, provider_changed_at, created_at,
  state_version, state_event_id
) ON transactions.transactions TO agentx_app;
GRANT SELECT ON transactions.transactions TO agentx_backup;

CREATE TABLE directory.instructions (
  instruction_id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES directory.orgs (org_id)
);

GRANT SELECT, INSERT ON directory.instructions TO agentx_app;
GRANT SELECT ON directory.instructions TO agentx_backup;
