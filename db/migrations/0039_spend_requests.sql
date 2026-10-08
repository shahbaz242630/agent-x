-- An agent's spend requests and their order claims (PRD §3 `SpendRequest`,
-- §3.2, §4.2, §5.2; ADR-006 §5, §11; ADR-012 §2, §4; ADR-014 §3, §5, §8;
-- BR-09, BR-22; Phase 2 D1): what an agent asked to pay, the decision made on
-- it, and the claim that keeps one order from being paid twice. The
-- spend-requests module owns both tables (ADR-004), in a schema of its own.
-- The decision and the reservation through them come with D2–D4.
--
-- spend_requests.requests is one request, as the agent made it and as it was
-- decided. A tenant table and an authority table (ADR-012 §2: "any request
-- decision") at the request's level in the lock order (ADR-006 §6: 8). All of
-- it is sealed, and all but the status is fixed when the request is made
-- (`fixed_at_creation`), so neither the app nor an owner can change what was
-- asked or decided after the fact:
-- - who asked: the agent and the key it used (Carry-Forward, Phase 3: the
--   key on its evidence);
-- - what was asked, as the agent sent it: the amount in minor units (ADR-006
--   §1), its currency, the purpose, the supplier, the funding source, the
--   order reference as written (ADR-006 §5: the raw value, as evidence; the
--   claim keeps its canonical form), and its idempotency key (PRD §3; the
--   idempotency table's own row goes after its retention, this stays);
-- - what it was weighed against (PRD §5.2: "exact versions"): the mandate and
--   its version in force, the organisation's policy version and the mandate's
--   (none where none is set, so the default applied), the supplier's version;
-- - the decision (ALLOW, DENY, REQUIRE_APPROVAL or REQUIRE_NEW_MANDATE), its
--   reason codes in the order the engine checked them, each once (none for
--   ALLOW), and the keyed hash of everything weighed (C2's
--   `decisionInputText`), with the version of the key that made it.
--
-- What the agent asked is kept even when it isn't the organisation's to give:
-- a request naming another organisation's supplier or source, or made with no
-- mandate in force, is still recorded, DENIED, as evidence. So the supplier
-- and the source the agent named have no foreign key; the versions weighed do
-- (a supplier's version is its supplier's, a mandate's version its mandate's,
-- a policy's version the organisation's own policy or the mandate's), and a
-- request that holds capacity (ALLOW or REQUIRE_APPROVAL) must name the
-- mandate and supplier versions it rests on (ADR-006 §6: every decision
-- records the supplier version it was made against).
--
-- The status follows PRD §4.2. The decision is made on locked reads before
-- the row is added (ADR-006 §7), so the row is born VALIDATING with its
-- decision already in it, and moved by that decision in the same transaction
-- (DENIED, APPROVAL_REQUIRED or APPROVED): the status guard takes one first
-- status, and the audit trail then shows the request received and decided.
-- PRD's CREATED is the API's receipt, the idempotency key's claim, before any
-- row. Then: an approval waiting is approved, rejected (DENIED), expired or
-- cancelled; an approved request is made ready and handed off, or denied by
-- the re-check before hand-off, or cancelled. DENIED, EXPIRED, CANCELLED and
-- HANDED_OFF move no further (after hand-off the outcome is the transaction's,
-- PRD §4.2). `a_status_on_its_decision` holds each status to the decisions
-- that can reach it: nothing denied is ever approved.
--
-- spend_requests.order_claims is the database's safety net against paying
-- one order twice (ADR-006 §11, PRD §3.2, SEC-DP-10, SEC-PAY-06): a request
-- that holds capacity claims its order, by the organisation, the supplier and
-- the order reference's canonical form (ADR-006 §5: NFKC, trimmed,
-- case-folded, spaces collapsed; for the rail's ASCII references, lower case
-- with single spaces), and by the payee key too where the supplier has one
-- (ADR-014 §3: the same invoice to a supplier re-created with the same
-- account). One open claim a key: a second request for the same order waits
-- on the first and is refused. A claim is released (`released_at`) only when
-- its request ends DENIED, CANCELLED or EXPIRED, or its payment ends in a
-- verified FAILED or CANCELLED; UNKNOWN keeps it, as possibly paid. One claim
-- a request, on its request's own supplier. Not an authority table: claims,
-- like reservations, are checked against the signed decision and outcome
-- events by a scheduled reconciliation (ADR-012 §2; E1).
--
-- Both are of the organisation they belong to, row-level security forced.
-- The app adds rows and reads them; a request it changes only as the audit
-- module's record seals it (its status, and its fields only unchanged), a
-- claim only in its release. Never a delete: a request deleted would leave a
-- decision with no record, a claim deleted an order payable again. The backup
-- role reads everything, as it must for a logical backup.

CREATE SCHEMA spend_requests;
GRANT USAGE ON SCHEMA spend_requests TO agentx_app, agentx_backup;

CREATE TABLE spend_requests.requests (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  agent_id uuid NOT NULL,
  agent_key_id uuid NOT NULL,
  mandate_id uuid,
  mandate_version_id uuid,
  organization_policy_version_id uuid,
  mandate_policy_version_id uuid,
  supplier_id uuid NOT NULL,
  supplier_version_id uuid,
  funding_source_id uuid NOT NULL,
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL REFERENCES mandates.allowed_currencies (code),
  purpose text NOT NULL CHECK (pg_catalog.char_length(purpose) BETWEEN 1 AND 200 AND purpose !~ '[[:cntrl:]]'),
  -- As the agent wrote it: the rail's creditor reference, 1 to 35 of its ASCII
  -- characters, not blank (the rail map; checked at our edge too).
  order_reference text NOT NULL CHECK (order_reference ~ '^[A-Za-z0-9 /?:().,''+-]{1,35}$' AND order_reference ~ '[^ ]'),
  idempotency_key text NOT NULL CHECK (pg_catalog.octet_length(idempotency_key) BETWEEN 1 AND 255),
  input_hash text NOT NULL CHECK (input_hash ~ '^[0-9a-f]{64}$'),
  input_hash_key_version integer NOT NULL CHECK (input_hash_key_version >= 1),
  decision text NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'REQUIRE_NEW_MANDATE')),
  reason_codes text CHECK (pg_catalog.char_length(reason_codes) <= 1000 AND reason_codes ~ '^[A-Z][A-Z0-9_]*( [A-Z][A-Z0-9_]*)*$'),
  status text NOT NULL CHECK (
    status IN (
      'VALIDATING', 'DENIED', 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF', 'EXPIRED', 'CANCELLED'
    )
  ),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  -- What a claim points at: its request on its request's supplier.
  CONSTRAINT on_its_supplier UNIQUE (org_id, id, supplier_id),
  CONSTRAINT of_an_agent FOREIGN KEY (org_id, agent_id) REFERENCES agents.agents (org_id, id),
  CONSTRAINT with_a_key FOREIGN KEY (org_id, agent_key_id) REFERENCES agents.agent_keys (org_id, id),
  CONSTRAINT under_a_mandate_version FOREIGN KEY (org_id, mandate_id, mandate_version_id)
    REFERENCES mandates.versions (org_id, mandate_id, id),
  -- The organisation's policy has the organisation's ID, a mandate's the mandate's (0037).
  CONSTRAINT under_the_organizations_policy FOREIGN KEY (org_id, org_id, organization_policy_version_id)
    REFERENCES mandates.policy_versions (org_id, policy_id, id),
  CONSTRAINT under_the_mandates_policy FOREIGN KEY (org_id, mandate_id, mandate_policy_version_id)
    REFERENCES mandates.policy_versions (org_id, policy_id, id),
  CONSTRAINT to_a_supplier_version FOREIGN KEY (org_id, supplier_id, supplier_version_id)
    REFERENCES suppliers.supplier_versions (org_id, supplier_id, id),
  -- A mandate with the version weighed, and a mandate's policy only with its mandate.
  CONSTRAINT a_mandate_with_its_version CHECK ((mandate_id IS NULL) = (mandate_version_id IS NULL)),
  CONSTRAINT a_mandate_policy_with_its_mandate CHECK (mandate_policy_version_id IS NULL OR mandate_id IS NOT NULL),
  -- Reasons for every decision but ALLOW, none for ALLOW.
  CONSTRAINT reasons_with_the_decision CHECK ((decision = 'ALLOW') = (reason_codes IS NULL)),
  -- Capacity is held only on a mandate version and a supplier version.
  CONSTRAINT holds_on_what_it_weighed CHECK (
    decision NOT IN ('ALLOW', 'REQUIRE_APPROVAL') OR (mandate_version_id IS NOT NULL AND supplier_version_id IS NOT NULL)
  ),
  -- Born with its decision; then only where that decision can lead. DENIED
  -- follows any (a refusal, a rejection, the re-check before hand-off).
  CONSTRAINT a_status_on_its_decision CHECK (
    CASE status
      WHEN 'VALIDATING' THEN true
      WHEN 'DENIED' THEN true
      WHEN 'APPROVAL_REQUIRED' THEN decision = 'REQUIRE_APPROVAL'
      ELSE decision IN ('ALLOW', 'REQUIRE_APPROVAL')
    END
  )
);

ALTER TABLE spend_requests.requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_requests.requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON spend_requests.requests
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON spend_requests.requests
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed(
    'agent_id', 'agent_key_id', 'mandate_id', 'mandate_version_id', 'organization_policy_version_id',
    'mandate_policy_version_id', 'supplier_id', 'supplier_version_id', 'funding_source_id', 'amount_minor', 'currency',
    'purpose', 'order_reference', 'idempotency_key', 'input_hash', 'input_hash_key_version', 'decision', 'reason_codes'
  );

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON spend_requests.requests
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'VALIDATING', 'VALIDATING>DENIED', 'APPROVAL_REQUIRED>DENIED', 'APPROVED>DENIED', 'INSTRUCTION_READY>DENIED',
    'VALIDATING>APPROVAL_REQUIRED', 'VALIDATING>APPROVED', 'APPROVAL_REQUIRED>APPROVED', 'APPROVAL_REQUIRED>EXPIRED',
    'APPROVAL_REQUIRED>CANCELLED', 'APPROVED>CANCELLED', 'INSTRUCTION_READY>CANCELLED', 'APPROVED>INSTRUCTION_READY',
    'INSTRUCTION_READY>HANDED_OFF'
  );

GRANT SELECT, INSERT ON spend_requests.requests TO agentx_app;
-- All but the status only as the audit module's record seals a new request, unchanged: `fixed_at_creation`.
GRANT UPDATE (
  agent_id, agent_key_id, mandate_id, mandate_version_id, organization_policy_version_id, mandate_policy_version_id,
  supplier_id, supplier_version_id, funding_source_id, amount_minor, currency, purpose, order_reference,
  idempotency_key, input_hash, input_hash_key_version, decision, reason_codes, status, state_version, state_event_id
) ON spend_requests.requests TO agentx_app;
GRANT SELECT ON spend_requests.requests TO agentx_backup;

CREATE TABLE spend_requests.order_claims (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  request_id uuid NOT NULL,
  supplier_id uuid NOT NULL,
  payee_key text CHECK (payee_key ~ '^[!-~]{1,128}$'),
  -- Canonical: the rail's characters in lower case, words one space apart, no space at either end.
  order_reference text NOT NULL CHECK (
    pg_catalog.char_length(order_reference) <= 35
    AND order_reference ~ '^[a-z0-9/?:().,''+-]+( [a-z0-9/?:().,''+-]+)*$'
  ),
  claimed_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(claimed_at)),
  released_at timestamptz CHECK (pg_catalog.isfinite(released_at)),
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_claim_a_request UNIQUE (org_id, request_id),
  CONSTRAINT for_its_request FOREIGN KEY (org_id, request_id, supplier_id)
    REFERENCES spend_requests.requests (org_id, id, supplier_id),
  CONSTRAINT on_a_supplier FOREIGN KEY (org_id, supplier_id) REFERENCES suppliers.suppliers (org_id, id),
  CONSTRAINT released_after_its_claim CHECK (released_at IS NULL OR released_at >= claimed_at)
);

-- One open claim an order, by its supplier, and by its payee where there is
-- one (ADR-014 §3). Partial, so a released claim no longer holds the order;
-- released_at is never a key column, so a release stays a no-key write
-- (ADR-006 §6).
CREATE UNIQUE INDEX one_open_claim_a_supplier_order ON spend_requests.order_claims (org_id, supplier_id, order_reference)
  WHERE released_at IS NULL;
CREATE UNIQUE INDEX one_open_claim_a_payee_order ON spend_requests.order_claims (org_id, payee_key, order_reference)
  WHERE released_at IS NULL AND payee_key IS NOT NULL;

ALTER TABLE spend_requests.order_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_requests.order_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON spend_requests.order_claims
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON spend_requests.order_claims TO agentx_app;
GRANT UPDATE (released_at) ON spend_requests.order_claims TO agentx_app;
GRANT SELECT ON spend_requests.order_claims TO agentx_backup;
