-- An agent's spend requests and their order claims (PRD §3 `SpendRequest`,
-- §3.2, §4.2, §5.2; ADR-006 §5, §11; ADR-012 §2, §4; ADR-014 §3, §5, §8;
-- BR-09, BR-22; Phase 2 D1): what an agent asked to pay, the decision made on
-- it, and the claim that keeps one order from being paid twice. The
-- spend-requests module owns both tables (ADR-004), in a schema of its own.
-- Deciding and reserving through them come with D2–D4r.
--
-- spend_requests.requests is one request, as the agent made it and as it was
-- decided. A tenant table and an authority table (ADR-012 §2: "any request
-- decision") at the request's level in the lock order (ADR-006 §6: 8). All of
-- it is sealed, and all but the status is fixed when the request is made
-- (`fixed_at_creation`), so neither the app nor an owner can change what was
-- asked or decided after the fact:
-- - who asked: the agent and the key it used, the agent's own (Carry-Forward,
--   Phase 3: the key on its evidence);
-- - what was asked, as the agent sent it: the amount in minor units (ADR-006
--   §1), its currency, the purpose, the supplier, the funding source, the
--   order reference as written (ADR-006 §5: the raw value, as evidence: the
--   supplier's own invoice or order number, in any script, partner S93; the
--   rail's 35-character payment reference is made from it at hand-off), and
--   its idempotency key (PRD §3; the idempotency table's own row goes after
--   its retention, this stays);
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
-- (a supplier's version is its supplier's, a mandate its agent's and a
-- version its mandate's, a policy's version the organisation's own policy or
-- the mandate's). A request that holds capacity (ALLOW or REQUIRE_APPROVAL)
-- must name the mandate and supplier versions it rests on (ADR-006 §6: every
-- decision records the supplier version it was made against), and its source
-- must be its mandate version's (`held_source_id`, given only then).
--
-- The status follows PRD §4.2. The decision is made on locked reads before
-- the row is added (ADR-006 §7), so the row is born VALIDATING with its
-- decision already in it, and moved by that decision in the same transaction:
-- `decided_move` lets it go only where the decision says (ALLOW to APPROVED,
-- REQUIRE_APPROVAL to APPROVAL_REQUIRED, the others to DENIED), so nothing
-- needing an approval is approved without one, and nothing denied is ever
-- approved. The status guard takes one first status, and the audit trail then
-- shows the request received and decided. PRD's CREATED is the API's receipt,
-- the idempotency key's claim, before any row. Then: an approval waiting is
-- approved, rejected (DENIED), expired or cancelled; an approved request is
-- made ready and handed off, or denied by the re-check before hand-off, or
-- cancelled. DENIED, EXPIRED, CANCELLED and HANDED_OFF move no further (after
-- hand-off the outcome is the transaction's, PRD §4.2).
--
-- spend_requests.order_claims is the database's safety net against paying
-- one order twice (ADR-006 §11, PRD §3.2, SEC-DP-10, SEC-PAY-06): a request
-- that holds capacity claims its order, by the organisation, the supplier and
-- the order reference's canonical form, and by the payee key too where the
-- supplier has one (ADR-014 §3: the same invoice to a supplier re-created
-- with the same account). One open claim a key: a second request for the same
-- order waits on the first and is refused. The canonical form (ADR-006 §5:
-- NFKC, case-folded, trimmed, spaces collapsed) is the request's own
-- `order_key`, worked out here from the reference as written, so the app
-- never works it out itself and no bug of its own can claim another order:
-- NFKC turns full-width letters and the other Unicode spaces into plain ones,
-- and case-folding is the database's lower() (one database's claims are only
-- ever compared with its own). A claim must carry exactly it. One claim a request, on its
-- request's own supplier and order, with that supplier's payee key as it is
-- when claimed (`claim_guard`), and only for a request that holds capacity.
-- A claim is released (`released_at`) once, and only after its request ends:
-- DENIED, CANCELLED or EXPIRED, or HANDED_OFF and its payment ended in a
-- verified FAILED or CANCELLED (UNKNOWN keeps it, as possibly paid; the
-- outcomes module checks that, Phase 4). Not an authority table: claims, like
-- reservations, are checked against the signed decision and outcome events by
-- a scheduled reconciliation (ADR-012 §2; E1).
--
-- Both are of the organisation they belong to, row-level security forced.
-- The app adds rows and reads them; a request it changes only as the audit
-- module's record seals it (its status, and its fields only unchanged), a
-- claim only in its release. Never a delete: a request deleted would leave a
-- decision with no record, a claim deleted an order payable again. The backup
-- role reads everything, as it must for a logical backup.
--
-- The two guards, like 0035's: no rights of their own, no EXECUTE granted,
-- search_path pg_catalog alone, refusing to run as anything but the trigger
-- they were written for. `decided_move` sorts before `status_guard`.

CREATE SCHEMA spend_requests;
GRANT USAGE ON SCHEMA spend_requests TO agentx_app, agentx_backup;

-- What a request's keys point at with its agent and its source: a mandate is
-- its agent's, an agent key its agent's, a mandate version names its source.
-- None of the three columns ever changes once its row is made.
ALTER TABLE mandates.mandates ADD CONSTRAINT with_its_agent UNIQUE (org_id, id, agent_id);
ALTER TABLE agents.agent_keys ADD CONSTRAINT with_its_agent UNIQUE (org_id, id, agent_id);
ALTER TABLE mandates.versions ADD CONSTRAINT with_its_source UNIQUE (org_id, id, funding_source_id);

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
  -- As the agent wrote it: up to 100 characters, none a control; not blank (`an_order_not_blank`).
  order_reference text NOT NULL CHECK (
    pg_catalog.char_length(order_reference) BETWEEN 1 AND 100 AND order_reference !~ '[[:cntrl:]]'
  ),
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
  -- Given by the database from sealed fields, never written: the order's
  -- canonical form, and the source a request holding capacity rests on.
  order_key text NOT NULL GENERATED ALWAYS AS (
    pg_catalog.regexp_replace(pg_catalog.btrim(pg_catalog.lower(pg_catalog.normalize(order_reference, 'NFKC'))), ' +', ' ', 'g')
  ) STORED,
  held_source_id uuid GENERATED ALWAYS AS (
    CASE WHEN decision IN ('ALLOW', 'REQUIRE_APPROVAL') THEN funding_source_id END
  ) STORED,
  PRIMARY KEY (org_id, id),
  -- What a claim points at: its request, on its request's supplier and order.
  CONSTRAINT claimed_as_asked UNIQUE (org_id, id, supplier_id, order_key),
  CONSTRAINT of_an_agent FOREIGN KEY (org_id, agent_id) REFERENCES agents.agents (org_id, id),
  CONSTRAINT with_its_agents_key FOREIGN KEY (org_id, agent_key_id, agent_id)
    REFERENCES agents.agent_keys (org_id, id, agent_id),
  CONSTRAINT under_its_agents_mandate FOREIGN KEY (org_id, mandate_id, agent_id)
    REFERENCES mandates.mandates (org_id, id, agent_id),
  CONSTRAINT under_a_mandate_version FOREIGN KEY (org_id, mandate_id, mandate_version_id)
    REFERENCES mandates.versions (org_id, mandate_id, id),
  CONSTRAINT from_its_mandates_source FOREIGN KEY (org_id, mandate_version_id, held_source_id)
    REFERENCES mandates.versions (org_id, id, funding_source_id),
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
  CONSTRAINT an_order_not_blank CHECK (order_key <> ''),
  -- Capacity is held only on a mandate version and a supplier version.
  CONSTRAINT holds_on_what_it_weighed CHECK (
    decision NOT IN ('ALLOW', 'REQUIRE_APPROVAL') OR (mandate_version_id IS NOT NULL AND supplier_version_id IS NOT NULL)
  )
);

ALTER TABLE spend_requests.requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_requests.requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON spend_requests.requests
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- Out of VALIDATING only where its decision leads.
CREATE FUNCTION spend_requests.guard_decided_move() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  decided text;
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP <> 'UPDATE' OR TG_TABLE_SCHEMA <> 'spend_requests'
     OR TG_TABLE_NAME <> 'requests' THEN
    RAISE EXCEPTION 'spend_requests.guard_decided_move must run BEFORE UPDATE, FOR EACH ROW, on spend_requests.requests'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  decided := CASE OLD.decision
    WHEN 'ALLOW' THEN 'APPROVED'
    WHEN 'REQUIRE_APPROVAL' THEN 'APPROVAL_REQUIRED'
    ELSE 'DENIED'
  END;
  IF OLD.status = 'VALIDATING' AND NEW.status IS DISTINCT FROM 'VALIDATING' AND NEW.status IS DISTINCT FROM decided THEN
    RAISE EXCEPTION 'a spend request decided % moves to %, not %', OLD.decision, decided, NEW.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'decided_move';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER decided_move BEFORE UPDATE ON spend_requests.requests
  FOR EACH ROW EXECUTE FUNCTION spend_requests.guard_decided_move();

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
  -- Its request's `order_key`: the canonical form.
  order_reference text NOT NULL,
  claimed_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(claimed_at)),
  released_at timestamptz CHECK (pg_catalog.isfinite(released_at)),
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_claim_a_request UNIQUE (org_id, request_id),
  CONSTRAINT for_its_request FOREIGN KEY (org_id, request_id, supplier_id, order_reference)
    REFERENCES spend_requests.requests (org_id, id, supplier_id, order_key),
  CONSTRAINT on_a_supplier FOREIGN KEY (org_id, supplier_id) REFERENCES suppliers.suppliers (org_id, id),
  CONSTRAINT released_after_its_claim CHECK (released_at IS NULL OR released_at >= claimed_at)
);

-- One open claim an order, by its supplier, and by its payee where there is one (schema-policy.ts says why partial).
CREATE UNIQUE INDEX one_open_claim_a_supplier_order ON spend_requests.order_claims (org_id, supplier_id, order_reference)
  WHERE released_at IS NULL;
CREATE UNIQUE INDEX one_open_claim_a_payee_order ON spend_requests.order_claims (org_id, payee_key, order_reference)
  WHERE released_at IS NULL AND payee_key IS NOT NULL;

ALTER TABLE spend_requests.order_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE spend_requests.order_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON spend_requests.order_claims
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

-- Claimed for a request holding capacity, with its supplier's payee key;
-- released once, after its request ends.
CREATE FUNCTION spend_requests.guard_claim() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  request record;
BEGIN
  IF TG_WHEN <> 'BEFORE' OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'UPDATE')
     OR TG_TABLE_SCHEMA <> 'spend_requests' OR TG_TABLE_NAME <> 'order_claims' THEN
    RAISE EXCEPTION 'spend_requests.guard_claim must run BEFORE INSERT OR UPDATE, FOR EACH ROW, on spend_requests.order_claims'
      USING ERRCODE = 'triggered_action_exception';
  END IF;
  SELECT r.decision, r.status INTO request
    FROM spend_requests.requests r
    WHERE r.org_id = NEW.org_id AND r.id = NEW.request_id;
  IF TG_OP = 'INSERT' THEN
    IF request.decision IS DISTINCT FROM 'ALLOW' AND request.decision IS DISTINCT FROM 'REQUIRE_APPROVAL' THEN
      RAISE EXCEPTION 'only a request holding capacity claims its order'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
    END IF;
    IF NEW.payee_key IS DISTINCT FROM (
      SELECT s.payee_key FROM suppliers.suppliers s WHERE s.org_id = NEW.org_id AND s.id = NEW.supplier_id
    ) THEN
      RAISE EXCEPTION 'a claim keeps its supplier''s payee key as it is'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at THEN
    RAISE EXCEPTION 'a claim is released once'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
  END IF;
  IF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL
     AND request.status IN ('VALIDATING', 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY') THEN
    RAISE EXCEPTION 'a claim is released only once its request has ended, not while %', request.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'claim_guard';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER claim_guard BEFORE INSERT OR UPDATE ON spend_requests.order_claims
  FOR EACH ROW EXECUTE FUNCTION spend_requests.guard_claim();

GRANT SELECT, INSERT ON spend_requests.order_claims TO agentx_app;
GRANT UPDATE (released_at) ON spend_requests.order_claims TO agentx_app;
GRANT SELECT ON spend_requests.order_claims TO agentx_backup;
