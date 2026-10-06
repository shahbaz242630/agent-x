-- An agent's mandates (PRD §3 `Mandate` / `MandateEvidence`, §3.1, §4.1;
-- ADR-006 §1, §4; ADR-012 §2; ADR-014 §5; BR-05, BR-06; Phase 2 B1): the
-- spending authority an organisation gives one of its agents, and the terms
-- of each version of it. The mandates module owns the three tables (ADR-004),
-- in a schema of its own.
--
-- mandates.allowed_currencies is the deployment's list of currencies (ADR-006
-- §1, ADR-010): AED in the Pilot. A global table, IDs only, on the CI-06 list
-- with exactly its column; the app only reads it. Another deployment adds a
-- currency by a migration of its own, never by the app.
--
-- mandates.mandates is a mandate across all its versions: the lineage
-- (PRD §3.1, ADR-006 §4), whose time zone and split window every version
-- keeps. Its monthly limit is checked against everything its agent reserved
-- that month under any of its mandates (partner, S87): so neither superseding
-- a version nor revoking a mandate and accepting a new one resets the total.
-- A tenant table and an authority table (ADR-012 §2) at the mandate's level
-- in the lock order (ADR-006 §6: 4). Sealed (they must equal the mandate's latest signed event):
-- - `agent_id`, `time_zone` and `split_window_hours`: whose authority it is,
--   the IANA zone its months are counted in (ADR-006 §4; default Asia/Dubai,
--   stored as the runtime names it) and the split check's rolling window
--   (default 24 hours, ADR-006 §9). Fixed when the mandate is made: the app
--   never writes them again, and the seal catches anyone who does.
-- - `status`: PENDING_ACCEPTANCE until an admin accepts its first version
--   (B3), then ACTIVE; SUSPENDED and back (B4); REVOKED (a draft never
--   accepted is withdrawn the same way) and EXPIRED end it. The status guard
--   holds the moves; superseding is not one (an ACTIVE mandate stays ACTIVE
--   with a new current version). An ended mandate's waiting draft can never
--   be accepted, since accepting needs it waiting or live.
-- - `current_version_id`, the version in force, with `accepted_by` (the
--   accepting admin's membership) and `accepted_at`; `pending_version_id`, a
--   draft waiting for acceptance. Accepting a draft makes it current in one
--   step, so the version it replaces is SUPERSEDED (PRD §4.1) by being no
--   longer current; the accept event in the audit chain is its evidence
--   (PRD `MandateEvidence`, with the version's `terms_hash`).
-- So an owner who reactivates a revoked mandate, swaps its terms for a
-- version no admin accepted, or moves it to another agent or time zone is
-- caught at the next read.
--
-- One live mandate an agent (PRD §3, the Pilot): a unique key on the agent
-- while ACTIVE or SUSPENDED (`one_live_mandate_an_agent`), so a second
-- mandate for an agent can't be accepted while one is live: the owner
-- supersedes it instead.
--
-- mandates.versions is one version of a mandate's terms, made once and never
-- changed: changing any term, the split check's setting included (PRD §3.2),
-- is a new version. Also an authority table, so all of it is sealed: its
-- mandate and number, the purpose, the currency, the three limits in minor
-- units (ADR-006 §1: bigint, never a float), the supplier allow-list, the
-- funding source, the split check, how its limits stand against the bank
-- consent's (`consent_limits`, partner S86: strict or flexible, B2), when it
-- ends (none: until revoked), the canonical hash of its terms (what an
-- acceptance is bound to, B3), and who drafted it and when.
--
-- The allow-list is supplier IDs as lower-case UUIDs, sorted, each once, one
-- space apart (the app holds the order, as it does an agent's scopes), at
-- most 100 (B2): sealed as one text, so the same suppliers seal the same. The
-- suppliers are checked by the use case, in the organisation, as a payment
-- will check each again (no foreign key can point from a list).
--
-- The limits nest: approval threshold ≤ per-order limit ≤ monthly limit (PRD
-- §3.3: a request over the mandate's own limits is REQUIRE_NEW_MANDATE, never
-- an approval).
--
-- A mandate's agent and a version's funding source are its organisation's
-- (composite keys, ADR-005, in the direction ADR-004's map allows). The
-- members who drafted and accepted are memberships' IDs with no foreign key:
-- the module may not reach into identity's tables, so the use cases check
-- them, as for an agent's owner.
--
-- The app adds rows and reads them, and changes only the sealed fields and
-- the two signed-state columns, which the audit module's record writes and
-- seals together (a version's, only as it is made: `made_once`). Never a
-- key or a creation time, and never deletes (a mandate deleted and added
-- again would be born with no history). The
-- backup role reads everything, as it must for a logical backup.

CREATE SCHEMA mandates;
GRANT USAGE ON SCHEMA mandates TO agentx_app, agentx_backup;

CREATE TABLE mandates.allowed_currencies (
  code text PRIMARY KEY CHECK (code ~ '^[A-Z]{3}$')
);

INSERT INTO mandates.allowed_currencies (code) VALUES ('AED');

GRANT SELECT ON mandates.allowed_currencies TO agentx_app, agentx_backup;

CREATE TABLE mandates.mandates (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  agent_id uuid NOT NULL,
  time_zone text NOT NULL CHECK (time_zone ~ '^[A-Za-z][A-Za-z0-9_+/-]{0,63}$'),
  split_window_hours integer NOT NULL CHECK (split_window_hours BETWEEN 1 AND 744),
  status text NOT NULL CHECK (status IN ('PENDING_ACCEPTANCE', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
  current_version_id uuid,
  pending_version_id uuid,
  accepted_by uuid,
  accepted_at timestamptz CHECK (pg_catalog.isfinite(accepted_at)),
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT of_an_agent FOREIGN KEY (org_id, agent_id) REFERENCES agents.agents (org_id, id),
  CONSTRAINT pending_is_not_current CHECK (pending_version_id IS DISTINCT FROM current_version_id),
  -- A version in force came with its acceptance: who and when.
  CONSTRAINT accepted_with_its_version CHECK (
    (current_version_id IS NULL) = (accepted_by IS NULL) AND (accepted_by IS NULL) = (accepted_at IS NULL)
  ),
  -- ACTIVE, SUSPENDED or EXPIRED only with a version in force; waiting for
  -- acceptance, with a version to accept. Accepting records the version in
  -- force first, then moves the status, so a mandate waiting may hold one for
  -- that moment. A revoked mandate may never have had one (a draft withdrawn).
  CONSTRAINT a_status_on_its_versions CHECK (
    CASE status
      WHEN 'REVOKED' THEN true
      WHEN 'PENDING_ACCEPTANCE' THEN current_version_id IS NOT NULL OR pending_version_id IS NOT NULL
      ELSE current_version_id IS NOT NULL
    END
  )
);

-- One live mandate an agent (PRD §3). Partial, so the status is never a key
-- column: a status change stays a no-key write (ADR-006 §6).
CREATE UNIQUE INDEX one_live_mandate_an_agent ON mandates.mandates (org_id, agent_id)
  WHERE status IN ('ACTIVE', 'SUSPENDED');

ALTER TABLE mandates.mandates ENABLE ROW LEVEL SECURITY;
ALTER TABLE mandates.mandates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mandates.mandates
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON mandates.mandates
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'PENDING_ACCEPTANCE', 'PENDING_ACCEPTANCE>ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE',
    'PENDING_ACCEPTANCE>REVOKED', 'ACTIVE>REVOKED', 'SUSPENDED>REVOKED', 'ACTIVE>EXPIRED', 'SUSPENDED>EXPIRED'
  );

GRANT SELECT, INSERT ON mandates.mandates TO agentx_app;
-- agent_id, time_zone and split_window_hours only as the audit module's record seals a new mandate.
GRANT UPDATE (
  agent_id, time_zone, split_window_hours, status, current_version_id, pending_version_id, accepted_by, accepted_at,
  state_version, state_event_id
) ON mandates.mandates TO agentx_app;
GRANT SELECT ON mandates.mandates TO agentx_backup;

CREATE TABLE mandates.versions (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  mandate_id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  purpose text NOT NULL CHECK (pg_catalog.char_length(purpose) BETWEEN 1 AND 200 AND purpose !~ '[[:cntrl:]]'),
  currency text NOT NULL REFERENCES mandates.allowed_currencies (code),
  per_order_limit_minor bigint NOT NULL CHECK (per_order_limit_minor > 0),
  monthly_limit_minor bigint NOT NULL CHECK (monthly_limit_minor > 0),
  approval_threshold_minor bigint NOT NULL CHECK (approval_threshold_minor > 0),
  supplier_ids text NOT NULL CHECK (
    pg_catalog.char_length(supplier_ids) <= 3699
    AND supplier_ids ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}( [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})*$'
  ),
  funding_source_id uuid NOT NULL,
  split_check text NOT NULL CHECK (split_check IN ('on', 'off')),
  consent_limits text NOT NULL CHECK (consent_limits IN ('strict', 'flexible')),
  ends_at timestamptz CHECK (pg_catalog.isfinite(ends_at)),
  terms_hash text NOT NULL CHECK (terms_hash ~ '^[0-9a-f]{64}$'),
  drafted_by uuid NOT NULL,
  drafted_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(drafted_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_number_a_version UNIQUE (org_id, mandate_id, version),
  CONSTRAINT its_mandates_own UNIQUE (org_id, mandate_id, id),
  CONSTRAINT of_a_mandate FOREIGN KEY (org_id, mandate_id) REFERENCES mandates.mandates (org_id, id),
  CONSTRAINT from_a_source FOREIGN KEY (org_id, funding_source_id) REFERENCES funding_sources.sources (org_id, id),
  CONSTRAINT limits_nest CHECK (
    approval_threshold_minor <= per_order_limit_minor AND per_order_limit_minor <= monthly_limit_minor
  ),
  CONSTRAINT ends_after_its_draft CHECK (ends_at IS NULL OR ends_at > drafted_at)
);

ALTER TABLE mandates.versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mandates.versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mandates.versions
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER made_once BEFORE UPDATE ON mandates.versions
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_made_once();

-- A mandate's current and pending versions are its own. The pending one is
-- checked at commit, since a new mandate names its first draft before that
-- version is added.
ALTER TABLE mandates.mandates
  ADD CONSTRAINT current_is_its_own FOREIGN KEY (org_id, id, current_version_id)
    REFERENCES mandates.versions (org_id, mandate_id, id),
  ADD CONSTRAINT pending_is_its_own FOREIGN KEY (org_id, id, pending_version_id)
    REFERENCES mandates.versions (org_id, mandate_id, id) DEFERRABLE INITIALLY DEFERRED;

GRANT SELECT, INSERT ON mandates.versions TO agentx_app;
-- Only as the audit module's record seals a new version: `made_once` refuses any change after.
GRANT UPDATE (
  mandate_id, version, purpose, currency, per_order_limit_minor, monthly_limit_minor, approval_threshold_minor,
  supplier_ids, funding_source_id, split_check, consent_limits, ends_at, terms_hash, drafted_by, drafted_at,
  state_version, state_event_id
) ON mandates.versions TO agentx_app;
GRANT SELECT ON mandates.versions TO agentx_backup;
