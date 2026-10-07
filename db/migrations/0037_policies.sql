-- Spending policies (PRD §3 `Policy` / `PolicyRule`, §5; BR-06; Phase 2 C1;
-- partner decision 5, S91): rules an organisation sets on top of its
-- mandates. The mandates module owns both tables (ADR-004: the policies module
-- stays a pure engine with no tables), in the mandates schema.
--
-- mandates.policies is a policy across all its versions: the lineage. Two
-- kinds (`scope`), each at most one, by construction of its ID:
-- - `organization`: the organisation's own, every agent's defaults. Its ID is
--   the organisation's, so it is read by that ID: no row and no signed
--   history means none was ever set (the default applies: AED 20,000 a month
--   for each agent, held by the engine, C2), and a row deleted past the app
--   is caught by its history in the log (signed state's `deleted`).
-- - `mandate`: one mandate's own, so one agent's. Its ID is the mandate's,
--   read the same way.
-- A tenant table and an authority table (ADR-012 §2), at the mandate's level
-- in the lock order (ADR-006 §6: 4), after the mandates. Sealed: `scope` and
-- `mandate_id`, fixed when it is made (`fixed_at_creation`), and
-- `current_version_id`, the version in force. A policy takes effect as it is
-- made, with an admin's passkey (C3): there is no acceptance, no status and
-- no draft waiting. A policy with nothing to narrow is a version whose rules
-- are all empty.
--
-- mandates.policy_versions is one version of a policy's rules, made once and
-- never changed: changing any rule is a new version. All of it sealed: its
-- policy and number, the currency, each rule (empty: this policy sets none),
-- the canonical hash of its rules, and who made it and when. The rules
-- (PRD §5.2, decision 5):
-- - a per-order cap, with what happens over it: DENY, or REQUIRE_APPROVAL;
-- - a monthly cap, for each agent's month (decision 4): over it, DENY. The
--   organisation's is every agent's default; a mandate's own replaces it for
--   that agent, higher or lower;
-- - an approval threshold;
-- - a supplier list, as a mandate's (lower-case UUIDs, sorted, each once, one
--   space apart, at most 100).
-- Each is the strictest of the mandate's and the policies' (the monthly cap:
-- the mandate's and the one in force for the agent), so nothing ever goes
-- above the mandate: that is the engine's (C2) and the writes' (C3), since a
-- mandate's terms change by versions of their own.
--
-- The rules a version sets nest as a mandate's do: approval threshold ≤
-- per-order cap ≤ monthly cap, where both are set.
--
-- A mandate policy's mandate is its organisation's (composite key, ADR-005).
-- Who made a version is a membership's ID with no foreign key, as for a
-- mandate's drafter: the use case checks it.
--
-- The app adds rows and reads them, and changes only the sealed fields and
-- the two signed-state columns, which the audit module's record writes and
-- seals together (a version's, only as it is made: `made_once`). Never a key
-- or a creation time, and never deletes. The backup role reads everything.

CREATE TABLE mandates.policies (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  scope text NOT NULL CHECK (scope IN ('organization', 'mandate')),
  mandate_id uuid,
  current_version_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  -- One of each, by its ID: the organisation's own, or its mandate's. Any
  -- other scope is the scope check's to refuse (null here, so it names it).
  CONSTRAINT one_of_each_kind CHECK (
    CASE scope
      WHEN 'organization' THEN id = org_id AND mandate_id IS NULL
      WHEN 'mandate' THEN mandate_id IS NOT NULL AND id = mandate_id
    END
  ),
  CONSTRAINT of_a_mandate FOREIGN KEY (org_id, mandate_id) REFERENCES mandates.mandates (org_id, id)
);

ALTER TABLE mandates.policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE mandates.policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mandates.policies
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON mandates.policies
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed('scope', 'mandate_id');

GRANT SELECT, INSERT ON mandates.policies TO agentx_app;
-- scope and mandate_id only as the audit module's record seals a new policy, unchanged: `fixed_at_creation`.
GRANT UPDATE (scope, mandate_id, current_version_id, state_version, state_event_id) ON mandates.policies TO agentx_app;
GRANT SELECT ON mandates.policies TO agentx_backup;

CREATE TABLE mandates.policy_versions (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  policy_id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  currency text NOT NULL REFERENCES mandates.allowed_currencies (code),
  per_order_cap_minor bigint CHECK (per_order_cap_minor > 0),
  over_per_order_cap text CHECK (over_per_order_cap IN ('DENY', 'REQUIRE_APPROVAL')),
  monthly_cap_minor bigint CHECK (monthly_cap_minor > 0),
  approval_threshold_minor bigint CHECK (approval_threshold_minor > 0),
  supplier_ids text CHECK (
    pg_catalog.char_length(supplier_ids) <= 3699
    AND supplier_ids ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}( [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})*$'
  ),
  rules_hash text NOT NULL CHECK (rules_hash ~ '^[0-9a-f]{64}$'),
  made_by uuid NOT NULL,
  made_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(made_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_number_a_policy_version UNIQUE (org_id, policy_id, version),
  CONSTRAINT its_policys_own UNIQUE (org_id, policy_id, id),
  CONSTRAINT of_a_policy FOREIGN KEY (org_id, policy_id) REFERENCES mandates.policies (org_id, id),
  -- A per-order cap says what happens over it; no cap, nothing to say.
  CONSTRAINT a_cap_with_its_outcome CHECK ((per_order_cap_minor IS NULL) = (over_per_order_cap IS NULL)),
  CONSTRAINT rules_nest CHECK (
    (approval_threshold_minor IS NULL OR per_order_cap_minor IS NULL OR approval_threshold_minor <= per_order_cap_minor)
    AND (per_order_cap_minor IS NULL OR monthly_cap_minor IS NULL OR per_order_cap_minor <= monthly_cap_minor)
    AND (approval_threshold_minor IS NULL OR monthly_cap_minor IS NULL OR approval_threshold_minor <= monthly_cap_minor)
  )
);

ALTER TABLE mandates.policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mandates.policy_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mandates.policy_versions
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER made_once BEFORE UPDATE ON mandates.policy_versions
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_made_once();

-- A policy's version in force is its own: checked at commit, since a new
-- policy names its first version before that version is added.
ALTER TABLE mandates.policies
  ADD CONSTRAINT current_is_its_own FOREIGN KEY (org_id, id, current_version_id)
    REFERENCES mandates.policy_versions (org_id, policy_id, id) DEFERRABLE INITIALLY DEFERRED;

GRANT SELECT, INSERT ON mandates.policy_versions TO agentx_app;
-- Only as the audit module's record seals a new version: `made_once` refuses any change after.
GRANT UPDATE (
  policy_id, version, currency, per_order_cap_minor, over_per_order_cap, monthly_cap_minor, approval_threshold_minor,
  supplier_ids, rules_hash, made_by, made_at, state_version, state_event_id
) ON mandates.policy_versions TO agentx_app;
GRANT SELECT ON mandates.policy_versions TO agentx_backup;
