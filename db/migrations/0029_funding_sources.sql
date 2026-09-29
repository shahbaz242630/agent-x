-- An organisation's funding sources (PRD §2.3, §3 `FundingSourceReference`,
-- ADR-012 §2, §5; BR-01, BR-02; Phase 1 D2-2): the business's own bank
-- account, linked through the payment partner, which Agent X never holds.
-- The funding-sources module owns both tables (ADR-004), in a schema of its
-- own; what the partner holds is read only through the providers module's
-- adapter.
--
-- funding_sources.links is a link Agent X started: its ID (the partner's
-- idempotency key for it), the member who started it (a membership), the
-- partner, the partner's session and when it runs out. How it ended is
-- filled in once, from the partner's answer server to server, never from
-- anything that came back through the browser (SEC-PTR-08): linked (with the
-- source it made), rejected, expired, or unknown to the partner. A link
-- grants nothing, so it is a plain tenant table: the app adds it, reads it,
-- and fills in its end once.
--
-- funding_sources.sources is a linked source: a tenant table and an authority
-- table (ADR-012 §2), since a hand-off will rest on it. Two statuses:
-- - `status`, Agent X's own: ACTIVE, or SUSPENDED by the business (the kill
--   switch, ADR-012 §5) and back, or ENDED once the partner says it is gone
--   for good (revoked, expired, consumed): a new link is then a new source.
--   The status guard holds these moves.
-- - `availability`, the partner's latest word (PENDING, ACTIVE, SUSPENDED,
--   UNAVAILABLE), with its own word for the consent kept as evidence.
-- Only a source ACTIVE in both, before its consent's expiry, may fund a
-- request. Sealed with them (they must equal the source's latest signed
-- event): the partner and its reference for the source, the consent's ID,
-- the one it renewed and its expiry, the bank's controls (currency, period,
-- the most a payment, the most a period in money and in payments), and what
-- may be shown of the account (BR-02): the holder's name, the account's type
-- and a hint (the country and the last four characters, `AE…6026`), with the
-- time the partner says it last changed. So an owner who revives an ended
-- source, swaps its reference or consent, stretches its expiry, widens its
-- controls or shows another account's name is caught at the next read.
-- Never an account number or a balance (PRD §2.3 step 4); the seal is a MAC,
-- so the holder's name is never put in an event.
--
-- One source per partner reference in an organisation, and one per link.
-- The member who started a link is a membership's ID with no foreign key:
-- the module may not reach into identity's tables (ADR-004's map), so the
-- use case checks the membership, as for an agent's owner.
--
-- The app adds rows and reads them, and changes only a link's end, once, and
-- a source's sealed fields and its two signed-state columns, all of which
-- the audit module's record writes and seals together (its partner and
-- reference among them, rewritten as they were). Never a key, a link or a
-- creation time, and never deletes (a source deleted and added again would
-- be born ACTIVE). The backup role reads everything, as it must for a
-- logical backup.

CREATE SCHEMA funding_sources;
GRANT USAGE ON SCHEMA funding_sources TO agentx_app, agentx_backup;

CREATE TABLE funding_sources.links (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  started_by uuid NOT NULL,
  partner text NOT NULL CHECK (partner ~ '^[a-z][a-z0-9_]{0,31}$'),
  session_ref text NOT NULL CHECK (session_ref ~ '^[!-~]{1,128}$'),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  outcome text CHECK (outcome IN ('linked', 'rejected', 'expired', 'unknown')),
  source_id uuid,
  settled_at timestamptz,
  PRIMARY KEY (org_id, id),
  CONSTRAINT expires_after_it_was_made CHECK (expires_at > created_at AND pg_catalog.isfinite(expires_at)),
  CONSTRAINT settled_once_with_its_end CHECK (
    (outcome IS NULL AND settled_at IS NULL AND source_id IS NULL)
    OR (outcome = 'linked' AND settled_at IS NOT NULL AND source_id IS NOT NULL)
    OR (outcome IN ('rejected', 'expired', 'unknown') AND settled_at IS NOT NULL AND source_id IS NULL)
  )
);

ALTER TABLE funding_sources.links ENABLE ROW LEVEL SECURITY;
ALTER TABLE funding_sources.links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON funding_sources.links
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON funding_sources.links TO agentx_app;
GRANT UPDATE (outcome, source_id, settled_at) ON funding_sources.links TO agentx_app;
GRANT SELECT ON funding_sources.links TO agentx_backup;

CREATE TABLE funding_sources.sources (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  link_id uuid NOT NULL,
  partner text NOT NULL CHECK (partner ~ '^[a-z][a-z0-9_]{0,31}$'),
  external_ref text NOT NULL CHECK (external_ref ~ '^[!-~]{1,128}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ENDED')),
  availability text NOT NULL CHECK (availability IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'UNAVAILABLE')),
  consent_status text NOT NULL CHECK (consent_status ~ '^[A-Za-z]{1,40}$'),
  account_consent_id text NOT NULL CHECK (account_consent_id ~ '^[!-~]{1,128}$'),
  replaces_consent_id text CHECK (replaces_consent_id ~ '^[!-~]{1,128}$'),
  consent_expires_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(consent_expires_at)),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  limit_period text NOT NULL CHECK (limit_period IN ('day', 'week', 'month', 'year')),
  max_payment_minor bigint NOT NULL CHECK (max_payment_minor > 0),
  max_period_minor bigint NOT NULL CHECK (max_period_minor > 0),
  max_period_payments integer NOT NULL CHECK (max_period_payments > 0),
  holder_name text NOT NULL CHECK (pg_catalog.char_length(holder_name) BETWEEN 1 AND 140),
  account_type text NOT NULL CHECK (account_type IN ('retail', 'sme', 'corporate')),
  hint text NOT NULL CHECK (hint ~ '^[A-Z]{2}…[0-9A-Z]{4}$'),
  partner_changed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT one_source_a_reference UNIQUE (org_id, partner, external_ref),
  CONSTRAINT one_source_a_link UNIQUE (org_id, link_id),
  CONSTRAINT from_a_link FOREIGN KEY (org_id, link_id) REFERENCES funding_sources.links (org_id, id)
);

-- A link that made a source names it: the same organisation's.
ALTER TABLE funding_sources.links
  ADD CONSTRAINT made_a_source FOREIGN KEY (org_id, source_id) REFERENCES funding_sources.sources (org_id, id);

ALTER TABLE funding_sources.sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE funding_sources.sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON funding_sources.sources
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON funding_sources.sources
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE', 'ACTIVE>ENDED', 'SUSPENDED>ENDED'
  );

GRANT SELECT, INSERT ON funding_sources.sources TO agentx_app;
GRANT UPDATE (
  partner, external_ref, status, availability, consent_status, account_consent_id, replaces_consent_id,
  consent_expires_at, currency, limit_period, max_payment_minor, max_period_minor, max_period_payments,
  holder_name, account_type, hint, partner_changed_at, state_version, state_event_id
) ON funding_sources.sources TO agentx_app;
GRANT SELECT ON funding_sources.sources TO agentx_backup;
