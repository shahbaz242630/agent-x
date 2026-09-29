-- The fake payment partner's own records (ADR-004 §8; Phase 1 D2-1): what
-- the fake partner holds of each organisation's links, sources and payee
-- registrations, so that on staging they outlive a restart (the API scales to
-- zero) and every process sees the same partner: the API that calls the
-- adapter, and the test steps that play the business at its bank.
--
-- These are the partner's records, never Agent X's: nothing of Agent X reads
-- them but the fake's adapter, and a real partner keeps its own. Only the
-- fake uses the table, and the fake is never chosen in production (D2-3's
-- config check), so there it stays empty.
--
-- A tenant table: every row is one organisation's, and the fake reaches it
-- only in withTenant's transaction for the organisation it acts for, so one
-- organisation's link, source or payee is never another's, as the contract
-- says (an unknown reference answers as none).
--
-- Each row is one record of the kind named, found by its reference (ours: a
-- link or registration ID; the partner's: a source reference), and by its
-- alias where the partner looks one up another way (a link's session, a
-- source's current consent, a hosted form). The body is the fake's own JSON,
-- and never holds an account number: a source names the sandbox account by
-- its ID, and a payee's registration holds only the masked hint and name
-- and the payee identity, a hash of the organisation and the account (PRD
-- Phase 1: no raw bank details in the database). The hash has no key, so
-- someone reading the table could test a guessed account number against it:
-- acceptable for a fake whose payees are test data, on staging alone.
--
-- The fake adds records, reads them and moves them on (a consent's status, a
-- form filled in); it never deletes one, as a partner keeps its records. The
-- backup role reads everything, as it must for a logical backup.

CREATE SCHEMA fake_partner;
GRANT USAGE ON SCHEMA fake_partner TO agentx_app, agentx_backup;

CREATE TABLE fake_partner.records (
  org_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('link', 'source', 'registration')),
  ref text NOT NULL CHECK (ref ~ '^[^\s]{1,64}$'),
  alias text CHECK (alias ~ '^[^\s]{1,64}$'),
  body jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(body) = 'object' AND pg_catalog.octet_length(body::text) <= 4096),
  PRIMARY KEY (org_id, kind, ref),
  CONSTRAINT one_record_an_alias UNIQUE (org_id, kind, alias)
);

ALTER TABLE fake_partner.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE fake_partner.records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON fake_partner.records
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT ON fake_partner.records TO agentx_app;
GRANT UPDATE (alias, body) ON fake_partner.records TO agentx_app;
GRANT SELECT ON fake_partner.records TO agentx_backup;
