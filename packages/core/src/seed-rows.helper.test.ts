// The rows the core's database tests make past the app (S94's D2 simplify
// review): an organisation, an agent and its key, a funding source, a
// supplier and a mandate waiting with its draft, as the steps that add them
// are tested elsewhere. A helper, not a test: Vitest leaves
// `*.helper.test.ts` out (vitest.config.ts), and the name keeps it with the
// tests, which alone may import @agentx/testing.
import type { TestSession } from '@agentx/testing';
import { randomUUID } from 'node:crypto';

import { DAY_MS } from './shared-kernel/index.ts';

export interface SeededSupplier {
  readonly id: string;
  readonly version: string;
}

export interface SeededMandate {
  readonly id: string;
  readonly version: string;
}

/** What a mandate is drafted for: its agent, its funding source and the one supplier it allows. */
export interface MandateFor {
  readonly agent: string;
  readonly source: string;
  readonly supplier: string;
}

/** Rows made as the database's admin, each made at `at`; IDs are new unless given. */
export const seedRows = (admin: TestSession, at: Date) => ({
  /** The organisation's directory row, which agent keys point at. */
  org: async (org: string): Promise<void> => {
    await admin.query('insert into directory.orgs (org_id) values ($1)', [org]);
  },

  /** An active agent that may write requests: its ID. */
  agent: async (
    org: string,
    { id = randomUUID(), name = 'Purchasing agent' }: { readonly id?: string; readonly name?: string } = {},
  ): Promise<string> => {
    await admin.query(
      `insert into agents.agents (org_id, id, name, owner, status, scopes, created_at)
       values ($1, $2, $3, $4, 'ACTIVE', 'requests:write', $5)`,
      [org, id, name, randomUUID(), at],
    );
    return id;
  },

  /** An active key of the agent, in the directory too: its ID. */
  agentKey: async (org: string, agent: string, id: string = randomUUID()): Promise<string> => {
    await admin.query('insert into directory.agent_keys (key_id, org_id) values ($1, $2)', [id, org]);
    await admin.query(
      `insert into agents.agent_keys (org_id, id, agent_id, status, scopes, secret_mac, secret_key_version, expires_at,
         created_at)
       values ($1, $2, $3, 'ACTIVE', 'requests:write', $4, 1, '2027-10-08T08:00:00Z', $5)`,
      [org, id, agent, 'c'.repeat(64), at],
    );
    return id;
  },

  /** An active funding source in AED, consented to AED 50,000 a payment and 200,000 a month, and its link: its ID. */
  source: async (org: string, id: string = randomUUID()): Promise<string> => {
    const link = randomUUID();
    await admin.query(
      `insert into funding_sources.links (org_id, id, started_by, partner, session_ref, expires_at, created_at)
       values ($1, $2, $3, 'fake', 'session-1', $5, $4)`,
      [org, link, randomUUID(), at, new Date(at.getTime() + DAY_MS)],
    );
    await admin.query(
      `insert into funding_sources.sources (org_id, id, link_id, partner, external_ref, status, availability,
         consent_status, account_consent_id, consent_expires_at, currency, limit_period, max_payment_minor,
         max_period_minor, max_period_payments, holder_name, account_type, hint, partner_changed_at, created_at)
       values ($1, $2, $3, 'fake', $4, 'ACTIVE', 'ACTIVE', 'Authorized', 'consent-1', '2027-10-06T08:00:00Z', 'AED',
         'month', 5000000, 20000000, 100, 'Acme Trading LLC', 'sme', 'AE…1234', $5, $5)`,
      [org, id, link, `acct-${id}`, at],
    );
    return id;
  },

  /** An unverified supplier with its first version, under the payee key if one is given. */
  supplier: async (org: string, payeeKey: string | null = null): Promise<SeededSupplier> => {
    const supplier = { id: randomUUID(), version: randomUUID() };
    await admin.query(
      `with supplier as (
         insert into suppliers.suppliers (org_id, id, status, current_version_id, payee_key, created_at)
         values ($1, $2, 'UNVERIFIED', $3, $4, $5) returning org_id)
       insert into suppliers.supplier_versions (org_id, id, supplier_id, version, display_name, contacts,
         phone_ciphertext, contacts_key_version, phone_since, source_kind, source_ref, entered_by, entered_at)
       select org_id, $3, $2, 1, 'Gulf Office Supplies LLC', 'phone',
         pg_catalog.decode(pg_catalog.repeat('00', 40), 'hex'), 1, $5, 'registry', 'trade-licence-1', $2, $5
       from supplier`,
      [org, supplier.id, supplier.version, payeeKey, at],
    );
    return supplier;
  },

  /**
   * A mandate waiting with its first draft, in Dubai with a 24-hour split
   * window: AED 5,000 an order, 20,000 a month, approval from 1,000.
   */
  mandate: async (org: string, given: MandateFor): Promise<SeededMandate> => {
    const mandate = { id: randomUUID(), version: randomUUID() };
    await admin.query(
      `with mandate as (
         insert into mandates.mandates (org_id, id, agent_id, time_zone, split_window_hours, status,
           pending_version_id, created_at)
         values ($1, $2, $3, 'Asia/Dubai', 24, 'PENDING_ACCEPTANCE', $4, $5) returning org_id)
       insert into mandates.versions (org_id, id, mandate_id, version, purpose, currency, per_order_limit_minor,
         monthly_limit_minor, approval_threshold_minor, supplier_ids, funding_source_id, split_check, consent_limits,
         terms_hash, drafted_by, drafted_at)
       select org_id, $4, $2, 1, 'Office supplies', 'AED', 500000, 2000000, 100000, $6, $7, 'on', 'strict', $8, $3, $5
       from mandate`,
      [org, mandate.id, given.agent, mandate.version, at, given.supplier, given.source, 'a'.repeat(64)],
    );
    return mandate;
  },
});
