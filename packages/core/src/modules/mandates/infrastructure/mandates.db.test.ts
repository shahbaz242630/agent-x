// B1: mandates and their versions (0035), on the real migrated schema, as the
// app role. The steps that add and move them come with B2–B4 and their seals'
// tamper tests with them; this holds the tables' own rules: the deployment's
// currencies, read only; a mandate born waiting with its first draft, its
// statuses moving only along its machine and each held to the versions it
// needs; one live mandate an agent; limits that nest; an allow-list of
// supplier IDs; an agent and a source of its own organisation only; versions
// made once; and no other organisation's rows, no deletes, no key changes.
// C1: policies and their versions (0037) on the same tables' terms: one of
// each kind, by its ID (the organisation's own, a mandate's own), so what it
// is a policy of never changes; a version in force of its own, checked at commit; rules
// that may each be empty, a per-order cap with what happens over it, rules
// that nest, a supplier list as a mandate's; versions made once.
import { createDatabase, type Database, type DatabaseTransaction, withTenant } from '@agentx/platform/db';
import { createTestDatabase, type TestDatabase, testLogger } from '@agentx/testing';
import { type Insertable, sql, type Updateable } from 'kysely';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { DEFAULT_TIME_ZONE } from '../../../shared-kernel/index.ts';
import {
  CONSENT_LIMITS,
  DEFAULT_SPLIT_WINDOW_HOURS,
  MOST_ALLOWED_SUPPLIERS,
  SPLIT_WINDOW_HOURS,
} from '../domain/mandate.ts';
import type { MandatesTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandatesTables>;

const AT = new Date('2026-10-06T08:00:00Z');

type Tx = DatabaseTransaction<MandatesTables>;
type MandateRow = Insertable<MandatesTables['mandates.mandates']>;
type VersionRow = Insertable<MandatesTables['mandates.versions']>;
type PolicyRow = Insertable<MandatesTables['mandates.policies']>;
type PolicyVersionRow = Insertable<MandatesTables['mandates.policy_versions']>;

interface Org {
  readonly id: string;
  readonly agent: string;
  readonly source: string;
}

/** An organisation with an agent and a funding source, made past the app, as the steps that add them are tested elsewhere. */
const organisation = async (): Promise<Org> => {
  const org = { id: randomUUID(), agent: randomUUID(), source: randomUUID() };
  const link = randomUUID();
  const admin = database.as('admin');
  await admin.query(
    `insert into agents.agents (org_id, id, name, owner, status, scopes, created_at)
     values ($1, $2, 'Purchasing agent', $3, 'ACTIVE', 'requests:write', $4)`,
    [org.id, org.agent, randomUUID(), AT],
  );
  await admin.query(
    `insert into funding_sources.links (org_id, id, started_by, partner, session_ref, expires_at, created_at)
     values ($1, $2, $3, 'fake', 'session-1', $5, $4)`,
    [org.id, link, randomUUID(), AT, new Date(AT.getTime() + 86_400_000)],
  );
  await admin.query(
    `insert into funding_sources.sources (org_id, id, link_id, partner, external_ref, status, availability,
       consent_status, account_consent_id, consent_expires_at, currency, limit_period, max_payment_minor,
       max_period_minor, max_period_payments, holder_name, account_type, hint, partner_changed_at, created_at)
     values ($1, $2, $3, 'fake', $4, 'ACTIVE', 'ACTIVE', 'Authorized', 'consent-1', '2027-10-06T08:00:00Z', 'AED',
       'month', 5000000, 20000000, 100, 'Acme Trading LLC', 'sme', 'AE…1234', $5, $5)`,
    [org.id, org.source, link, `acct-${org.source}`, AT],
  );
  return org;
};

const inOrg = <Result>(org: Org, work: (tx: Tx) => Promise<Result>) => withTenant(app, org.id, work);

/** A version's row, with any column given otherwise. */
const versionRow = (org: Org, mandate: string, id: string, overrides: Partial<VersionRow> = {}): VersionRow => ({
  org_id: org.id,
  id,
  mandate_id: mandate,
  version: 1,
  purpose: 'Office supplies',
  currency: 'AED',
  per_order_limit_minor: 500_000n,
  monthly_limit_minor: 2_000_000n,
  approval_threshold_minor: 100_000n,
  supplier_ids: [randomUUID(), randomUUID()].sort().join(' '),
  funding_source_id: org.source,
  split_check: 'on',
  consent_limits: CONSENT_LIMITS[0],
  ends_at: null,
  terms_hash: 'a'.repeat(64),
  drafted_by: randomUUID(),
  drafted_at: AT,
  ...overrides,
});

/** A mandate's row, waiting for its draft, with any column given otherwise. */
const mandateRow = (org: Org, id: string, pending: string, overrides: Partial<MandateRow> = {}): MandateRow => ({
  org_id: org.id,
  id,
  agent_id: org.agent,
  time_zone: DEFAULT_TIME_ZONE,
  split_window_hours: DEFAULT_SPLIT_WINDOW_HOURS,
  status: 'PENDING_ACCEPTANCE',
  pending_version_id: pending,
  created_at: AT,
  ...overrides,
});

/** Adds a mandate and its first draft in one transaction, as B2 will. */
const add = (org: Org, mandate: MandateRow, version: VersionRow) =>
  inOrg(org, async (tx) => {
    await tx.insertInto('mandates.mandates').values(mandate).execute();
    await tx.insertInto('mandates.versions').values(version).execute();
  });

/** Another agent of the organisation, made past the app: an agent has one open mandate at a time. */
const anotherAgent = async (org: Org): Promise<string> => {
  const agent = randomUUID();
  await database.as('admin').query(
    `insert into agents.agents (org_id, id, name, owner, status, scopes, created_at)
       values ($1, $2, 'Another agent', $3, 'ACTIVE', 'requests:write', $4)`,
    [org.id, agent, randomUUID(), AT],
  );
  return agent;
};

/** A mandate waiting for acceptance with its first draft, for a new agent unless one is given: its ID and the draft's. */
const drafted = async (org: Org, overrides: Partial<VersionRow> = {}, agent?: string) => {
  const [id, version] = [randomUUID(), randomUUID()];
  const agentId = agent ?? (await anotherAgent(org));
  await add(org, mandateRow(org, id, version, { agent_id: agentId }), versionRow(org, id, version, overrides));
  return { id, version };
};

const change = (org: Org, id: string, values: Updateable<MandatesTables['mandates.mandates']>) =>
  inOrg(org, (tx) => tx.updateTable('mandates.mandates').set(values).where('id', '=', id).execute());

const changeVersion = (org: Org, id: string, values: Updateable<MandatesTables['mandates.versions']>) =>
  inOrg(org, (tx) => tx.updateTable('mandates.versions').set(values).where('id', '=', id).execute());

/** Accepts the draft as B3 will: the version in force first, then the status. */
const accepted = async (org: Org, agent?: string) => {
  const mandate = await drafted(org, {}, agent);
  await inOrg(org, async (tx) => {
    await tx
      .updateTable('mandates.mandates')
      .set({
        current_version_id: mandate.version,
        pending_version_id: null,
        accepted_by: randomUUID(),
        accepted_at: AT,
      })
      .where('id', '=', mandate.id)
      .execute();
    await tx.updateTable('mandates.mandates').set({ status: 'ACTIVE' }).where('id', '=', mandate.id).execute();
  });
  return mandate;
};

/** A policy version's row, setting every rule unless given otherwise. */
const policyVersionRow = (
  org: Org,
  policy: string,
  id: string,
  overrides: Partial<PolicyVersionRow> = {},
): PolicyVersionRow => ({
  org_id: org.id,
  id,
  policy_id: policy,
  version: 1,
  currency: 'AED',
  per_order_cap_minor: 250_000n,
  over_per_order_cap: 'REQUIRE_APPROVAL',
  monthly_cap_minor: 2_000_000n,
  approval_threshold_minor: 50_000n,
  supplier_ids: randomUUID(),
  rules_hash: 'b'.repeat(64),
  made_by: randomUUID(),
  made_at: AT,
  ...overrides,
});

/** The organisation's own policy's row (its ID the organisation's), naming its first version. */
const orgPolicyRow = (org: Org, version: string, overrides: Partial<PolicyRow> = {}): PolicyRow => ({
  org_id: org.id,
  id: org.id,
  scope: 'organization',
  mandate_id: null,
  current_version_id: version,
  created_at: AT,
  ...overrides,
});

/** Adds a policy and its first version in one transaction, as C3 will: its version's ID. */
const addPolicy = async (org: Org, policy: PolicyRow, overrides: Partial<PolicyVersionRow> = {}) => {
  const version = policy.current_version_id;
  await inOrg(org, async (tx) => {
    await tx.insertInto('mandates.policies').values(policy).execute();
    await tx
      .insertInto('mandates.policy_versions')
      .values(policyVersionRow(org, policy.id, version, overrides))
      .execute();
  });
  return version;
};

/** The organisation's own policy, with any rule of its first version given otherwise: that version's ID. */
const orgPolicy = (org: Org, overrides: Partial<PolicyVersionRow> = {}) =>
  addPolicy(org, orgPolicyRow(org, randomUUID()), overrides);

/** A mandate's own policy (its ID the mandate's), with any rule of its first version given otherwise: the mandate's ID and the version's. */
const mandatePolicy = async (org: Org, overrides: Partial<PolicyVersionRow> = {}) => {
  const { id } = await drafted(org);
  const row = orgPolicyRow(org, randomUUID(), { id, scope: 'mandate', mandate_id: id });
  return { id, version: await addPolicy(org, row, overrides) };
};

const changePolicy = (org: Org, id: string, values: Updateable<MandatesTables['mandates.policies']>) =>
  inOrg(org, (tx) => tx.updateTable('mandates.policies').set(values).where('id', '=', id).execute());

const refusedBy = (constraint: string): unknown => expect.objectContaining({ constraint });
const DENIED: unknown = expect.objectContaining({ code: '42501' });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandatesTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe('the deployment’s currencies', () => {
  it('are AED, which the app reads and never changes', async () => {
    expect(await app.selectFrom('mandates.allowed_currencies').select('code').execute()).toEqual([{ code: 'AED' }]);
    await expect(app.insertInto('mandates.allowed_currencies').values({ code: 'USD' }).execute()).rejects.toEqual(
      DENIED,
    );
    await expect(app.deleteFrom('mandates.allowed_currencies').execute()).rejects.toEqual(DENIED);
  });

  it('are the only ones a version may be in', async () => {
    const org = await organisation();
    await expect(drafted(org, { currency: 'USD' })).rejects.toEqual(
      expect.objectContaining({ code: '23503', constraint: 'versions_currency_fkey' }),
    );
  });
});

describe('a mandate', () => {
  it('is born waiting for acceptance, with its first draft named before it is added', async () => {
    const org = await organisation();
    const { id, version } = await drafted(org);

    expect(
      await inOrg(org, (tx) =>
        tx
          .selectFrom('mandates.mandates')
          .select(['status', 'pending_version_id', 'current_version_id'])
          .where('id', '=', id)
          .execute(),
      ),
    ).toEqual([{ status: 'PENDING_ACCEPTANCE', pending_version_id: version, current_version_id: null }]);
  });

  it('is never born in another status (status_guard)', async () => {
    const org = await organisation();
    const [id, version] = [randomUUID(), randomUUID()];

    await expect(
      add(org, mandateRow(org, id, version, { status: 'ACTIVE' }), versionRow(org, id, version)),
    ).rejects.toEqual(refusedBy('status_guard'));
  });

  it('waits with a draft that is its own, checked at commit (pending_is_its_own)', async () => {
    const org = await organisation();

    await expect(
      inOrg(org, (tx) =>
        tx
          .insertInto('mandates.mandates')
          .values(mandateRow(org, randomUUID(), randomUUID()))
          .execute(),
      ),
    ).rejects.toEqual(refusedBy('pending_is_its_own'));
  });

  it('is accepted as B3 will accept it, and moves only along its machine', async () => {
    const org = await organisation();
    const { id } = await accepted(org);

    await change(org, id, { status: 'SUSPENDED' });
    await change(org, id, { status: 'ACTIVE' });
    await expect(change(org, id, { status: 'PENDING_ACCEPTANCE' })).rejects.toEqual(refusedBy('status_guard'));
    await change(org, id, { status: 'REVOKED' });
    await expect(change(org, id, { status: 'ACTIVE' })).rejects.toEqual(refusedBy('status_guard'));
  });

  it('expires only once live, suspended or not, and never comes back (status_guard)', async () => {
    const [org, other] = [await organisation(), await organisation()];
    const waiting = await drafted(org);
    const [live, suspended] = [await accepted(org), await accepted(other)];
    await change(other, suspended.id, { status: 'SUSPENDED' });

    await expect(change(org, waiting.id, { status: 'EXPIRED' })).rejects.toEqual(refusedBy('status_guard'));
    await expect(change(org, waiting.id, { status: 'SUSPENDED' })).rejects.toEqual(refusedBy('status_guard'));
    await change(org, live.id, { status: 'EXPIRED' });
    await change(other, suspended.id, { status: 'EXPIRED' });
    await expect(change(org, live.id, { status: 'ACTIVE' })).rejects.toEqual(refusedBy('status_guard'));
    await expect(change(org, live.id, { status: 'REVOKED' })).rejects.toEqual(refusedBy('status_guard'));
  });

  it('is superseded as B3 will: a new version accepted while live, the mandate staying ACTIVE', async () => {
    const org = await organisation();
    const { id, version } = await accepted(org);
    const next = randomUUID();

    await inOrg(org, async (tx) => {
      await tx
        .insertInto('mandates.versions')
        .values(versionRow(org, id, next, { version: 2, monthly_limit_minor: 3_000_000n }))
        .execute();
      await tx.updateTable('mandates.mandates').set({ pending_version_id: next }).where('id', '=', id).execute();
    });
    await change(org, id, {
      current_version_id: next,
      pending_version_id: null,
      accepted_by: randomUUID(),
      accepted_at: AT,
    });

    expect(
      await inOrg(org, (tx) =>
        tx.selectFrom('mandates.mandates').select(['status', 'current_version_id']).where('id', '=', id).execute(),
      ),
    ).toEqual([{ status: 'ACTIVE', current_version_id: next }]);
    // The version it replaced is still there, unchanged: SUPERSEDED by being no longer current.
    expect(
      await inOrg(org, (tx) =>
        tx.selectFrom('mandates.versions').select('version').where('id', '=', version).execute(),
      ),
    ).toEqual([{ version: 1 }]);
  });

  it('never waits on the version already in force (pending_is_not_current)', async () => {
    const org = await organisation();
    const { id, version } = await accepted(org);

    await expect(change(org, id, { pending_version_id: version })).rejects.toEqual(refusedBy('pending_is_not_current'));
  });

  it('keeps its agent, time zone and window as made, while the rest moves on (fixed_at_creation)', async () => {
    const [org, other] = [await organisation(), await organisation()];
    const { id } = await accepted(org, org.agent);
    // The audit module's record writes them again as they are, which is no change.
    await change(org, id, { agent_id: org.agent, time_zone: DEFAULT_TIME_ZONE, split_window_hours: 24 });

    for (const values of [
      { time_zone: 'Pacific/Kiritimati' },
      { split_window_hours: 1 },
      { agent_id: other.agent },
    ] satisfies Updateable<MandatesTables['mandates.mandates']>[]) {
      await expect(change(org, id, values)).rejects.toEqual(refusedBy('fixed_at_creation'));
    }
    await change(org, id, { status: 'SUSPENDED' });
  });

  it('is live or expired only with a version in force (a_status_on_its_versions)', async () => {
    const org = await organisation();
    const { id } = await drafted(org);

    await expect(change(org, id, { status: 'ACTIVE' })).rejects.toEqual(refusedBy('a_status_on_its_versions'));
    // Waiting, it keeps a version to accept.
    await expect(change(org, id, { pending_version_id: null })).rejects.toEqual(refusedBy('a_status_on_its_versions'));
    // A draft never accepted is withdrawn by revoking it.
    await change(org, id, { status: 'REVOKED' });
  });

  it('is accepted by someone, at a time, with its version in force (accepted_with_its_version)', async () => {
    const org = await organisation();
    const { id, version } = await drafted(org);

    await expect(change(org, id, { current_version_id: version, pending_version_id: null })).rejects.toEqual(
      refusedBy('accepted_with_its_version'),
    );
    await expect(change(org, id, { accepted_by: randomUUID(), accepted_at: AT })).rejects.toEqual(
      refusedBy('accepted_with_its_version'),
    );
    // Someone, but no time (from the mutation pass).
    await expect(
      change(org, id, { current_version_id: version, pending_version_id: null, accepted_by: randomUUID() }),
    ).rejects.toEqual(refusedBy('accepted_with_its_version'));
  });

  it('has only its own versions in force (current_is_its_own)', async () => {
    const org = await organisation();
    const { id } = await drafted(org);
    const other = await drafted(org);

    await expect(
      change(org, id, { current_version_id: other.version, accepted_by: randomUUID(), accepted_at: AT }),
    ).rejects.toEqual(refusedBy('current_is_its_own'));
  });

  it('is one of an agent’s while open, and another may follow once it ends (one_open_mandate_an_agent)', async () => {
    const org = await organisation();
    const waiting = await drafted(org, {}, org.agent);

    await expect(drafted(org, {}, org.agent)).rejects.toEqual(refusedBy('one_open_mandate_an_agent'));
    await change(org, waiting.id, { status: 'REVOKED' });
    const first = await accepted(org, org.agent);
    await expect(drafted(org, {}, org.agent)).rejects.toEqual(refusedBy('one_open_mandate_an_agent'));
    await change(org, first.id, { status: 'SUSPENDED' });
    await expect(drafted(org, {}, org.agent)).rejects.toEqual(refusedBy('one_open_mandate_an_agent'));
    await change(org, first.id, { status: 'EXPIRED' });
    await accepted(org, org.agent);
  });

  it('is for an agent of its own organisation only (of_an_agent)', async () => {
    const [org, other] = [await organisation(), await organisation()];
    const [id, version] = [randomUUID(), randomUUID()];

    await expect(
      add(org, mandateRow(org, id, version, { agent_id: other.agent }), versionRow(org, id, version)),
    ).rejects.toEqual(refusedBy('of_an_agent'));
  });

  it('keeps its time zone and window within bounds', async () => {
    const org = await organisation();

    for (const [overrides, constraint] of [
      [{ split_window_hours: SPLIT_WINDOW_HOURS.least - 1 }, 'mandates_split_window_hours_check'],
      [{ split_window_hours: SPLIT_WINDOW_HOURS.most + 1 }, 'mandates_split_window_hours_check'],
      [{ time_zone: '+04:00' }, 'mandates_time_zone_check'],
    ] satisfies [Partial<MandateRow>, string][]) {
      const [id, version] = [randomUUID(), randomUUID()];
      await expect(add(org, mandateRow(org, id, version, overrides), versionRow(org, id, version))).rejects.toEqual(
        refusedBy(constraint),
      );
    }
  });
});

describe('a mandate version', () => {
  it('has limits that nest: approval threshold ≤ per-order ≤ monthly (limits_nest)', async () => {
    const org = await organisation();

    await expect(drafted(org, { approval_threshold_minor: 500_001n })).rejects.toEqual(refusedBy('limits_nest'));
    await expect(drafted(org, { per_order_limit_minor: 2_000_001n })).rejects.toEqual(refusedBy('limits_nest'));
    await drafted(org, {
      approval_threshold_minor: 500_000n,
      per_order_limit_minor: 500_000n,
      monthly_limit_minor: 500_000n,
    });
  });

  it('has positive limits, never a fraction', async () => {
    const org = await organisation();

    await expect(drafted(org, { approval_threshold_minor: 0n })).rejects.toEqual(
      refusedBy('versions_approval_threshold_minor_check'),
    );
    await expect(drafted(org, { monthly_limit_minor: '1.5' })).rejects.toEqual(
      expect.objectContaining({ code: '22P02' }),
    );
  });

  it('names up to 100 suppliers, as lower-case IDs one space apart', async () => {
    const org = await organisation();
    const hundred = Array.from({ length: MOST_ALLOWED_SUPPLIERS }, () => randomUUID()).sort();

    await drafted(org, { supplier_ids: hundred.join(' ') });
    for (const list of [
      [...hundred, randomUUID()].join(' '),
      hundred.slice(0, 2).join(','),
      hundred.slice(0, 2).join('  '),
      randomUUID().toUpperCase(),
      '',
    ]) {
      await expect(drafted(org, { supplier_ids: list })).rejects.toEqual(refusedBy('versions_supplier_ids_check'));
    }
  });

  it('draws on a source of its own organisation only (from_a_source)', async () => {
    const [org, other] = [await organisation(), await organisation()];

    await expect(drafted(org, { funding_source_id: other.source })).rejects.toEqual(refusedBy('from_a_source'));
  });

  it('ends after it was drafted, if it ends (ends_after_its_draft)', async () => {
    const org = await organisation();

    await expect(drafted(org, { ends_at: AT })).rejects.toEqual(refusedBy('ends_after_its_draft'));
    await drafted(org, { ends_at: new Date('2027-01-01T00:00:00Z') });
  });

  it('is numbered once a mandate (one_number_a_version)', async () => {
    const org = await organisation();
    const { id } = await drafted(org);
    const another = (version: number) =>
      inOrg(org, (tx) =>
        tx
          .insertInto('mandates.versions')
          .values(versionRow(org, id, randomUUID(), { version }))
          .execute(),
      );

    await expect(another(1)).rejects.toEqual(refusedBy('one_number_a_version'));
    await another(2);
  });

  it('is made once: nothing in it changes after its first signed state (made_once)', async () => {
    const org = await organisation();
    const { version } = await drafted(org);

    // Before its first signed state, the audit module's record writes it.
    await changeVersion(org, version, { purpose: 'Office supplies' });
    await changeVersion(org, version, { state_event_id: randomUUID() });
    await expect(changeVersion(org, version, { monthly_limit_minor: 99_000_000n })).rejects.toEqual(
      refusedBy('made_once'),
    );
  });
});

describe('a policy', () => {
  it('is the organisation’s own, by the organisation’s ID, or a mandate’s own, by the mandate’s (one_of_each_kind)', async () => {
    const org = await organisation();
    await orgPolicy(org);
    const { id } = await mandatePolicy(org);

    expect(
      await inOrg(org, (tx) =>
        tx.selectFrom('mandates.policies').select(['id', 'scope', 'mandate_id']).orderBy('scope').execute(),
      ),
    ).toEqual([
      { id, scope: 'mandate', mandate_id: id },
      { id: org.id, scope: 'organization', mandate_id: null },
    ]);
  });

  it('is one of each kind: never another ID, nor a mandate’s without its mandate (one_of_each_kind)', async () => {
    const org = await organisation();
    const { id: mandate } = await drafted(org);

    for (const row of [
      orgPolicyRow(org, randomUUID(), { id: randomUUID() }),
      orgPolicyRow(org, randomUUID(), { mandate_id: mandate }),
      orgPolicyRow(org, randomUUID(), { id: randomUUID(), scope: 'mandate', mandate_id: mandate }),
      orgPolicyRow(org, randomUUID(), { id: mandate, scope: 'mandate', mandate_id: null }),
    ]) {
      await expect(addPolicy(org, row)).rejects.toEqual(refusedBy('one_of_each_kind'));
    }
    await expect(addPolicy(org, orgPolicyRow(org, randomUUID(), { scope: 'agent' }))).rejects.toEqual(
      refusedBy('policies_scope_check'),
    );
  });

  it('is at most one of each kind (policies_pkey)', async () => {
    const org = await organisation();
    await orgPolicy(org);

    await expect(orgPolicy(org)).rejects.toEqual(refusedBy('policies_pkey'));
  });

  it('is for a mandate of its own organisation only (of_a_mandate)', async () => {
    const [org, other] = [await organisation(), await organisation()];
    const { id } = await drafted(other);

    await expect(
      addPolicy(org, orgPolicyRow(org, randomUUID(), { id, scope: 'mandate', mandate_id: id })),
    ).rejects.toEqual(refusedBy('of_a_mandate'));
  });

  it('has a version in force of its own from the start, checked at commit (current_is_its_own)', async () => {
    const [org, other] = [await organisation(), await organisation()];
    const elsewhere = await orgPolicy(other);

    await expect(
      inOrg(org, (tx) => tx.insertInto('mandates.policies').values(orgPolicyRow(org, randomUUID())).execute()),
    ).rejects.toEqual(refusedBy('current_is_its_own'));
    await expect(
      inOrg(org, (tx) => tx.insertInto('mandates.policies').values(orgPolicyRow(org, elsewhere)).execute()),
    ).rejects.toEqual(refusedBy('current_is_its_own'));
  });

  it('moves to a new version of its own, never to another kind (one_of_each_kind)', async () => {
    const org = await organisation();
    const { id: mandate } = await drafted(org);
    const first = await orgPolicy(org);
    const second = randomUUID();
    await inOrg(org, (tx) =>
      tx
        .insertInto('mandates.policy_versions')
        .values(policyVersionRow(org, org.id, second, { version: 2 }))
        .execute(),
    );

    // The audit module's record writes them again as they are, which is no change.
    await changePolicy(org, org.id, { scope: 'organization', mandate_id: null, current_version_id: second });
    for (const values of [
      { scope: 'mandate', mandate_id: mandate },
      { scope: 'mandate' },
      { mandate_id: mandate },
    ] satisfies Updateable<MandatesTables['mandates.policies']>[]) {
      await expect(changePolicy(org, org.id, values)).rejects.toEqual(refusedBy('one_of_each_kind'));
    }
    await changePolicy(org, org.id, { current_version_id: first });
  });

  it('may set no rule at all, or any one alone', async () => {
    const org = await organisation();
    const none = {
      per_order_cap_minor: null,
      over_per_order_cap: null,
      monthly_cap_minor: null,
      approval_threshold_minor: null,
      supplier_ids: null,
    } satisfies Partial<PolicyVersionRow>;
    await orgPolicy(org, none);

    for (const one of [
      { per_order_cap_minor: 1n, over_per_order_cap: 'DENY' },
      { monthly_cap_minor: 1n },
      { approval_threshold_minor: 1n },
      { supplier_ids: randomUUID() },
    ] satisfies Partial<PolicyVersionRow>[]) {
      await mandatePolicy(org, { ...none, ...one });
    }
  });

  it('says what happens over its per-order cap, and only with one (a_cap_with_its_outcome)', async () => {
    const org = await organisation();

    await expect(orgPolicy(org, { over_per_order_cap: null })).rejects.toEqual(refusedBy('a_cap_with_its_outcome'));
    await expect(orgPolicy(org, { per_order_cap_minor: null })).rejects.toEqual(refusedBy('a_cap_with_its_outcome'));
    await expect(orgPolicy(org, { over_per_order_cap: 'ALLOW' })).rejects.toEqual(
      refusedBy('policy_versions_over_per_order_cap_check'),
    );
    await orgPolicy(org, { over_per_order_cap: 'DENY' });
  });

  it('has rules that nest where both are set: approval threshold ≤ per-order cap ≤ monthly cap (rules_nest)', async () => {
    const org = await organisation();

    for (const rules of [
      { approval_threshold_minor: 250_001n },
      { per_order_cap_minor: 2_000_001n },
      { per_order_cap_minor: null, over_per_order_cap: null, approval_threshold_minor: 2_000_001n },
    ] satisfies Partial<PolicyVersionRow>[]) {
      await expect(orgPolicy(org, rules)).rejects.toEqual(refusedBy('rules_nest'));
    }
    await orgPolicy(org, {
      approval_threshold_minor: 250_000n,
      per_order_cap_minor: 250_000n,
      monthly_cap_minor: 250_000n,
    });
  });

  it('has positive rules, in an allowed currency', async () => {
    const org = await organisation();

    await expect(orgPolicy(org, { monthly_cap_minor: 0n })).rejects.toEqual(
      refusedBy('policy_versions_monthly_cap_minor_check'),
    );
    await expect(orgPolicy(org, { approval_threshold_minor: -1n })).rejects.toEqual(
      refusedBy('policy_versions_approval_threshold_minor_check'),
    );
    await expect(orgPolicy(org, { per_order_cap_minor: -1n, approval_threshold_minor: null })).rejects.toEqual(
      refusedBy('policy_versions_per_order_cap_minor_check'),
    );
    await expect(orgPolicy(org, { currency: 'USD' })).rejects.toEqual(
      expect.objectContaining({ code: '23503', constraint: 'policy_versions_currency_fkey' }),
    );
  });

  it('names its suppliers as a mandate does: up to 100 lower-case IDs one space apart', async () => {
    const org = await organisation();
    const hundred = Array.from({ length: MOST_ALLOWED_SUPPLIERS }, () => randomUUID()).sort();

    await orgPolicy(org, { supplier_ids: hundred.join(' ') });
    for (const list of [
      [...hundred, randomUUID()].join(' '),
      hundred.slice(0, 2).join(','),
      randomUUID().toUpperCase(),
      '',
    ]) {
      await expect(mandatePolicy(org, { supplier_ids: list })).rejects.toEqual(
        refusedBy('policy_versions_supplier_ids_check'),
      );
    }
  });

  it('is numbered once a policy, each version made once (one_number_a_policy_version, made_once)', async () => {
    const org = await organisation();
    const version = await orgPolicy(org);
    const another = (number: number) =>
      inOrg(org, (tx) =>
        tx
          .insertInto('mandates.policy_versions')
          .values(policyVersionRow(org, org.id, randomUUID(), { version: number }))
          .execute(),
      );
    const changeVersion = (values: Updateable<MandatesTables['mandates.policy_versions']>) =>
      inOrg(org, (tx) => tx.updateTable('mandates.policy_versions').set(values).where('id', '=', version).execute());

    await expect(another(1)).rejects.toEqual(refusedBy('one_number_a_policy_version'));
    await another(2);
    // Before its first signed state, the audit module's record writes it.
    await changeVersion({ state_event_id: randomUUID() });
    await expect(changeVersion({ monthly_cap_minor: 99_000_000n })).rejects.toEqual(refusedBy('made_once'));
  });
});

describe('the app', () => {
  it('sees no other organisation’s mandates, policies or versions', async () => {
    const [org, other] = [await organisation(), await organisation()];
    const { id, version } = await drafted(org);
    const policyVersion = await orgPolicy(org);

    const seen = await inOrg(other, async (tx) => [
      ...(await tx.selectFrom('mandates.mandates').select('id').where('id', '=', id).execute()),
      ...(await tx.selectFrom('mandates.versions').select('id').where('id', '=', version).execute()),
      ...(await tx.selectFrom('mandates.policies').select('id').where('id', '=', org.id).execute()),
      ...(await tx.selectFrom('mandates.policy_versions').select('id').where('id', '=', policyVersion).execute()),
    ]);
    expect(seen).toEqual([]);
  });

  it('never deletes, and never changes a key or a creation time', async () => {
    const org = await organisation();
    const { id, version } = await drafted(org);
    const policyVersion = await orgPolicy(org);

    for (const statement of [
      (tx: Tx) => tx.deleteFrom('mandates.mandates').where('id', '=', id).execute(),
      (tx: Tx) => tx.deleteFrom('mandates.versions').where('id', '=', version).execute(),
      (tx: Tx) => tx.updateTable('mandates.mandates').set({ created_at: AT }).where('id', '=', id).execute(),
      (tx: Tx) => tx.updateTable('mandates.mandates').set({ id: randomUUID() }).where('id', '=', id).execute(),
      (tx: Tx) => tx.updateTable('mandates.versions').set({ org_id: randomUUID() }).where('id', '=', version).execute(),
      (tx: Tx) => sql`truncate mandates.versions`.execute(tx),
      (tx: Tx) => tx.deleteFrom('mandates.policies').where('id', '=', org.id).execute(),
      (tx: Tx) => tx.deleteFrom('mandates.policy_versions').where('id', '=', policyVersion).execute(),
      (tx: Tx) => tx.updateTable('mandates.policies').set({ created_at: AT }).where('id', '=', org.id).execute(),
      (tx: Tx) => tx.updateTable('mandates.policies').set({ id: randomUUID() }).where('id', '=', org.id).execute(),
      (tx: Tx) =>
        tx
          .updateTable('mandates.policy_versions')
          .set({ org_id: randomUUID() })
          .where('id', '=', policyVersion)
          .execute(),
    ]) {
      await expect(inOrg<unknown>(org, statement)).rejects.toEqual(DENIED);
    }
  });
});
