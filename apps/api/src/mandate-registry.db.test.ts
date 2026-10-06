// Phase 2 B2: drafting and reading mandates, composed in the API, on the real
// migrated schema as the app role, with a signed agent, a funding source
// linked through the fake partner and signed suppliers: an admin drafts one
// for an active agent with no mandate open, on the organisation's own
// usable source and suppliers, within the bank consent unless flexible;
// every refusal by its code; a retry answered from the mandate; a later
// draft replacing the one waiting, none for an ended mandate; the day's
// budget; and every member reads them.
import { addAgent, AGENTS, type AgentsTables } from '@agentx/core/modules/agents';
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { addLink, addSource, type FundingSourcesTables, settleLink } from '@agentx/core/modules/funding-sources';
import { addMembership, type IdentityTables, type Role, userForSubject } from '@agentx/core/modules/identity';
import { MANDATES, type MandatesTables, MOST_DRAFTS_A_DAY } from '@agentx/core/modules/mandates';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createFakeRail } from '@agentx/core/modules/providers';
import { addSupplier, type SuppliersTables } from '@agentx/core/modules/suppliers';
import { money } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createMandateRegistry,
  DRAFT_OPERATION,
  type MandateDraft,
  type MandateRegistry,
  type MandateWrite,
  REDRAFT_OPERATION,
} from './mandate-registry.ts';
import type { Member } from './use-case-work.ts';

type Tables = IdentityTables &
  MandatesTables &
  AgentsTables &
  FundingSourcesTables &
  SuppliersTables &
  OrganizationsTables &
  DirectoryTables &
  AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb2a0_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b2';
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';

let clock: FixedClock;
let registry: MandateRegistry;

const quiet = () => ({ keys, ids, logger: testLogger() });

interface World {
  readonly org: string;
  readonly admin: Member;
  readonly agent: string;
  readonly source: string;
  /** The source's consent per payment, in fils. */
  readonly maxPayment: bigint;
  readonly suppliers: readonly string[];
}

let people = 0;

async function member(org: string, role: Role): Promise<Member> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `mandate-registry-${String(people)}` },
    { ids, clock },
  );
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: ids.next(), userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId };
}

/** An organisation with an admin, an active agent, a source linked through the fake partner, and two suppliers. */
async function world(): Promise<World> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  const admin = await member(org, 'admin');
  const agent = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addAgent(tx, states, {
      orgId: org,
      id: agent,
      name: 'Purchasing agent',
      owner: ids.next(),
      scopes: ['requests:write'],
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  const rail = createFakeRail({ clock, ids: new SequentialIds(0xfa0_b200_0000) });
  const linkId = ids.next();
  const session = await rail.startSourceLink({ organizationId: org, linkId });
  await rail.bank.approve(org, session.sessionRef, ACCOUNT);
  const answer = await rail.confirmSourceLink({ organizationId: org, linkId });
  if (answer.kind !== 'linked') throw new Error(`not linked: ${answer.kind}`);
  await withTenant(app, org, (tx) =>
    addLink(tx, {
      orgId: org,
      id: linkId,
      startedBy: ids.next(),
      partner: 'fake',
      sessionRef: session.sessionRef,
      expiresAt: session.expiresAt,
      createdAt: clock.now(),
    }),
  );
  const source = ids.next();
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    await addSource(tx, states, {
      orgId: org,
      id: source,
      linkId,
      partner: 'fake',
      state: answer.source,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    await settleLink(tx, { orgId: org, id: linkId }, { outcome: 'linked', sourceId: source }, clock.now());
  });
  const suppliers = [ids.next(), ids.next()];
  for (const id of suppliers) {
    await withSignedStates(app, org, quiet(), (tx, states) =>
      addSupplier(tx, states, keys, {
        orgId: org,
        id,
        versionId: ids.next(),
        supplier: {
          displayName: 'Gulf Office Supplies LLC',
          contacts: { phone: '+971501234567', email: null, tradeLicence: null },
          source: { kind: 'registry', ref: 'DED-123456' },
        },
        enteredBy: ids.next(),
        createdAt: clock.now(),
        actor: OPERATOR,
      }),
    );
  }
  return { org, admin, agent, source, maxPayment: answer.source.controls.maxPaymentMinor, suppliers };
}

const AED = (minor: bigint) => money(minor, 'AED');

/** A draft within the source's consent: the per-order limit at most what it allows per payment. */
const draftOf = (w: World, overrides: Partial<MandateDraft['terms']> = {}, agentId = w.agent): MandateDraft => ({
  agentId,
  timeZone: null,
  splitWindowHours: null,
  terms: {
    purpose: 'Office supplies',
    perOrderLimit: AED(w.maxPayment),
    monthlyLimit: AED(w.maxPayment * 2n),
    approvalThreshold: AED(w.maxPayment / 2n),
    supplierIds: [...w.suppliers].sort(),
    fundingSourceId: w.source,
    splitCheck: true,
    consentLimits: 'strict',
    endsAt: null,
    ...overrides,
  },
});

let keysUsed = 0;
/** A fresh idempotency key for each write. */
const nextKey = () => {
  keysUsed += 1;
  return `key-${String(keysUsed)}`;
};
const keyed = (who: Member, operation: string, key = nextKey()): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload: '{}',
});

const draft = (who: Member, given: MandateDraft, key?: string) =>
  registry.draft(who, keyed(who, DRAFT_OPERATION, key), given, CORRELATION);

const redraft = (who: Member, mandateId: string, terms: MandateDraft['terms']) =>
  registry.redraft(who, keyed(who, REDRAFT_OPERATION), mandateId, terms, CORRELATION);

const draftedOf = (write: MandateWrite) => {
  if (write.outcome !== 'drafted') throw new Error(`not drafted: ${JSON.stringify(write)}`);
  return write;
};

const refused = (status: number, code: string) => ({ outcome: 'refused', status, code });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-06T08:00:00Z'));
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger: testLogger(new LogCapture()) });
});

describe('drafting a mandate (B2)', () => {
  it('an admin drafts one, waiting for acceptance, answered with its draft and no warning', async () => {
    const w = await world();
    const drafted = draftedOf(await draft(w.admin, draftOf(w)));

    expect(drafted.mandate).toMatchObject({
      agentId: w.agent,
      timeZone: 'Asia/Dubai',
      splitWindowHours: 24,
      status: 'PENDING_ACCEPTANCE',
      currentVersionId: null,
    });
    expect(drafted.current).toBeNull();
    expect(drafted.pending).toMatchObject({ version: { version: 1, purpose: 'Office supplies' }, consentWarnings: [] });
    const actions = await withTenant(app, w.org, (tx) =>
      tx.selectFrom('audit.events').select('action').where('subject_id', '=', drafted.mandate.id).execute(),
    );
    expect(actions).toEqual([{ action: 'mandate.drafted' }]);
  });

  it('keeps the zone and window given', async () => {
    const w = await world();
    const drafted = draftedOf(await draft(w.admin, { ...draftOf(w), timeZone: 'Europe/London', splitWindowHours: 48 }));

    expect(drafted.mandate).toMatchObject({ timeZone: 'Europe/London', splitWindowHours: 48 });
  });

  it('answers a retry from the mandate, drafting nothing twice', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w), 'the-same-key'));
    const again = draftedOf(await draft(w.admin, draftOf(w), 'the-same-key'));

    expect(again.mandate.id).toBe(first.mandate.id);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s', async (role) => {
    const w = await world();
    expect(await draft(await member(w.org, role), draftOf(w))).toEqual(refused(403, 'FORBIDDEN'));
  });

  it('refuses an agent not the organisation’s, or suspended', async () => {
    const w = await world();
    expect(await draft(w.admin, draftOf(w, {}, ids.next()))).toEqual(refused(404, 'NOT_FOUND'));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspend',
        details: {},
      }),
    );
    expect(await draft(w.admin, draftOf(w))).toEqual(refused(409, 'AGENT_NOT_ACTIVE'));
  });

  it('refuses a second mandate for an agent with one waiting, in force or suspended; one revoked frees it', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));

    expect(await draft(w.admin, draftOf(w))).toEqual(refused(409, 'MANDATE_OPEN'));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, MANDATES, { orgId: w.org, id: first.mandate.id }, 'revoke', {
        actor: OPERATOR,
        action: 'mandate.revoke',
        details: {},
      }),
    );
    draftedOf(await draft(w.admin, draftOf(w)));
  });

  it('refuses a supplier or a source not the organisation’s', async () => {
    const [w, other] = [await world(), await world()];

    expect(await draft(w.admin, draftOf(w, { supplierIds: [w.suppliers[0] ?? '', other.suppliers[0] ?? ''] }))).toEqual(
      refused(409, 'SUPPLIER_UNKNOWN'),
    );
    expect(await draft(w.admin, draftOf(w, { fundingSourceId: other.source }))).toEqual(
      refused(409, 'SOURCE_NOT_USABLE'),
    );
  });

  it('refuses a strict mandate past the bank consent, and keeps a flexible one with its warning', async () => {
    const w = await world();
    const past = { perOrderLimit: AED(w.maxPayment + 1n), monthlyLimit: AED(w.maxPayment * 2n) };

    expect(await draft(w.admin, draftOf(w, past))).toEqual(refused(409, 'MANDATE_PAST_CONSENT'));
    const kept = draftedOf(await draft(w.admin, draftOf(w, { ...past, consentLimits: 'flexible' })));
    expect(kept.pending?.consentWarnings).toEqual(['the per-order limit is above the bank consent’s per payment']);
  });
});

describe('drafting a later version (B2)', () => {
  it('replaces the draft waiting, the mandate as it was', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    const second = draftedOf(await redraft(w.admin, first.mandate.id, draftOf(w, { purpose: 'Stationery' }).terms));

    expect(second.mandate).toMatchObject({ id: first.mandate.id, status: 'PENDING_ACCEPTANCE' });
    expect(second.pending).toMatchObject({ version: { version: 2, purpose: 'Stationery' } });
  });

  it('refuses one for a mandate ended, or none of the organisation’s', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, MANDATES, { orgId: w.org, id: first.mandate.id }, 'revoke', {
        actor: OPERATOR,
        action: 'mandate.revoke',
        details: {},
      }),
    );

    expect(await redraft(w.admin, first.mandate.id, draftOf(w).terms)).toEqual(refused(409, 'MANDATE_ENDED'));
    expect(await redraft(w.admin, ids.next(), draftOf(w).terms)).toEqual(refused(404, 'NOT_FOUND'));
  });

  it(`spends the day's budget of ${String(MOST_DRAFTS_A_DAY)} drafts, and refuses the next until a day has passed`, async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    for (let made = 1; made < MOST_DRAFTS_A_DAY; made += 1) {
      draftedOf(await redraft(w.admin, first.mandate.id, draftOf(w).terms));
    }

    expect(await redraft(w.admin, first.mandate.id, draftOf(w).terms)).toEqual(refused(409, 'MANDATE_DRAFTS_SPENT'));
    clock.advanceBy(24 * 60 * 60 * 1000 + 1);
    draftedOf(await redraft(w.admin, first.mandate.id, draftOf(w).terms));
  }, 60_000);
});

describe('reading mandates (B2)', () => {
  it('lists and shows them to every member', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    const viewer = await member(w.org, 'viewer');

    expect(await registry.list(viewer.orgId, { after: null, limit: 10 }, CORRELATION)).toMatchObject({
      outcome: 'listed',
      mandates: [{ id: first.mandate.id, purpose: 'Office supplies', status: 'PENDING_ACCEPTANCE' }],
      next: null,
    });
    expect(await registry.show(viewer.orgId, first.mandate.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      pending: { version: { version: 1 } },
    });
    expect(await registry.show(viewer.orgId, ids.next(), CORRELATION)).toEqual(refused(404, 'NOT_FOUND'));
  });
});
