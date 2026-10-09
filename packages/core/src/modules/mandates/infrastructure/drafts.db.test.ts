// B2: drafting mandates and their versions, and reading them, on the real
// migrated schema, as the app role: a mandate born waiting with its first
// version, both sealed and read back whole; a later draft replacing the one
// that waited; none for an ended mandate; pages; the agent's open mandate; the
// day's count; and (FX-TAMPER, SEC-DB-03's store half) a limit or a status
// changed by the owner past the app, denied and the organisation held.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { seedRows } from '../../../seed-rows.helper.test.ts';
import { type TamperSign, withSignedStates } from '../../audit/index.ts';
import { createOrganization } from '../../organizations/index.ts';
import { DAY_MS, money } from '../../../shared-kernel/index.ts';
import { type MandateTerms, MandateTermsRefused } from '../domain/terms.ts';
import {
  draftMandate,
  draftsSince,
  draftVersion,
  mandateOf,
  mandatesPage,
  mandateVersionOf,
  openMandateOfAgent,
  termsHash,
} from './drafts.ts';
import { acceptDraft, agentOfMandate, mandatesOfAgent } from './acceptance.ts';
import { MANDATE_VERSIONS, MANDATES } from './mandates.ts';
import type { MandatesTables } from './tables.ts';

type OrganizationTables = Parameters<typeof createOrganization>[0] extends Transaction<infer T> ? T : never;
type Tables = MandatesTables & OrganizationTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb2_0000);
const clock = new FixedClock(new Date('2026-10-06T08:00:00Z'));
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const AED = (minor: bigint) => money(minor, 'AED');

let capture: LogCapture;
let owner: OwnerTamper;
let ownerOfVersions: OwnerTamper;
let org: string;
let agent: string;
/** Another agent: an agent has one mandate open at most (0035). */
let otherAgent: string;
let source: string;

const services = () => ({ keys, ids, logger: testLogger(capture) });
const quiet = () => ({ keys, ids, logger: testLogger() });

const terms = (overrides: Partial<MandateTerms> = {}): MandateTerms => ({
  purpose: 'Office supplies',
  perOrderLimit: AED(500_000n),
  monthlyLimit: AED(2_000_000n),
  approvalThreshold: AED(100_000n),
  supplierIds: [ids.next(), ids.next()],
  fundingSourceId: source,
  splitCheck: true,
  consentLimits: 'strict',
  endsAt: null,
  ...overrides,
});

/** An agent and a funding source of the organisation, made past the app: the steps that add them are tested elsewhere. */
async function seed(): Promise<void> {
  const rows = seedRows(database.as('admin'), clock.now());
  agent = await rows.agent(org, { id: ids.next() });
  otherAgent = await rows.agent(org, { id: ids.next(), name: 'Another agent' });
  source = await rows.source(org, ids.next());
}

/** A mandate drafted with its first version, for the agent unless another is given: their IDs. */
async function drafted(given: MandateTerms = terms(), agentId = agent): Promise<{ id: string; versionId: string }> {
  const [id, versionId] = [ids.next(), ids.next()];
  await withSignedStates(app, org, quiet(), (tx, states) =>
    draftMandate(tx, states, {
      orgId: org,
      id,
      versionId,
      agentId,
      timeZone: 'Asia/Dubai',
      splitWindowHours: 24,
      terms: given,
      draftedBy: ids.next(),
      draftedAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return { id, versionId };
}

/** A later draft of the mandate, from it read for change: its ID. */
async function redrafted(mandateId: string, given: MandateTerms = terms()): Promise<string> {
  const id = ids.next();
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await mandateOf(tx, states, { orgId: org, id: mandateId }, 'change');
    if (read.outcome !== 'found') throw new Error('The mandate was not found');
    return draftVersion(tx, states, read, {
      orgId: org,
      id,
      terms: given,
      draftedBy: ids.next(),
      draftedAt: clock.now(),
      actor: OPERATOR,
    });
  });
  return id;
}

/** Revokes the mandate, as B4 will. */
const revoked = (id: string) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, MANDATES, { orgId: org, id }, 'revoke', {
      actor: OPERATOR,
      action: 'mandate.revoke',
      details: {},
    }),
  );

const read = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) => mandateOf(tx, states, { orgId: org, id }, 'share'));

const readVersion = (id: string, mandateId: string) =>
  withSignedStates(app, org, services(), (tx, states) => mandateVersionOf(tx, states, { orgId: org, id }, mandateId));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  await seed();
  owner = await tamperAsOwner(database, MANDATES, org);
  ownerOfVersions = await tamperAsOwner(database, MANDATE_VERSIONS, org);
});

afterEach(async () => {
  await owner.end();
  await ownerOfVersions.end();
});

describe('drafting a mandate (B2)', () => {
  it('makes it waiting for acceptance, with its first version, both read back whole', async () => {
    const given = terms({ endsAt: new Date('2027-01-01T00:00:00Z'), consentLimits: 'flexible', splitCheck: false });
    const { id, versionId } = await drafted(given);

    expect(await read(id)).toMatchObject({
      outcome: 'found',
      mandate: {
        id,
        agentId: agent,
        timeZone: 'Asia/Dubai',
        splitWindowHours: 24,
        status: 'PENDING_ACCEPTANCE',
        currentVersionId: null,
        pendingVersionId: versionId,
        acceptedBy: null,
        acceptedAt: null,
      },
    });
    const version = await readVersion(versionId, id);
    const binding = { id, agentId: agent, timeZone: 'Asia/Dubai', splitWindowHours: 24 };
    expect(version).toEqual({
      outcome: 'found',
      version: {
        ...given,
        supplierIds: [...given.supplierIds].sort(),
        id: versionId,
        mandateId: id,
        version: 1,
        termsHash: termsHash(binding, 1, { ...given, supplierIds: [...given.supplierIds].sort() }),
        draftedBy: expect.any(String) as unknown,
        draftedAt: clock.now(),
      },
    });
  });

  it('refuses terms it can’t have before any SQL runs', async () => {
    await expect(drafted(terms({ approvalThreshold: AED(500_001n) }))).rejects.toBeInstanceOf(MandateTermsRefused);
    expect(await openOf()).toEqual({ outcome: 'missing' });
  });

  it('binds each version’s terms hash to the mandate, the version’s number and every term', () => {
    const binding = { id: org, agentId: agent, timeZone: 'Asia/Dubai', splitWindowHours: 24 };
    const base = terms();
    const hash = termsHash(binding, 1, base);

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    for (const changed of [
      termsHash({ ...binding, agentId: source }, 1, base),
      termsHash({ ...binding, timeZone: 'Europe/London' }, 1, base),
      termsHash({ ...binding, splitWindowHours: 25 }, 1, base),
      termsHash(binding, 2, base),
      termsHash(binding, 1, { ...base, monthlyLimit: AED(2_000_001n) }),
      termsHash(binding, 1, { ...base, supplierIds: [base.supplierIds[0] ?? ''] }),
      termsHash(binding, 1, { ...base, splitCheck: false }),
      termsHash(binding, 1, { ...base, consentLimits: 'flexible' }),
    ]) {
      expect(changed).not.toBe(hash);
    }
  });
});

describe('drafting a later version (B2)', () => {
  it('makes it the draft waiting, replacing one that waited, numbered on', async () => {
    const { id, versionId } = await drafted();
    const second = await redrafted(id, terms({ purpose: 'Stationery' }));
    const third = await redrafted(id);

    expect(await read(id)).toMatchObject({ mandate: { status: 'PENDING_ACCEPTANCE', pendingVersionId: third } });
    expect(await readVersion(second, id)).toMatchObject({ version: { version: 2, purpose: 'Stationery' } });
    expect(await readVersion(third, id)).toMatchObject({ version: { version: 3 } });
    // The first is kept as it was, made once.
    expect(await readVersion(versionId, id)).toMatchObject({ version: { version: 1, purpose: 'Office supplies' } });
  });

  it('finds no version of another mandate as one of this one’s', async () => {
    const first = await drafted();
    const second = await drafted(terms(), otherAgent);
    expect(await readVersion(first.versionId, second.id)).toEqual({ outcome: 'missing' });
  });

  it('refuses an ended mandate', async () => {
    const { id } = await drafted();
    await revoked(id);

    await expect(redrafted(id)).rejects.toThrow('An ended mandate takes no new version');
  });
});

const openOf = () => withSignedStates(app, org, quiet(), (tx, states) => openMandateOfAgent(tx, states, org, agent));

describe('reading mandates (B2)', () => {
  it('lists them a page at a time, each with the purpose of its version in force or waiting', async () => {
    const first = await drafted(terms({ purpose: 'Office supplies' }));
    const second = await drafted(terms({ purpose: 'Cleaning' }), otherAgent);
    const page = (after: string | null) =>
      withSignedStates(app, org, quiet(), (tx, states) => mandatesPage(tx, states, org, { after, limit: 1 }));

    expect(await page(null)).toMatchObject({
      outcome: 'listed',
      mandates: [{ id: first.id, purpose: 'Office supplies' }],
      next: first.id,
    });
    expect(await page(first.id)).toMatchObject({ mandates: [{ id: second.id, purpose: 'Cleaning' }], next: null });
  });

  it('finds the agent’s open mandate, none once it ended, and counts the day’s drafts', async () => {
    const first = await drafted();
    await redrafted(first.id);
    expect(await openOf()).toMatchObject({ outcome: 'found', mandate: { id: first.id } });
    await revoked(first.id);
    expect(await openOf()).toEqual({ outcome: 'missing' });
    const second = await drafted();
    expect(await openOf()).toMatchObject({ outcome: 'found', mandate: { id: second.id } });

    const since = (at: Date) => withSignedStates(app, org, quiet(), (tx) => draftsSince(tx, org, at));
    expect(await since(new Date(clock.now().getTime() - DAY_MS))).toBe(3);
    expect(await since(clock.now())).toBe(0);
  });
});

/** Denied with the alarm on the row, and the organisation held for it. */
async function deniedAndHeld(
  readIt: () => Promise<unknown>,
  { id, subjectType, sign }: { id: string; subjectType: 'mandate' | 'mandate_version'; sign: TamperSign },
): Promise<void> {
  expect(await readIt()).toEqual({ outcome: 'tampered', sign });
  expect(capture.lines().filter((line) => line.event === 'audit.integrity_failed')).toEqual([
    expect.objectContaining({ chain: 'organisation', check: 'state', reason: sign, subjectType, objectId: id }),
  ]);
  expect(
    await withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none')),
  ).toMatchObject({ outcome: 'held' });
}

/** Accepts `versionId` as B3's use case does: from the mandate read for change. */
const acceptedNow = (mandateId: string, versionId: string) =>
  withSignedStates(app, org, quiet(), async (tx, states) => {
    const read = await mandateOf(tx, states, { orgId: org, id: mandateId }, 'change');
    if (read.outcome !== 'found') throw new Error('The mandate was not found');
    await acceptDraft(tx, states, read, {
      orgId: org,
      versionId,
      acceptedBy: ids.next(),
      acceptedAt: clock.now(),
      actor: OPERATOR,
      details: {},
    });
  });

describe('accepting a draft, the core (B3)', () => {
  it('makes the draft waiting the version in force, ACTIVE for a first; a later one supersedes it, still ACTIVE', async () => {
    const { id, versionId } = await drafted();
    await acceptedNow(id, versionId);
    expect(await read(id)).toMatchObject({
      mandate: { status: 'ACTIVE', currentVersionId: versionId, pendingVersionId: null, acceptedAt: clock.now() },
    });

    const second = await redrafted(id);
    await acceptedNow(id, second);
    expect(await read(id)).toMatchObject({ mandate: { status: 'ACTIVE', currentVersionId: second } });
  });

  it('accepts only the draft waiting, on a mandate waiting or ACTIVE', async () => {
    const { id, versionId } = await drafted();
    await expect(acceptedNow(id, ids.next())).rejects.toThrow('Only the draft waiting is accepted');
    await revoked(id);
    await expect(acceptedNow(id, versionId)).rejects.toThrow('Only a mandate waiting or ACTIVE takes a version');
  });

  it('names a mandate’s agent, none for another organisation’s, and the agent’s mandates by ID', async () => {
    const first = await drafted();
    await revoked(first.id);
    const second = await drafted();
    const agentOf = (id: string) => withSignedStates(app, org, quiet(), (tx) => agentOfMandate(tx, org, id));

    expect(await agentOf(first.id)).toBe(agent);
    expect(await agentOf(ids.next())).toBeUndefined();
    expect(await withSignedStates(app, org, quiet(), (tx) => mandatesOfAgent(tx, org, agent))).toEqual(
      [first.id, second.id].sort(),
    );
  });
});

describe('FX-TAMPER as the owner on a mandate (SEC-DB-03, the store’s half)', () => {
  it('its monthly limit raised past the app: denied, and held', async () => {
    const { id, versionId } = await drafted();
    await ownerOfVersions.query('alter table mandates.versions disable trigger made_once');
    try {
      await ownerOfVersions.setColumn(versionId, 'monthly_limit_minor', '99000000');
    } finally {
      await ownerOfVersions.query('alter table mandates.versions enable trigger made_once');
    }

    await deniedAndHeld(() => readVersion(versionId, id), {
      id: versionId,
      subjectType: 'mandate_version',
      sign: 'seal',
    });
  });

  it('a listed mandate’s version changed past the app: the page refused, and held', async () => {
    const { versionId } = await drafted();
    await ownerOfVersions.query('alter table mandates.versions disable trigger made_once');
    try {
      await ownerOfVersions.setColumn(versionId, 'purpose', 'Anything at all');
    } finally {
      await ownerOfVersions.query('alter table mandates.versions enable trigger made_once');
    }

    await deniedAndHeld(
      () =>
        withSignedStates(app, org, services(), (tx, states) =>
          mandatesPage(tx, states, org, { after: null, limit: 10 }),
        ),
      { id: versionId, subjectType: 'mandate_version', sign: 'seal' },
    );
  });

  it('a draft made ACTIVE past the app: denied, and held', async () => {
    const { id, versionId } = await drafted();
    await owner.query(
      "update mandates.mandates set status = 'ACTIVE', current_version_id = $2, pending_version_id = null, accepted_by = $3, accepted_at = now() where id = $1",
      [id, versionId, ids.next()],
    );

    await deniedAndHeld(() => read(id), { id, subjectType: 'mandate', sign: 'seal' });
  });

  it('a draft made REVOKED past the app, hiding it from the open-mandate query: its read denied, and held', async () => {
    const { id } = await drafted();
    await owner.query("update mandates.mandates set status = 'REVOKED' where id = $1", [id]);

    expect(await openOf()).toEqual({ outcome: 'missing' });
    await deniedAndHeld(() => read(id), { id, subjectType: 'mandate', sign: 'seal' });
  });
});
