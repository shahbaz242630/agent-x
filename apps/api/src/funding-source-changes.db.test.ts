// D2-4a (BR-01, BR-02, SEC-PTR-08, SEC-AG-05): reading the organisation's
// funding sources and refreshing one from the partner, through the use cases
// the routes call, on the real migrated schema, as the app role, with the
// fake partner over its own records in the same database, as staging runs
// it. Each source is linked as D2-3 links it: started, approved at the fake
// bank, confirmed. The routes' answers are funding-sources.test.ts.
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type FundingSourcesTables, SOURCES, type SourceRecord } from '@agentx/core/modules/funding-sources';
import {
  addMembership,
  createStepUpChallenges,
  type IdentityTables,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  createDatabaseRecords,
  createFakeRail,
  type FakePartnerTables,
  type FakeRail,
  type FinancialRailAdapter,
  USUAL_CONTROLS,
} from '@agentx/core/modules/providers';
import { DAY_MS } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createFundingSourceChanges,
  type FundingSourceChanges,
  REFRESH_OPERATION,
  type SourceChangeWrite,
} from './funding-source-changes.ts';
import {
  createFundingSourceLinks,
  type FundingSourceLinks,
  LINK_CONFIRM_OPERATION,
  LINK_START_OPERATION,
  type LinkingMember,
} from './funding-source-links.ts';
import { createFundingSourceReads, type FundingSourceReads } from './funding-source-reads.ts';

type Tables = IdentityTables &
  FundingSourcesTables &
  FakePartnerTables &
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
const ids = new SequentialIds(0xd24a_0000_0000);
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';
const FIRST_PAGE = { after: null, limit: 50 };

let clock: FixedClock;
let rail: FakeRail;
let links: FundingSourceLinks;
let reads: FundingSourceReads;
let changes: FundingSourceChanges;

let people = 0;

/** A person with a membership in the organisation. */
async function member(org: string, role: Role): Promise<LinkingMember> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `funding-changes-${String(people)}` },
    { ids, clock },
  );
  await withSignedStates(app, org, { keys, ids, logger: testLogger() }, (tx, states) =>
    addMembership(tx, states, { orgId: org, id: ids.next(), userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: testLogger() }, (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

let keysUsed = 0;
/** A fresh idempotency key for each write. */
const nextKey = () => {
  keysUsed += 1;
  return `key-${String(keysUsed)}`;
};
const keyed = (who: LinkingMember, operation: string, key = nextKey()): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload: '{}',
});

/** A source linked as D2-3 links it, through the use case and the fake bank: it and the consent the bank gave. */
async function linked(admin: LinkingMember, accountId = ACCOUNT) {
  const started = await links.start(admin, keyed(admin, LINK_START_OPERATION), CORRELATION);
  if (started.outcome !== 'started') throw new Error(`not started: ${JSON.stringify(started)}`);
  const consentId = await rail.bank.approve(admin.orgId, started.link.sessionRef, accountId);
  const confirmed = await links.confirm(admin, keyed(admin, LINK_CONFIRM_OPERATION), started.link.id, CORRELATION);
  if (confirmed.outcome !== 'confirmed' || confirmed.source === null) {
    throw new Error(`not linked: ${JSON.stringify(confirmed)}`);
  }
  return { source: confirmed.source, consentId };
}

const refresh = (who: LinkingMember, sourceId: string, key?: string) =>
  changes.refresh(who, keyed(who, REFRESH_OPERATION, key), sourceId, CORRELATION);

const refreshed = (write: SourceChangeWrite): SourceRecord => {
  if (write.outcome !== 'changed') throw new Error(`not changed: ${JSON.stringify(write)}`);
  return write.source;
};

const events = (org: string, sourceId: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_type', 'actor_id'])
      .where('subject_type', '=', 'funding_source')
      .where('subject_id', '=', sourceId)
      .orderBy('seq')
      .execute(),
  );

const changesWith = (partner: FinancialRailAdapter | undefined) =>
  createFundingSourceChanges({
    database: app,
    keys,
    ids,
    rail: partner,
    challenges: createStepUpChallenges({ ids, clock }),
    logger: testLogger(),
  });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
  rail = createFakeRail({ clock, ids, records: createDatabaseRecords(app) });
  const services = { database: app, keys, ids, logger: testLogger() };
  links = createFundingSourceLinks({ ...services, clock, rail, partner: 'fake' });
  reads = createFundingSourceReads({ ...services, clock });
  changes = changesWith(rail);
});

describe(`refreshing a source from the partner (D2-4a, Postgres ${server.version})`, () => {
  it('records the bank’s suspension and its return, as the admin’s, each once', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source, consentId } = await linked(admin);

    expect(refreshed(await refresh(admin, source.id))).toEqual(source);
    clock.advanceBy(60_000);
    await rail.bank.changeConsent(org, consentId, 'Suspended');
    const suspended = refreshed(await refresh(admin, source.id));
    clock.advanceBy(60_000);
    await rail.bank.changeConsent(org, consentId, 'Authorized');
    const back = refreshed(await refresh(admin, source.id));

    expect(suspended).toMatchObject({ status: 'ACTIVE', availability: 'SUSPENDED', consentStatus: 'Suspended' });
    expect(back).toMatchObject({ status: 'ACTIVE', availability: 'ACTIVE', consentStatus: 'Authorized' });
    expect(await events(org, source.id)).toEqual([
      expect.objectContaining({ action: 'funding_source.linked' }),
      { action: 'funding_source.partner_changed', actor_type: 'user', actor_id: admin.userId },
      { action: 'funding_source.partner_changed', actor_type: 'user', actor_id: admin.userId },
    ]);
  });

  it('ends a source whose consent the bank revoked, for good: a later refresh asks nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source, consentId } = await linked(admin);
    await rail.bank.changeConsent(org, consentId, 'Revoked');

    expect(refreshed(await refresh(admin, source.id))).toMatchObject({ status: 'ENDED', availability: 'UNAVAILABLE' });
    rail.bank.goDown();
    expect(refreshed(await refresh(admin, source.id))).toMatchObject({ status: 'ENDED' });
  });

  it('ends a source the partner no longer knows', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source } = await linked(admin);
    const forgetful: FinancialRailAdapter = { ...rail, getSourceState: () => Promise.resolve({ kind: 'not_found' }) };

    expect(
      refreshed(await changesWith(forgetful).refresh(admin, keyed(admin, REFRESH_OPERATION), source.id, CORRELATION)),
    ).toMatchObject({
      status: 'ENDED',
      availability: 'ACTIVE',
    });
    expect((await events(org, source.id)).map((event) => event.action)).toEqual([
      'funding_source.linked',
      'funding_source.ended',
    ]);
  });

  it('answers a source ended while the partner was asked as it stands, recording nothing more', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source, consentId } = await linked(admin);
    const forgetful: FinancialRailAdapter = { ...rail, getSourceState: () => Promise.resolve({ kind: 'not_found' }) };
    // Another admin's refresh ends the source between this refresh's first read and its write.
    const endingMeanwhile: FinancialRailAdapter = {
      ...rail,
      getSourceState: async (ref) => {
        const other = await member(org, 'admin');
        await changesWith(forgetful).refresh(other, keyed(other, REFRESH_OPERATION), source.id, CORRELATION);
        clock.advanceBy(60_000);
        await rail.bank.changeConsent(org, consentId, 'Suspended');
        return rail.getSourceState(ref);
      },
    };

    const answered = refreshed(
      await changesWith(endingMeanwhile).refresh(admin, keyed(admin, REFRESH_OPERATION), source.id, CORRELATION),
    );

    expect(answered).toMatchObject({ status: 'ENDED', availability: 'ACTIVE', consentStatus: 'Authorized' });
    expect((await events(org, source.id)).map((event) => event.action)).toEqual([
      'funding_source.linked',
      'funding_source.ended',
    ]);
  });

  it.each([
    {
      about: 'another source',
      mixUp: async (admin: LinkingMember): Promise<FinancialRailAdapter> => {
        const { source: other } = await linked(admin, 'sme-trading-business-acct-01');
        return { ...rail, getSourceState: (ref) => rail.getSourceState({ ...ref, externalRef: other.externalRef }) };
      },
    },
    {
      about: 'another organisation',
      // This source's own reference, answered as another real organisation's.
      mixUp: async (): Promise<FinancialRailAdapter> => {
        const stranger = await organization();
        return {
          ...rail,
          getSourceState: async (ref) => {
            const answer = await rail.getSourceState(ref);
            return answer.kind === 'found'
              ? { ...answer, source: { ...answer.source, organizationId: stranger } }
              : answer;
          },
        };
      },
    },
  ])('believes nothing of an answer about $about, answering 503 and logging the partner’s fault', async ({ mixUp }) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source } = await linked(admin);
    const mixedUp = await mixUp(admin);
    const capture = new LogCapture();
    const confused = createFundingSourceChanges({
      database: app,
      keys,
      ids,
      rail: mixedUp,
      challenges: createStepUpChallenges({ ids, clock }),
      logger: testLogger(capture),
    });

    expect(await confused.refresh(admin, keyed(admin, REFRESH_OPERATION), source.id, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });
    expect(await events(org, source.id)).toHaveLength(1);
    expect(capture.lines().filter((line) => line.event === 'funding_sources.partner_answer_mismatch')).toEqual([
      expect.objectContaining({ level: 'error', orgId: org, correlationId: CORRELATION, sourceId: source.id }),
    ]);
  });

  it('suspends a source whose limits the bank now answers in another currency than its account’s, recording none of it (the S68 audit)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source } = await linked(admin);
    // The bank renews the consent with limits in dollars on the dirham account.
    await rail.bank.renew(org, source.externalRef, { ...USUAL_CONTROLS, currency: 'USD' });
    const capture = new LogCapture();
    const changes = createFundingSourceChanges({
      database: app,
      keys,
      ids,
      rail,
      challenges: createStepUpChallenges({ ids, clock }),
      logger: testLogger(capture),
    });

    const answered = refreshed(await changes.refresh(admin, keyed(admin, REFRESH_OPERATION), source.id, CORRELATION));

    // Suspended by Agent X, the limits kept as they were: an admin reactivates it with a passkey once put right.
    expect(answered).toMatchObject({ status: 'SUSPENDED', controls: source.controls });
    const recorded = await events(org, source.id);
    expect(recorded).toHaveLength(2);
    expect(recorded.at(-1)).toMatchObject({ action: 'funding_source.suspended', actor_id: 'api' });
    expect(capture.lines().filter((line) => line.event === 'funding_sources.currency_mismatch')).toEqual([
      expect.objectContaining({ level: 'error', orgId: org, sourceId: source.id }),
    ]);
    // Refreshed again while it stays wrong: already stopped, and answered as it is.
    expect(
      refreshed(await changes.refresh(admin, keyed(admin, REFRESH_OPERATION), source.id, CORRELATION)),
    ).toMatchObject({
      status: 'SUSPENDED',
    });
    expect(await events(org, source.id)).toHaveLength(2);
  });

  it('answers a retry of the same write as the first did', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source, consentId } = await linked(admin);
    await rail.bank.changeConsent(org, consentId, 'Suspended');
    const first = refreshed(await refresh(admin, source.id, 'same'));

    expect(refreshed(await refresh(admin, source.id, 'same'))).toEqual(first);
    expect(await events(org, source.id)).toHaveLength(2);
  });

  it('answers 503 PARTNER_UNAVAILABLE when the partner doesn’t answer or none is set up, changing nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source } = await linked(admin);
    rail.bank.goDown();
    const unavailable = { outcome: 'refused', status: 503, code: 'PARTNER_UNAVAILABLE' };

    expect(await refresh(admin, source.id)).toEqual(unavailable);
    expect(
      await changesWith(undefined).refresh(admin, keyed(admin, REFRESH_OPERATION), source.id, CORRELATION),
    ).toEqual(unavailable);
    expect(await events(org, source.id)).toHaveLength(1);
  });

  it('refuses anyone but an admin, changing nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { source, consentId } = await linked(admin);
    await rail.bank.changeConsent(org, consentId, 'Suspended');
    for (const role of ['approver', 'developer', 'viewer'] as const) {
      expect(await refresh(await member(org, role), source.id)).toEqual({
        outcome: 'refused',
        status: 403,
        code: 'FORBIDDEN',
      });
    }
    expect(await events(org, source.id)).toHaveLength(1);
  });

  it('finds another organisation’s source as none, and asks the partner nothing of it (SEC-PTR-08)', async () => {
    const org = await organization();
    const { source } = await linked(await member(org, 'admin'));
    const other = await organization();
    const outsider = await member(other, 'admin');
    let asked = 0;
    const counting: FinancialRailAdapter = {
      ...rail,
      getSourceState: (ref) => {
        asked += 1;
        return rail.getSourceState(ref);
      },
    };

    expect(
      await changesWith(counting).refresh(outsider, keyed(outsider, REFRESH_OPERATION), source.id, CORRELATION),
    ).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect(asked).toBe(0);
  });
});

describe(`reading the organisation’s sources (D2-4a, Postgres ${server.version})`, () => {
  it('lists every source to its members, an ended one too, and none of another organisation’s', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = await linked(admin);
    const second = await linked(admin, 'sme-trading-business-acct-01');
    await rail.bank.changeConsent(org, second.consentId, 'Revoked');
    const ended = refreshed(await refresh(admin, second.source.id));
    await linked(await member(await organization(), 'admin'));

    expect(await reads.list(org, FIRST_PAGE, CORRELATION)).toEqual({
      outcome: 'listed',
      sources: [first.source, ended],
      next: null,
    });
    expect(await reads.show(org, ended.id, CORRELATION)).toEqual({ outcome: 'found', source: ended });
  });

  it('shows another organisation’s source as none', async () => {
    const org = await organization();
    const { source } = await linked(await member(org, 'admin'));

    expect(await reads.show(await organization(), source.id, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 404,
      code: 'NOT_FOUND',
    });
  });

  it('refuses every read and a refresh, 503 INTEGRITY_FAILED, once a source is tampered with (FX-TAMPER)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    await linked(admin);
    const { source } = await linked(admin, 'sme-trading-business-acct-01');
    const owner = await tamperAsOwner(database, SOURCES, org);
    try {
      await owner.setColumn(source.id, 'availability', 'ACTIVE');
      await owner.setColumn(source.id, 'max_payment_minor', '999999999999');
    } finally {
      await owner.end();
    }
    const withheld = { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };

    expect(await reads.list(org, FIRST_PAGE, CORRELATION)).toEqual(withheld);
    expect(await reads.usableByAgent(org, FIRST_PAGE, CORRELATION)).toEqual(withheld);
    expect(await reads.show(org, source.id, CORRELATION)).toEqual(withheld);
    expect(await refresh(admin, source.id)).toEqual(withheld);
  });

  it('gives an agent only the sources that may fund a request now (SEC-AG-05)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const usable = await linked(admin);
    const atTheBank = await linked(admin, 'sme-trading-business-acct-01');
    await rail.bank.changeConsent(org, atTheBank.consentId, 'Suspended');
    clock.advanceBy(60_000);
    await refresh(admin, atTheBank.source.id);

    expect(await reads.usableByAgent(org, FIRST_PAGE, CORRELATION)).toEqual({
      outcome: 'listed',
      sources: [usable.source],
      next: null,
    });
    // Past the consent's expiry, none may fund one.
    clock.advanceBy(366 * DAY_MS);
    expect(await reads.usableByAgent(org, FIRST_PAGE, CORRELATION)).toEqual({
      outcome: 'listed',
      sources: [],
      next: null,
    });
  });
});
