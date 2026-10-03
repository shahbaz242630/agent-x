// D2-4b (BR-01, ADR-012 §5, ADR-014 §8, ADR-003 §8, SEC-HA-12): the
// business's brake on its bank account, and giving it back with an admin's
// passkey step-up, through the use case the routes call, on the real migrated
// schema, as the app role, each source linked as D2-3 links it through the
// fake partner. The routes' answers are funding-sources.test.ts.
import { createHash } from 'node:crypto';

import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type FundingSourcesTables, mayFund, type SourceRecord } from '@agentx/core/modules/funding-sources';
import {
  addMembership,
  createSessions,
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
} from '@agentx/core/modules/providers';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createFundingSourceChanges,
  type FundingSourceChanges,
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  type SessionMember,
  type SourceChangeWrite,
  SUSPEND_OPERATION,
} from './funding-source-changes.ts';
import {
  createFundingSourceLinks,
  type FundingSourceLinks,
  LINK_CONFIRM_OPERATION,
  LINK_START_OPERATION,
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
const ids = new SequentialIds(0xd24b_0000_0000);
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

let clock: FixedClock;
let rail: FakeRail;
let links: FundingSourceLinks;
let reads: FundingSourceReads;
let changes: FundingSourceChanges;
const challenges = () => createStepUpChallenges({ ids, clock });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

let people = 0;

/** A person with a session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<SessionMember & { readonly membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `funding-suspension-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
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
const keyed = (who: SessionMember, operation: string, key = nextKey()): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload: '{}',
});

/** A source linked as D2-3 links it, through the use case and the fake bank. */
async function linked(admin: SessionMember, accountId = ACCOUNT): Promise<SourceRecord> {
  const started = await links.start(admin, keyed(admin, LINK_START_OPERATION), CORRELATION);
  if (started.outcome !== 'started') throw new Error(`not started: ${JSON.stringify(started)}`);
  await rail.bank.approve(admin.orgId, started.link.sessionRef, accountId);
  const confirmed = await links.confirm(admin, keyed(admin, LINK_CONFIRM_OPERATION), started.link.id, CORRELATION);
  if (confirmed.outcome !== 'confirmed' || confirmed.source === null) {
    throw new Error(`not linked: ${JSON.stringify(confirmed)}`);
  }
  return confirmed.source;
}

const suspend = (who: SessionMember, sourceId: string, key?: string) =>
  changes.suspend(who, keyed(who, SUSPEND_OPERATION, key), sourceId, CORRELATION);
const reactivate = (who: SessionMember, sourceId: string) =>
  changes.reactivate(who, keyed(who, REACTIVATE_OPERATION), sourceId, CORRELATION);
const confirm = (who: SessionMember, sourceId: string, challengeId: string) =>
  changes.reactivateConfirm(who, keyed(who, REACTIVATE_CONFIRM_OPERATION), sourceId, challengeId, CORRELATION);

/** The member signs in again for the challenge: its evidence recorded, as the step-up's return does. */
const stepUp = (who: SessionMember, challengeId: string, amr: readonly string[] = PASSKEY) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

const changedOf = (write: SourceChangeWrite): SourceRecord => {
  if (write.outcome !== 'changed') throw new Error(`not changed: ${JSON.stringify(write)}`);
  return write.source;
};

const askedFor = (write: SourceChangeWrite): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

/** The organisation's events about the source, oldest first. */
const eventsAbout = (org: string, sourceId: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_type', 'actor_id', 'details'])
      .where('subject_type', '=', 'funding_source')
      .where('subject_id', '=', sourceId)
      .orderBy('seq')
      .execute(),
  );

const actions = async (org: string, sourceId: string) =>
  (await eventsAbout(org, sourceId)).map((event) => event.action);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
  rail = createFakeRail({ clock, ids, records: createDatabaseRecords(app) });
  const services = { database: app, keys, ids, logger: loggerFor(new LogCapture()) };
  links = createFundingSourceLinks({ ...services, clock, rail, partner: 'fake' });
  reads = createFundingSourceReads({ ...services, clock });
  changes = createFundingSourceChanges({ ...services, rail, challenges: challenges() });
});

describe(`suspending a source: the brake, with no step-up (D2-4b, Postgres ${server.version})`, () => {
  it.each(['admin', 'approver'] as const)('is one write by an %s: SUSPENDED, funding nothing', async (role) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    const who = role === 'admin' ? admin : await member(org, role);

    const suspended = changedOf(await suspend(who, source.id));

    expect(suspended).toMatchObject({ id: source.id, status: 'SUSPENDED', availability: 'ACTIVE' });
    expect(mayFund(suspended, clock.now())).toBe(false);
    expect(await reads.usableByAgent(org, { after: null, limit: 50 }, CORRELATION)).toMatchObject({ sources: [] });
    expect((await eventsAbout(org, source.id)).at(-1)).toMatchObject({
      action: 'funding_source.suspended',
      actor_type: 'user',
      actor_id: who.userId,
    });
  });

  it('pressed twice, or on an ended source, is answered as it is, recording nothing more', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    changedOf(await suspend(admin, source.id));

    expect(changedOf(await suspend(admin, source.id)).status).toBe('SUSPENDED');
    expect(await actions(org, source.id)).toEqual(['funding_source.linked', 'funding_source.suspended']);

    const ended = await linked(admin, 'sme-trading-business-acct-01');
    await rail.bank.changeConsent(org, ended.accountConsentId, 'Revoked');
    changedOf(await changes.refresh(admin, keyed(admin, 'funding-sources.refresh'), ended.id, CORRELATION));
    const recorded = await actions(org, ended.id);

    expect(changedOf(await suspend(admin, ended.id)).status).toBe('ENDED');
    expect(await actions(org, ended.id)).toEqual(recorded);
  });

  it('refuses a developer or a viewer: FORBIDDEN, the source left ACTIVE', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    for (const role of ['developer', 'viewer'] as const) {
      expect(await suspend(await member(org, role), source.id)).toEqual({
        outcome: 'refused',
        status: 403,
        code: 'FORBIDDEN',
      });
    }
    expect(await actions(org, source.id)).toEqual(['funding_source.linked']);
  });

  it('answers NOT_FOUND for another organisation’s source, leaving it ACTIVE', async () => {
    const org = await organization();
    const source = await linked(await member(org, 'admin'));
    const outsider = await member(await organization(), 'admin');

    expect(await suspend(outsider, source.id)).toEqual({ outcome: 'refused', status: 404, code: 'NOT_FOUND' });
    expect(await actions(org, source.id)).toEqual(['funding_source.linked']);
  });

  it('answers a retry of the same write as the first did', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    const first = changedOf(await suspend(admin, source.id, 'same'));

    expect(changedOf(await suspend(admin, source.id, 'same'))).toEqual(first);
    expect(await actions(org, source.id)).toEqual(['funding_source.linked', 'funding_source.suspended']);
  });
});

describe(`reactivating a suspended source, with an admin’s passkey step-up (D2-4b, Postgres ${server.version})`, () => {
  it('asks a step-up, then reactivates it once the admin signed in again with a passkey', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    changedOf(await suspend(admin, source.id));
    const challengeId = askedFor(await reactivate(admin, source.id));
    await stepUp(admin, challengeId);

    const back = changedOf(await confirm(admin, source.id, challengeId));

    expect(back).toMatchObject({ id: source.id, status: 'ACTIVE' });
    expect(mayFund(back, clock.now())).toBe(true);
    const events = await eventsAbout(org, source.id);
    expect(events.map((event) => event.action)).toEqual([
      'funding_source.linked',
      'funding_source.suspended',
      'funding_source.reactivated',
    ]);
    expect(JSON.parse(String(events[2]?.details))).toMatchObject({
      stepUpChallengeId: challengeId,
      methods: PASSKEY.join(' '),
    });
  });

  it('refuses an admin who signed in again without a passkey: STEP_UP_FAILED, the source left SUSPENDED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    changedOf(await suspend(admin, source.id));
    const challengeId = askedFor(await reactivate(admin, source.id));
    await stepUp(admin, challengeId, APP_CODE);

    expect(await confirm(admin, source.id, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect(await actions(org, source.id)).toEqual(['funding_source.linked', 'funding_source.suspended']);
  });

  it('refuses an approver, who may brake but not give back: FORBIDDEN, asking or confirming', async () => {
    const org = await organization();
    const approver = await member(org, 'approver');
    const source = await linked(await member(org, 'admin'));
    changedOf(await suspend(approver, source.id));

    const refused = { outcome: 'refused', status: 403, code: 'FORBIDDEN' };
    expect(await reactivate(approver, source.id)).toEqual(refused);
    expect(await confirm(approver, source.id, ids.next())).toEqual(refused);
  });

  it('refuses a source that isn’t suspended: SOURCE_NOT_SUSPENDED, asking or confirming', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);

    const refused = { outcome: 'refused', status: 409, code: 'SOURCE_NOT_SUSPENDED' };
    expect(await reactivate(admin, source.id)).toEqual(refused);
    expect(await confirm(admin, source.id, ids.next())).toEqual(refused);
  });

  it('answers NOT_FOUND for another organisation’s source, asking or confirming', async () => {
    const org = await organization();
    const theirAdmin = await member(org, 'admin');
    const theirs = await linked(theirAdmin);
    changedOf(await suspend(theirAdmin, theirs.id));
    const admin = await member(await organization(), 'admin');

    const missing = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
    expect(await reactivate(admin, theirs.id)).toEqual(missing);
    expect(await confirm(admin, theirs.id, ids.next())).toEqual(missing);
    expect((await eventsAbout(org, theirs.id)).at(-1)?.action).toBe('funding_source.suspended');
  });

  it('refuses a step-up asked for another source, or before the admin signed in again', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    const other = await linked(admin, 'sme-trading-business-acct-01');
    changedOf(await suspend(admin, source.id));
    changedOf(await suspend(admin, other.id));
    const forOther = askedFor(await reactivate(admin, other.id));
    await stepUp(admin, forOther);
    const notYet = askedFor(await reactivate(admin, source.id));

    expect(await confirm(admin, source.id, forOther)).toMatchObject({ code: 'STEP_UP_FAILED' });
    expect(await confirm(admin, source.id, notYet)).toMatchObject({ code: 'STEP_UP_FAILED' });
  });

  it('refuses a step-up done in another session of the same admin: STEP_UP_FAILED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    changedOf(await suspend(admin, source.id));
    const challengeId = askedFor(await reactivate(admin, source.id));
    await stepUp(admin, challengeId);
    const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
    const { sessionId } = await sessions.open(app, admin.userId, {
      idpSessionId: 'V1_3',
      authTime: clock.now(),
      amr: [...PASSKEY],
    });

    expect(await confirm({ ...admin, sessionId }, source.id, challengeId)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect((await eventsAbout(org, source.id)).at(-1)?.action).toBe('funding_source.suspended');
  });

  it('refuses a step-up asked for an earlier suspension: it reactivates exactly the one it was asked for', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    changedOf(await suspend(admin, source.id));
    const earlier = askedFor(await reactivate(admin, source.id));
    await stepUp(admin, earlier);
    // Reactivated through another step-up, then suspended again: a new suspension.
    const between = askedFor(await reactivate(admin, source.id));
    await stepUp(admin, between);
    changedOf(await confirm(admin, source.id, between));
    changedOf(await suspend(admin, source.id));

    expect(await confirm(admin, source.id, earlier)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'STEP_UP_FAILED',
    });
    expect((await eventsAbout(org, source.id)).at(-1)?.action).toBe('funding_source.suspended');
  });

  it('never reactivates a source the partner ended while it was suspended', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    changedOf(await suspend(admin, source.id));
    const challengeId = askedFor(await reactivate(admin, source.id));
    await stepUp(admin, challengeId);
    await rail.bank.changeConsent(org, source.accountConsentId, 'Revoked');
    changedOf(await changes.refresh(admin, keyed(admin, 'funding-sources.refresh'), source.id, CORRELATION));

    expect(await confirm(admin, source.id, challengeId)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'SOURCE_NOT_SUSPENDED',
    });
    expect((await eventsAbout(org, source.id)).at(-1)?.action).toBe('funding_source.ended');
  });
});

describe(`the confirmation's lock order against the confirmer's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('a reactivation holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const source = await linked(admin);
    changedOf(await suspend(admin, source.id));
    const challengeId = askedFor(await reactivate(admin, source.id));
    await stepUp(admin, challengeId);

    const confirmed = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: org, membershipId: admin.membershipId },
      () => confirm(admin, source.id, challengeId),
    );

    expect(changedOf(confirmed)).toMatchObject({ id: source.id, status: 'ACTIVE' });
  });
});
