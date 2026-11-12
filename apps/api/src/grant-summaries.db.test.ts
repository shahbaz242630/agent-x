// The grant summaries' job (OR1; grant-summaries.ts), on the real migrated
// schema as the app role: each organisation's memberships from before 0085
// get their summaries built and sealed, an organisation found whole is not
// visited again, and a failure is logged, naming the organisation, while the
// run goes on to the next.
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import { type DirectoryTables, registerMember } from '@agentx/core/modules/directory';
import {
  addMembership,
  type IdentityTables,
  MEMBERSHIPS,
  type MembershipsTransaction,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createDatabase, type Database } from '@agentx/platform/db';
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

import { createGrantSummaryBuilding } from './grant-summaries.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb200_0000_0000);
const clock = new FixedClock(new Date('2026-10-01T09:00:00Z'));
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

let capture: LogCapture;
let subjects = 0;
const quiet = () => ({ keys, ids, logger: testLogger(new LogCapture()) });
const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** An organisation with one member from before 0085 (no summary) and one added since (with one). */
async function organisation(): Promise<{ readonly org: string; readonly before: string }> {
  const org = ids.next();
  const before = ids.next();
  const person = async () => {
    subjects += 1;
    return userForSubject(
      app,
      { issuer: 'https://auth.example.test', subject: `job-${String(subjects)}` },
      { ids, clock },
    );
  };
  const [first, second] = [await person(), await person()];
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  await withSignedStates(app, org, quiet(), async (tx: MembershipsTransaction, states) => {
    await registerMember(tx, { orgId: org, userId: first, membershipId: before });
    const fields = { user_id: first, role: 'admin', status: 'ACTIVE', joined_at: clock.now() };
    await tx
      .insertInto('identity.memberships')
      .values({ org_id: org, id: before, ...fields })
      .execute();
    await states.record(tx, MEMBERSHIPS, { orgId: org, id: before }, 'new', fields, {
      actor: OPERATOR,
      action: 'membership.created',
      details: { role: 'admin' },
    });
    await addMembership(tx, states, {
      orgId: org,
      id: ids.next(),
      userId: second,
      role: 'viewer',
      joinedAt: clock.now(),
      actor: { type: 'user', id: first },
    });
  });
  return { org, before };
}

const summaries = async (org: string) =>
  database
    .as('backup')
    .query<{ id: string }>('select id from identity.membership_grants where org_id = $1 order by id', [org]);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe(`the grant summaries' job (OR1, Postgres ${server.version})`, () => {
  it('builds each listed organisation’s missing summaries, once, and goes on past one that fails', async () => {
    const one = await organisation();
    const two = await organisation();
    // An entry no organisation can have: its transaction can't open, so its build fails.
    const gone = 'not-an-organisation';
    let listed = [one.org, gone, two.org];
    const job = createGrantSummaryBuilding({
      list: () => Promise.resolve(listed),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
      page: 2,
    });

    await job.run();

    expect((await summaries(one.org)).map(({ id }) => id)).toContain(one.before);
    expect((await summaries(two.org)).map(({ id }) => id)).toContain(two.before);
    expect(lines('grant_summaries.built')).toEqual([
      expect.objectContaining({ orgId: one.org, built: 1 }),
      expect.objectContaining({ orgId: two.org, built: 1 }),
    ]);
    // Its failure logged, naming it, and the run went on to the next.
    expect(lines('grant_summaries.build_failed')).toEqual([expect.objectContaining({ level: 'error', orgId: gone })]);

    // Both in step now: looked at again, nothing built. (The job's logger is the capture it was made with.)
    const seen = capture.lines().length;
    listed = [one.org, two.org];
    await job.run();
    expect(
      capture
        .lines()
        .slice(seen)
        .filter(({ event }) => String(event).startsWith('grant_summaries.')),
    ).toEqual([]);
  });

  it('brings up to date, on its next run, a summary left behind after the organisation was found whole', async () => {
    const { org, before } = await organisation();
    const job = createGrantSummaryBuilding({
      list: () => Promise.resolve([org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });
    await job.run();
    expect(lines('grant_summaries.built')).toEqual([expect.objectContaining({ built: 1 })]);

    // An image from before OR1 changes the membership, writing no summary: left behind.
    await withSignedStates(app, org, quiet(), async (tx, states) => {
      const state = await states.verifiedState(tx, MEMBERSHIPS, { orgId: org, id: before }, 'change');
      if (state.outcome !== 'verified') throw new Error('not verified');
      await states.record(
        tx,
        MEMBERSHIPS,
        { orgId: org, id: before },
        state,
        { role: 'approver' },
        {
          actor: OPERATOR,
          action: 'membership.role_changed',
          details: { roleFrom: 'admin', roleTo: 'approver' },
        },
      );
    });
    await job.run();

    // The job's logger is the one it was made with: its second run's line after the first.
    expect(lines('grant_summaries.built')).toEqual([
      expect.objectContaining({ orgId: org, built: 1 }),
      expect.objectContaining({ orgId: org, built: 1 }),
    ]);
    const rows = await database
      .as('backup')
      .query<{ membership_version: number }>(
        'select membership_version from identity.membership_grants where org_id = $1 and id = $2',
        [org, before],
      );
    expect(rows).toEqual([{ membership_version: 2 }]);
    expect(lines('audit.integrity_failed')).toEqual([]);
  });

  it('says so when the organisations can’t be listed, and stops when told to', async () => {
    const failing = createGrantSummaryBuilding({
      list: () => Promise.reject(new Error('the directory is down')),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });
    await failing.run();
    expect(lines('grant_summaries.run_failed')).toEqual([expect.objectContaining({ level: 'error' })]);

    const { org, before } = await organisation();
    const stopped = new AbortController();
    stopped.abort();
    await createGrantSummaryBuilding({
      list: () => Promise.resolve([org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    }).run(stopped.signal);
    expect((await summaries(org)).map(({ id }) => id)).not.toContain(before);
  });

  it('leaves an organisation found tampered with to be looked at again, its alarm raised', async () => {
    const { org, before } = await organisation();
    // The summary added since, emptied past the app: the build finds it before building the other.
    await database.as('admin').query(`update identity.membership_grants set granted_by = '' where org_id = $1`, [org]);
    const job = createGrantSummaryBuilding({
      list: () => Promise.resolve([org]),
      database: app,
      keys,
      ids,
      logger: testLogger(capture),
    });

    await job.run();
    await job.run();

    expect(lines('audit.integrity_failed').length).toBeGreaterThanOrEqual(2);
    expect((await summaries(org)).map(({ id }) => id)).not.toContain(before);
    expect(lines('grant_summaries.built')).toEqual([]);
  });
});
