// Phase 2 B4: mandates ended by the clock, on the real migrated schema as the
// app role: an ACTIVE or SUSPENDED mandate whose version in force has reached
// its end EXPIRED by the job, as the API's, every admin and approver told;
// one not yet ended, with no end, waiting for acceptance or ended already left
// as it is; a run again moving nothing; a new version with a later end
// accepted while the job waits for the mandate (forced); a tampered mandate
// refused and logged while the others are expired, even those after it in a
// full page (S90 review); a run's share, the rest left to the next; and a
// stopped run.
import { addAgent } from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import { listedOrganizations } from '@agentx/core/modules/directory';
import { acceptDraft, mandateOf, MANDATES } from '@agentx/core/modules/mandates';
import { createOutbox } from '@agentx/core/modules/notifications';
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateExpiry, type MandateExpiry } from './mandate-expiry.ts';
import { createMandateRegistry, type MandateRegistry, REDRAFT_OPERATION } from './mandate-registry.ts';
import {
  draftedOf,
  keys,
  mandateWorld,
  type MandateWorldTables,
  OPERATOR,
  type World,
} from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xb4e0_0000_0000);
const HOUR = 3_600_000;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let expiry: MandateExpiry;
/** The job, expiring at most `most` of an organisation's mandates a run, a page as long. */
let expiryOf: (most?: number) => MandateExpiry;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'mandate-expiry' });
const { world, eventsAbout, noticesOf, movedPastTheUseCase, quiet, keyed, termsOf } = shared;

/** A mandate in force for the world's agent, ending at `endsAt`. */
const inForce = (w: World, endsAt: Date | null) => shared.inForce(registry, w, { endsAt });

const statusOf = async (w: World, id: string) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await mandateOf(tx, states, { orgId: w.org, id }, 'share');
    return read.outcome === 'found' ? read.mandate : read.outcome;
  });

/** The run's lines of this event about the organisation (every test's organisations share the database). */
const lines = (event: string, w: World) =>
  capture.lines().filter((line) => line.event === event && line.orgId === w.org);

const inHours = (hours: number) => new Date(clock.now().getTime() + hours * HOUR);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-07T08:00:00Z'));
  capture = new LogCapture();
  const logger = testLogger(capture);
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  expiryOf = (most) =>
    createMandateExpiry({
      list: () => listedOrganizations(app),
      database: app,
      keys,
      ids,
      clock,
      outbox: createOutbox({ ids, clock }),
      logger,
      ...(most !== undefined && { most }),
    });
  expiry = expiryOf();
});

/** The mandate SUSPENDED by the table's owner, past the app and its signed state: tampered with. */
const suspendedPastTheApp = async (w: World, id: string): Promise<void> => {
  const owner = await tamperAsOwner(database, MANDATES, w.org);
  try {
    await owner.withoutStatusGuard(() =>
      owner.query("update mandates.mandates set status = 'SUSPENDED' where id = $1", [id]),
    );
  } finally {
    await owner.end();
  }
};

/** The world with another active agent of its organisation, who may hold a mandate of its own. */
const withAnotherAgent = async (w: World): Promise<World> => {
  const agent = ids.next();
  await withSignedStates(app, w.org, quiet(), (tx, states) =>
    addAgent(tx, states, {
      orgId: w.org,
      id: agent,
      name: 'Second agent',
      owner: w.admin.membershipId,
      scopes: ['requests:write'],
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  return { ...w, agent };
};

describe('mandates ended by the clock (B4)', () => {
  it('expires an ACTIVE mandate once its version in force reaches its end, as the API’s, every admin and approver told', async () => {
    const w = await world();
    const id = await inForce(w, inHours(1));

    await expiry.run();
    expect(await statusOf(w, id)).toMatchObject({ status: 'ACTIVE' });

    clock.advanceBy(HOUR);
    await expiry.run();
    expect(await statusOf(w, id)).toMatchObject({ status: 'EXPIRED' });
    expect((await eventsAbout(w.org, id)).at(-1)).toMatchObject({
      action: 'mandate.expired',
      actorType: 'system',
      details: { endsAt: clock.now().toISOString() },
    });
    expect(await noticesOf(w.org)).toEqual([{ kind: 'mandate_expired', about_id: id, recipient_user_id: null }]);
    expect(lines('mandate_expiry.expired', w)).toEqual([expect.objectContaining({ mandateId: id })]);

    await expiry.run();
    expect((await eventsAbout(w.org, id)).filter(({ action }) => action === 'mandate.expired')).toHaveLength(1);
  });

  it('expires a SUSPENDED one too', async () => {
    const w = await world();
    const id = await inForce(w, inHours(1));
    await movedPastTheUseCase(w, id, 'suspend');
    clock.advanceBy(HOUR + 1);

    await expiry.run();
    expect(await statusOf(w, id)).toMatchObject({ status: 'EXPIRED' });
  });

  it('leaves one with no end, one waiting for acceptance and one revoked as they are', async () => {
    const forever = await world();
    const noEnd = await inForce(forever, null);
    const waitingWorld = await world();
    const waiting = await shared.drafted(registry, waitingWorld, { endsAt: inHours(1) });
    const revokedWorld = await world();
    const revoked = await inForce(revokedWorld, inHours(1));
    await movedPastTheUseCase(revokedWorld, revoked, 'revoke');
    clock.advanceBy(2 * HOUR);

    await expiry.run();
    expect(await statusOf(forever, noEnd)).toMatchObject({ status: 'ACTIVE' });
    expect(await statusOf(waitingWorld, waiting.id)).toMatchObject({ status: 'PENDING_ACCEPTANCE' });
    expect(await statusOf(revokedWorld, revoked)).toMatchObject({ status: 'REVOKED' });
  });

  it('leaves one whose new version, with a later end, was accepted while the job waited for it (forced: the mandate held)', async () => {
    const w = await world();
    const id = await inForce(w, inHours(1));
    const later = draftedOf(
      await registry.redraft(
        w.admin,
        keyed(w.admin, REDRAFT_OPERATION),
        id,
        termsOf(w, { endsAt: inHours(3) }),
        'a-correlation',
      ),
    ).pending?.version.id;
    clock.advanceBy(HOUR);
    const { promise: held, resolve: holding } = Promise.withResolvers<undefined>();
    const { promise: gate, resolve: open } = Promise.withResolvers<undefined>();
    // The acceptance holds the mandate for change; the job's search, reading no lock, still finds it past its end.
    const accepting = withSignedStates(app, w.org, quiet(), async (tx, states) => {
      const read = await mandateOf(tx, states, { orgId: w.org, id }, 'change');
      if (read.outcome !== 'found' || later === undefined) throw new Error('no mandate, or no draft waiting');
      holding(undefined);
      await gate;
      await acceptDraft(tx, states, read, {
        orgId: w.org,
        versionId: later,
        acceptedBy: w.admin.membershipId,
        acceptedAt: clock.now(),
        actor: OPERATOR,
        details: {},
      });
    });
    await held;
    const running = within(20_000, expiry.run(), 'the run');
    await waitUntilQueued(database.as('admin'), 1);
    open(undefined);
    await accepting;
    await running;

    expect(await statusOf(w, id)).toMatchObject({ status: 'ACTIVE', currentVersionId: later });
  });

  it('refuses a mandate tampered with past the app, logged, and still expires the other organisations’ (FX-TAMPER)', async () => {
    const tampered = await world();
    const bad = await inForce(tampered, inHours(1));
    await suspendedPastTheApp(tampered, bad);
    const fine = await world();
    const good = await inForce(fine, inHours(1));
    clock.advanceBy(HOUR);

    await expiry.run();
    expect(lines('mandate_expiry.failed', tampered)).toEqual([expect.objectContaining({ mandateId: bad })]);
    expect(await statusOf(fine, good)).toMatchObject({ status: 'EXPIRED' });
  });

  it('pages past a tampered mandate that fills a page, expiring the one after it (S90 review)', async () => {
    const w = await world();
    const bad = await inForce(w, inHours(1));
    const good = await inForce(await withAnotherAgent(w), inHours(1));
    expect(bad < good).toBe(true);
    await suspendedPastTheApp(w, bad);
    clock.advanceBy(HOUR);

    await expiryOf(1).run();
    expect(lines('mandate_expiry.failed', w)).toEqual([expect.objectContaining({ mandateId: bad })]);
    expect(await statusOf(w, good)).toMatchObject({ status: 'EXPIRED' });
  });

  it('pages past a tampered mandate yet never expires more than its share in a run (S90 review)', async () => {
    const w = await world();
    const bad = await inForce(w, inHours(1));
    const good = [];
    for (let i = 0; i < 3; i += 1) good.push(await inForce(await withAnotherAgent(w), inHours(1)));
    await suspendedPastTheApp(w, bad);
    clock.advanceBy(HOUR);

    await expiryOf(2).run();
    const statuses = await Promise.all(good.map(async (id) => ((await statusOf(w, id)) as { status: string }).status));
    expect(statuses).toEqual(['EXPIRED', 'EXPIRED', 'ACTIVE']);
  });

  it('expires its share of an organisation’s mandates a run, the rest the next', async () => {
    const w = await world();
    const first = await inForce(w, inHours(1));
    const second = await inForce(await withAnotherAgent(w), inHours(1));
    clock.advanceBy(HOUR);

    const job = expiryOf(1);
    await job.run();
    expect(await statusOf(w, first)).toMatchObject({ status: 'EXPIRED' });
    expect(await statusOf(w, second)).toMatchObject({ status: 'ACTIVE' });
    await job.run();
    expect(await statusOf(w, second)).toMatchObject({ status: 'EXPIRED' });
  });

  it('a run stopped expires nothing more', async () => {
    const w = await world();
    const id = await inForce(w, inHours(1));
    clock.advanceBy(HOUR);
    const stopping = new AbortController();
    stopping.abort();

    await expiry.run(stopping.signal);
    expect(await statusOf(w, id)).toMatchObject({ status: 'ACTIVE' });
  });
});
