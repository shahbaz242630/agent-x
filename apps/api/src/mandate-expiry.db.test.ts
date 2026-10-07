// Phase 2 B4: mandates ended by the clock, on the real migrated schema as the
// app role: an ACTIVE or SUSPENDED mandate whose version in force has reached
// its end EXPIRED by the job, as the API's, every admin and approver told;
// one not yet ended, with no end, waiting for acceptance or ended already left
// as it is; a run again moving nothing; a tampered mandate refused and
// logged while the others are expired; and a stopped run.
import { withSignedStates } from '@agentx/core/modules/audit';
import { mandateOf, MANDATES } from '@agentx/core/modules/mandates';
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
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createMandateExpiry, type MandateExpiry } from './mandate-expiry.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, mandateWorld, type MandateWorldTables, OPERATOR, type World } from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xb4e0_0000_0000);
const HOUR = 3_600_000;

let clock: FixedClock;
let capture: LogCapture;
let registry: MandateRegistry;
let expiry: MandateExpiry;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'mandate-expiry' });
const { world, eventsAbout, noticesOf, acceptedPastTheUseCase, quiet } = shared;

/** A mandate drafted for the world's agent, ending at `endsAt`, and accepted unless `waiting`. */
async function mandate(w: World, endsAt: Date | null, waiting = false): Promise<string> {
  const { id } = await shared.drafted(registry, w, { endsAt });
  if (!waiting) await acceptedPastTheUseCase(w, id);
  return id;
}

/** Moves the mandate by `event`, past the use cases. */
const movedPast = (w: World, id: string, event: 'suspend' | 'revoke') =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    states.changeStatus(tx, MANDATES, { orgId: w.org, id }, event, {
      actor: OPERATOR,
      action: `mandate.${event}`,
      details: {},
    }),
  );

const statusOf = async (w: World, id: string) =>
  withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await mandateOf(tx, states, { orgId: w.org, id }, 'share');
    return read.outcome === 'found' ? read.mandate.status : read.outcome;
  });

/** The run's lines of this event about the organisation (every test's organisations share the database). */
const lines = (event: string, w: World) =>
  capture.lines().filter((line) => line.event === event && line.orgId === w.org);

const inAnHour = () => new Date(clock.now().getTime() + HOUR);

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
  expiry = createMandateExpiry({ database: app, keys, ids, clock, outbox: createOutbox({ ids, clock }), logger });
});

describe('mandates ended by the clock (B4)', () => {
  it('expires an ACTIVE mandate once its version in force reaches its end, as the API’s, every admin and approver told', async () => {
    const w = await world();
    const id = await mandate(w, inAnHour());

    await expiry.run();
    expect(await statusOf(w, id)).toBe('ACTIVE');

    clock.advanceBy(HOUR);
    await expiry.run();
    expect(await statusOf(w, id)).toBe('EXPIRED');
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
    const id = await mandate(w, inAnHour());
    await movedPast(w, id, 'suspend');
    clock.advanceBy(HOUR + 1);

    await expiry.run();
    expect(await statusOf(w, id)).toBe('EXPIRED');
  });

  it('leaves one with no end, one waiting for acceptance and one revoked as they are', async () => {
    const forever = await world();
    const noEnd = await mandate(forever, null);
    const waitingWorld = await world();
    const waiting = await mandate(waitingWorld, inAnHour(), true);
    const revokedWorld = await world();
    const revoked = await mandate(revokedWorld, inAnHour());
    await movedPast(revokedWorld, revoked, 'revoke');
    clock.advanceBy(2 * HOUR);

    await expiry.run();
    expect(await statusOf(forever, noEnd)).toBe('ACTIVE');
    expect(await statusOf(waitingWorld, waiting)).toBe('PENDING_ACCEPTANCE');
    expect(await statusOf(revokedWorld, revoked)).toBe('REVOKED');
  });

  it('refuses a mandate tampered with past the app, logged, and still expires the organisation’s others (FX-TAMPER)', async () => {
    const tampered = await world();
    const bad = await mandate(tampered, inAnHour());
    const owner = await tamperAsOwner(database, MANDATES, tampered.org);
    try {
      await owner.withoutStatusGuard(() =>
        owner.query("update mandates.mandates set status = 'SUSPENDED' where id = $1", [bad]),
      );
    } finally {
      await owner.end();
    }
    const fine = await world();
    const good = await mandate(fine, inAnHour());
    clock.advanceBy(HOUR);

    await expiry.run();
    expect(lines('mandate_expiry.failed', tampered)).toEqual([expect.objectContaining({ mandateId: bad })]);
    expect(await statusOf(fine, good)).toBe('EXPIRED');
  });

  it('a run stopped expires nothing more', async () => {
    const w = await world();
    const id = await mandate(w, inAnHour());
    clock.advanceBy(HOUR);
    const stopping = new AbortController();
    stopping.abort();

    await expiry.run(stopping.signal);
    expect(await statusOf(w, id)).toBe('ACTIVE');
  });
});
