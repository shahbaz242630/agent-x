// Phase 2 B5: an agent's own mandate and the sources it names, on the real
// migrated schema as the app role: the mandate in force (ACTIVE, or
// SUSPENDED) with its version; none for no mandate, a draft, one revoked or
// past its end though the expiry job hasn't reached it, or another agent's;
// the one source of an ACTIVE mandate while it may fund, paged after that
// filter; and a tampered mandate refused (FX-TAMPER).
import { MANDATES } from '@agentx/core/modules/mandates';
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

import { type AgentMandates, createAgentMandates } from './agent-mandate.ts';
import { createMandateRegistry, type MandateRegistry } from './mandate-registry.ts';
import { keys, mandateWorld, type MandateWorldTables, refused, type World } from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xb5a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b5';
const HOUR = 3_600_000;
const FIRST_PAGE = { after: null, limit: 50 };

let clock: FixedClock;
let registry: MandateRegistry;
let mandates: AgentMandates;

const shared = mandateWorld({ app: () => app, clock: () => clock, ids, name: 'agent-mandate' });
const { world, partnerSays, movedPastTheUseCase } = shared;

const inForce = (w: World, endsAt: Date | null = null) => shared.inForce(registry, w, { endsAt });
const shown = (w: World, agentId = w.agent) => mandates.inForce(w.org, agentId, CORRELATION);
const sourceIds = async (w: World, page: { after: string | null; limit: number } = FIRST_PAGE) => {
  const listed = await mandates.sources(w.org, w.agent, page, CORRELATION);
  if (listed.outcome !== 'listed') throw new Error(`not listed: ${JSON.stringify(listed)}`);
  expect(listed.next).toBeNull();
  return listed.sources.map(({ id }) => id);
};
const NONE = refused(404, 'NOT_FOUND');

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
  const logger = testLogger(new LogCapture());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  mandates = createAgentMandates({ database: app, keys, ids, clock, logger });
});

describe('an agent’s own mandate and sources (B5, SEC-AG-05)', () => {
  it('gives the ACTIVE mandate with its version in force, and the source it names', async () => {
    const w = await world();
    const id = await inForce(w);

    expect(await shown(w)).toMatchObject({
      outcome: 'found',
      mandate: { id, status: 'ACTIVE', agentId: w.agent },
      version: { version: 1, fundingSourceId: w.source, supplierIds: [...w.suppliers].sort() },
    });
    expect(await sourceIds(w)).toEqual([w.source]);
    // Paged after the filter: past the one source, nothing.
    expect(await sourceIds(w, { after: w.source, limit: 50 })).toEqual([]);
  });

  it('gives a SUSPENDED mandate, so the agent learns why, and no source while it is', async () => {
    const w = await world();
    const id = await inForce(w);
    await movedPastTheUseCase(w, id, 'suspend');

    expect(await shown(w)).toMatchObject({ outcome: 'found', mandate: { status: 'SUSPENDED' } });
    expect(await sourceIds(w)).toEqual([]);
  });

  it('gives nothing without a mandate, for a draft, or for another agent', async () => {
    const w = await world();
    expect(await shown(w)).toEqual(NONE);
    expect(await sourceIds(w)).toEqual([]);

    await shared.drafted(registry, w);
    expect(await shown(w)).toEqual(NONE);
    expect(await sourceIds(w)).toEqual([]);
    expect(await shown(w, ids.next())).toEqual(NONE);
  });

  it('gives nothing once revoked, or once past its end though the expiry job hasn’t run', async () => {
    const revoked = await world();
    await movedPastTheUseCase(revoked, await inForce(revoked), 'revoke');
    expect(await shown(revoked)).toEqual(NONE);

    const ending = await world();
    await inForce(ending, new Date(clock.now().getTime() + HOUR));
    clock.advanceBy(HOUR);
    expect(await shown(ending)).toEqual(NONE);
    expect(await sourceIds(ending)).toEqual([]);
  });

  it('withholds the source once it can’t fund a request, the mandate still shown', async () => {
    const w = await world();
    await inForce(w);
    await partnerSays(w, { consentExpiresAt: clock.now() });

    expect(await shown(w)).toMatchObject({ outcome: 'found' });
    expect(await sourceIds(w)).toEqual([]);
  });

  it('refuses a mandate tampered with past the app: INTEGRITY_FAILED (FX-TAMPER)', async () => {
    const w = await world();
    const id = await inForce(w);
    const owner = await tamperAsOwner(database, MANDATES, w.org);
    try {
      await owner.withoutStatusGuard(() =>
        owner.query("update mandates.mandates set status = 'SUSPENDED' where id = $1", [id]),
      );
    } finally {
      await owner.end();
    }

    const integrity = refused(503, 'INTEGRITY_FAILED');
    expect(await shown(w)).toEqual(integrity);
    expect(await mandates.sources(w.org, w.agent, FIRST_PAGE, CORRELATION)).toEqual(integrity);
  });
});
