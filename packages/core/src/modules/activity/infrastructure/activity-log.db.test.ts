// L3: the activity log (0052) on the real migrated schema, as the app role: an
// organisation's row written inside its own wall and seen by no other, a
// person's row with the organisation they only claimed, nothing written for a
// line malformed, and no row ever changed or deleted by the app.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createTestDatabase, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createActivityLog, type OrganisationRequest, type PersonRequest } from './activity-log.ts';
import type { ActivityTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<ActivityTables>;

const ids = new SequentialIds(0xac71_0000);
const log = createActivityLog({ ids });

const ORG = '0199a0f0-0000-7000-8000-00000000ac01';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000ac02';
const PERSON = '0199a0f0-0000-7000-8000-00000000ac03';
const AGENT = '0199a0f0-0000-7000-8000-00000000ac04';
const AT = new Date('2026-10-18T10:00:00.000Z');

const facts = {
  at: AT,
  method: 'POST',
  route: '/v1/agents/:id/suspend',
  pathIds: [AGENT.toUpperCase()],
  status: 403,
  reason: 'PASSKEY_REQUIRED',
  correlationId: '0199A0F0-0000-7000-8000-00000000AC05',
  durationMs: 12,
} as const;

const forOrganisation = (change: Partial<OrganisationRequest> = {}): OrganisationRequest => ({
  ...facts,
  orgId: ORG,
  actor: { type: 'user', id: PERSON },
  ...change,
});

const forPerson = (change: Partial<PersonRequest> = {}): PersonRequest => ({
  ...facts,
  method: 'GET',
  route: '/v1/profile',
  pathIds: [],
  status: 200,
  reason: undefined,
  userId: PERSON,
  claimedOrg: undefined,
  ...change,
});

const rowsOf = (orgId: string) =>
  withTenant(app, orgId, (tx) => tx.selectFrom('access.requests').selectAll().orderBy('id').execute());
const personRows = () => app.selectFrom('access.person_requests').selectAll().orderBy('id').execute();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<ActivityTables>({ ...database.connection('app'), maxConnections: 2 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the activity log (L3, decision 26, Postgres ${server.version})`, () => {
  it('writes an organisation’s row inside its own wall, IDs in lower case, the clues left for L4', async () => {
    await log.recordForOrganisation(app, forOrganisation());

    expect(await rowsOf(ORG)).toEqual([
      expect.objectContaining({
        org_id: ORG,
        recorded_at: AT,
        actor_type: 'user',
        actor_id: PERSON,
        method: 'POST',
        route: '/v1/agents/:id/suspend',
        path_ids: [AGENT],
        status: 403,
        reason: 'PASSKEY_REQUIRED',
        correlation_id: facts.correlationId.toLowerCase(),
        duration_ms: 12,
        ip: null,
        country: null,
        city: null,
        time_zone: null,
        time_zone_from: null,
      }),
    ]);
    expect(await rowsOf(OTHER_ORG)).toEqual([]);
    // Outside any organisation's transaction, the wall shows nothing.
    expect(await app.selectFrom('access.requests').selectAll().execute()).toEqual([]);
  });

  it('writes an agent’s row, and a success with no reason', async () => {
    await log.recordForOrganisation(
      app,
      forOrganisation({ orgId: OTHER_ORG, actor: { type: 'agent', id: AGENT }, status: 200, reason: undefined }),
    );

    expect(await rowsOf(OTHER_ORG)).toEqual([
      expect.objectContaining({ actor_type: 'agent', actor_id: AGENT, status: 200, reason: null }),
    ]);
  });

  it('writes a person’s row apart, the organisation they only claimed kept as a claim', async () => {
    await log.recordForPerson(app, forPerson());
    await log.recordForPerson(
      app,
      forPerson({ claimedOrg: OTHER_ORG.toUpperCase(), status: 403, reason: 'FORBIDDEN' }),
    );

    expect(await personRows()).toEqual([
      expect.objectContaining({ user_id: PERSON, claimed_org: null, route: '/v1/profile', path_ids: [], reason: null }),
      expect.objectContaining({ user_id: PERSON, claimed_org: OTHER_ORG, status: 403, reason: 'FORBIDDEN' }),
    ]);
    // Never in the organisation it named.
    expect(await rowsOf(OTHER_ORG)).toHaveLength(1);
  });

  it.each([
    ['a time that isn’t one', { at: new Date(Number.NaN) }],
    ['a method no route is served on', { method: 'TRACE' as never }],
    ['a URL rather than a pattern', { route: '/v1/agents?x=1' }],
    ['more than four path IDs', { pathIds: Array.from({ length: 5 }, () => AGENT) }],
    ['a path ID that isn’t a UUID', { pathIds: ['not-an-id'] }],
    ['a status outside HTTP’s', { status: 600 }],
    ['a reason that isn’t a code', { reason: 'passkey required' }],
    ['a correlation ID that isn’t a UUID', { correlationId: 'x' }],
    ['a duration that isn’t whole milliseconds', { durationMs: 1.5 }],
    ['an organisation that isn’t a UUID', { orgId: 'org' }],
    ['an actor that is Agent X itself', { actor: { type: 'system' as never, id: 'api' } }],
    ['an actor that is Agent X, though by a UUID', { actor: { type: 'system' as never, id: PERSON } }],
    ['an actor by something not a UUID', { actor: { type: 'user' as const, id: 'someone' } }],
  ])('writes nothing for %s', async (_what, change) => {
    const before = await rowsOf(ORG);

    await expect(log.recordForOrganisation(app, forOrganisation(change))).rejects.toThrow(RangeError);
    expect(await rowsOf(ORG)).toEqual(before);
  });

  it.each([
    ['a person not by UUID', { userId: 'someone' }],
    ['a claimed organisation not by UUID', { claimedOrg: 'org' }],
  ])('writes no person’s row for %s', async (_what, change) => {
    const before = await personRows();

    await expect(log.recordForPerson(app, forPerson(change))).rejects.toThrow(RangeError);
    expect(await personRows()).toEqual(before);
  });

  it('never lets the app change or delete a row (append-only)', async () => {
    await expect(
      withTenant(app, ORG, (tx) => sql`update access.requests set status = 200`.execute(tx)),
    ).rejects.toThrow(/permission denied/);
    await expect(withTenant(app, ORG, (tx) => sql`delete from access.requests`.execute(tx))).rejects.toThrow(
      /permission denied/,
    );
    await expect(sql`update access.person_requests set status = 200`.execute(app)).rejects.toThrow(/permission denied/);
    await expect(sql`delete from access.person_requests`.execute(app)).rejects.toThrow(/permission denied/);
  });

  it('refuses a row written into another organisation’s wall', async () => {
    await expect(
      withTenant(app, ORG, (tx) =>
        tx
          .insertInto('access.requests')
          .values({
            org_id: OTHER_ORG,
            id: ids.next(),
            recorded_at: AT,
            actor_type: 'user',
            actor_id: PERSON,
            method: 'GET',
            route: '/v1/profile',
            path_ids: [],
            status: 200,
            reason: null,
            correlation_id: ids.next(),
            duration_ms: 1,
            ip: null,
            country: null,
            city: null,
            time_zone: null,
            time_zone_from: null,
          })
          .execute(),
      ),
    ).rejects.toThrow(/row-level security/);
  });
});
