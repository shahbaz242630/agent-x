// The integrity hold as its admin sees and investigates it (B3+-2b-2): only
// the organisation's admin, read again inside the transaction; recording only
// while the hold is HELD, its idempotency key claimed first, and a replay
// answered from the investigation's own event. What the hold and an
// investigation are is the audit module's (hold-investigation.db.test.ts).
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { Role } from '../domain/membership.ts';
import {
  createHoldInvestigations,
  type HoldAdmin,
  type HoldInvestigations,
  INVESTIGATE_OPERATION,
} from './hold-investigations.ts';
import { addMembership, MEMBERSHIPS } from './memberships.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xe100_0000_0000);
const clock = new FixedClock(new Date('2026-09-26T09:00:00Z'));
let investigations: HoldInvestigations;

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000bb';
const FINDING = { conclusion: 'CAUSE_REMOVED', reference: 'INC-2026-7' } as const;

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
const services = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });

let people = 0;

/** A person in the organisation with this role: who they are, and their membership. */
async function member(org: string, role: Role): Promise<HoldAdmin & { membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `holding-${String(people)}` },
    { ids, clock },
  );
  const membershipId = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, membershipId };
}

let org: string;
let admin: HoldAdmin & { membershipId: string };

/** Puts the organisation on hold: another member's role changed past the app, then read. */
async function putOnHold(): Promise<void> {
  const other = await member(org, 'viewer');
  const owner = await tamperAsOwner(database, MEMBERSHIPS, org);
  try {
    await owner.setColumn(other.membershipId, 'role', 'admin');
  } finally {
    await owner.end();
  }
  await withSignedStates(app, org, services(), (tx, states) =>
    states.verifiedState(tx, MEMBERSHIPS, { orgId: org, id: other.membershipId }, 'share'),
  );
}

/** Runs `work` as the database's owner, inside the organisation. */
async function asOwner(work: (owner: OwnerTamper) => Promise<unknown>): Promise<void> {
  const owner = await tamperAsOwner(database, MEMBERSHIPS, org);
  try {
    await work(owner);
  } finally {
    await owner.end();
  }
}

/** The hold's own events stripped of their seals: no state for it can be believed. */
const stripTheHold = () =>
  asOwner((owner) =>
    owner.query("update audit.events set details = '{}' where org_id = $1 and subject_type = 'integrity_hold'", [org]),
  );

const keyed = (who: HoldAdmin, key: string, payload = JSON.stringify(FINDING)): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation: INVESTIGATE_OPERATION,
  key,
  payload,
});

const record = (
  who: HoldAdmin = admin,
  key = 'investigate-1',
  finding: typeof FINDING | { conclusion: 'NO_TAMPERING'; reference: string } = FINDING,
) => investigations.record(who, keyed(who, key, JSON.stringify(finding)), finding, CORRELATION);

/** How many investigation events the organisation's log holds, read in its own transaction. */
const investigationEvents = async (): Promise<number> => {
  const rows = await withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select('id')
      .where('org_id', '=', org)
      .where('subject_type', '=', 'hold_investigation')
      .execute(),
  );
  return rows.length;
};

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
  investigations = createHoldInvestigations({ database: app, keys, ids, logger: loggerFor(new LogCapture()) });
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  org = ids.next();
  await withSignedStates(app, org, services(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  admin = await member(org, 'admin');
});

describe(`showing the hold to the organisation's admin (Postgres ${server.version})`, () => {
  it('shows it CLEAR, then HELD once tampering is found', async () => {
    expect(await investigations.show(admin, CORRELATION)).toMatchObject({
      outcome: 'shown',
      hold: { outcome: 'clear', version: 1 },
    });

    await putOnHold();

    expect(await investigations.show(admin, CORRELATION)).toMatchObject({
      outcome: 'shown',
      hold: { outcome: 'held', version: 2, reason: 'seal', foundOn: 'membership' },
    });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s', async (role) => {
    const someone = await member(org, role);

    expect(await investigations.show(someone, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it('refuses an admin since deactivated', async () => {
    await withSignedStates(app, org, services(), (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: admin.membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );

    expect(await investigations.show(admin, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
    await putOnHold();
    expect(await record()).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
  });

  it('refuses someone who is no member at all', async () => {
    expect(await investigations.show({ orgId: org, userId: ids.next() }, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  it("refuses a hold that can't be believed as INTEGRITY_FAILED", async () => {
    await stripTheHold();

    expect(await investigations.show(admin, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });

  it("refuses when the admin's own membership can't be believed, as INTEGRITY_FAILED", async () => {
    const owner = await tamperAsOwner(database, MEMBERSHIPS, org);
    try {
      await owner.setColumn(admin.membershipId, 'role', 'viewer');
    } finally {
      await owner.end();
    }

    expect(await investigations.show(admin, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'INTEGRITY_FAILED',
    });
  });
});

describe(`recording the investigation (Postgres ${server.version})`, () => {
  it('records it for the admin while the hold is HELD: 201 with the investigation', async () => {
    await putOnHold();

    const written = await record();

    expect(written).toEqual({
      outcome: 'written',
      status: 201,
      investigation: {
        id: expect.any(String) as string,
        holdVersion: 2,
        holdEventId: expect.any(String) as string,
        conclusion: 'CAUSE_REMOVED',
        reference: 'INC-2026-7',
        recordedBy: admin.userId,
        recordedAt: expect.any(Date) as Date,
      },
    });
    expect(await investigationEvents()).toBe(1);
  });

  it('answers a replay of the same request from the investigation itself, recording nothing more', async () => {
    await putOnHold();
    const first = await record();

    expect(await record()).toEqual(first);
    expect(await investigationEvents()).toBe(1);
  });

  it('refuses the same key for another finding, recording nothing more', async () => {
    await putOnHold();
    await record();

    expect(await record(admin, 'investigate-1', { conclusion: 'NO_TAMPERING', reference: 'INC-8' })).toEqual({
      outcome: 'conflict',
    });
    expect(await investigationEvents()).toBe(1);
  });

  it('refuses while the hold is CLEAR as NOT_ON_HOLD, keeping nothing, so the key can be used once it is held', async () => {
    expect(await record()).toEqual({ outcome: 'refused', status: 409, code: 'NOT_ON_HOLD' });
    expect(await investigationEvents()).toBe(0);

    await putOnHold();

    expect(await record()).toMatchObject({ outcome: 'written', status: 201 });
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a %s, recording nothing', async (role) => {
    await putOnHold();
    const someone = await member(org, role);

    expect(await record(someone)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect(await investigationEvents()).toBe(0);
  });

  it("refuses while the hold can't be believed as INTEGRITY_FAILED, recording nothing", async () => {
    await putOnHold();
    await stripTheHold();

    expect(await record()).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(await investigationEvents()).toBe(0);
  });

  it('answers a replay as INTEGRITY_FAILED once the investigation it names has been changed past the app', async () => {
    await putOnHold();
    await record();
    await asOwner((owner) =>
      owner.query(
        "update audit.events set details = replace(details, 'INC-2026-7', 'INC-2026-8') where org_id = $1 and subject_type = 'hold_investigation'",
        [org],
      ),
    );

    expect(await record()).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
  });

  it("refuses when the admin's own membership can't be believed, recording nothing", async () => {
    await putOnHold();
    const owner = await tamperAsOwner(database, MEMBERSHIPS, org);
    try {
      await owner.setColumn(admin.membershipId, 'role', 'viewer');
    } finally {
      await owner.end();
    }

    expect(await record()).toEqual({ outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' });
    expect(await investigationEvents()).toBe(0);
  });
});
