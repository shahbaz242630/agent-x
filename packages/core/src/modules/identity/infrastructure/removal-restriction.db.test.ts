// B6-3d (SEC-OPS-04): whether a person is in the 7 days without an admin's or
// approver's powers after a second factor was removed, on the real migrated
// schema, as the app role, read from what the copier (B6-2b, with a stand-in
// for the login service's feed) and the reset job (reset-removals.ts) record
// on the platform chain: a removal by someone else or by the login service
// counts, in an organisation or before joining one; one the person made
// themselves doesn't, nor any other change to their sign-in, nor anyone
// else's removal.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, FixedClock, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import { classOfIdpEvent } from '../domain/idp-event.ts';
import { createIdpEventCopier } from './idp-copier.ts';
import type { IdpEvent } from './idp-feed.ts';
import { addMembership } from './memberships.ts';
import { createRemovalRestriction, lastCountedRemoval, SECOND_FACTORS_REMOVED } from './removal-restriction.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables &
  OrganizationsTables &
  DirectoryTables &
  AuditTables &
  NotificationsTables &
  PlatformControlsTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xb63d_0000_0000);
const ISSUER = 'https://auth.example.test';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
let clock: FixedClock;

const logger = () => testLogger();

let subjects = 0;

/** A person who has signed in to Agent X, as the login service's subject: digits, as Zitadel's IDs. */
async function person(): Promise<{ userId: string; subject: string }> {
  subjects += 1;
  const subject = String(313_000_000_000_000_000n + BigInt(subjects));
  return { userId: await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock }), subject };
}

/** A new organisation with the person as an admin. */
async function adminOfNewOrganization(userId: string): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: logger() }, async (tx, states) => {
    await createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR });
    await addMembership(tx, states, {
      orgId: org,
      id: ids.next(),
      userId,
      role: 'admin',
      joinedAt: clock.now(),
      actor: OPERATOR,
    });
  });
  return org;
}

let sequence = 0;

/** An event of the login service's about the subject, at the time given, by someone else unless told. */
function event(
  type: string,
  subject: string,
  createdAt: Date,
  editorUserId: string | null = '313000000000009999',
): IdpEvent {
  sequence += 1;
  const eventClass = classOfIdpEvent(type);
  if (eventClass === undefined) throw new Error(`not a type we copy: ${type}`);
  return {
    type,
    eventClass,
    aggregateType: 'user',
    aggregateId: subject,
    sequence: String(sequence),
    createdAt,
    editorUserId,
  };
}

/** Copies the events, as the API's job does, the clock then moved on past them. */
async function copied(...events: IdpEvent[]): Promise<void> {
  const copier = createIdpEventCopier({
    database: app,
    feed: {
      eventsBetween: (since, until, most) =>
        Promise.resolve(
          events
            .filter((each) => each.createdAt > since && each.createdAt < until)
            .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
            .slice(0, most),
        ),
    },
    keys,
    ids,
    clock,
    issuer: ISSUER,
    outbox: createOutbox({ ids, clock }),
    logger: logger(),
  });
  await copier.run();
}

/** Some minutes before the test's time: the copier reads up to a minute ago. */
const minutesAgo = (count: number): Date => new Date(clock.now().getTime() - count * 60_000);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 2 }, logger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // Each test later than the last, so the copier's cursor reads each test's events.
  clock = new FixedClock(new Date(Date.UTC(2026, 8, 28, 10) + sequence * 3_600_000));
});

describe(`the restriction after a second factor is removed, read from the platform chain (B6-3d, Postgres ${server.version})`, () => {
  it('SEC-OPS-04 counts a factor someone else removed at the login service, for 7 days from its time, and no longer', async () => {
    const who = await person();
    await adminOfNewOrganization(who.userId);
    const removedAt = minutesAgo(5);

    await copied(event('user.human.mfa.u2f.token.removed', who.subject, removedAt));

    expect(await lastCountedRemoval(app, who.userId)).toEqual(removedAt);
    const until = new Date(removedAt.getTime() + 7 * DAY_MS);
    expect(await createRemovalRestriction({ database: app, clock })(who.userId)).toEqual(until);
    expect(
      await createRemovalRestriction({ database: app, clock: new FixedClock(new Date(until.getTime() - 1)) })(
        who.userId,
      ),
    ).toEqual(until);
    expect(await createRemovalRestriction({ database: app, clock: new FixedClock(until) })(who.userId)).toBeUndefined();
  });

  it('counts a factor the login service removed by itself, and one removed before the person joined any organisation', async () => {
    const bySystem = await person();
    await adminOfNewOrganization(bySystem.userId);
    const beforeJoining = await person();

    await copied(
      event('user.human.passwordless.token.removed', bySystem.subject, minutesAgo(6), null),
      event('user.human.mfa.otp.removed', beforeJoining.subject, minutesAgo(5)),
    );
    await adminOfNewOrganization(beforeJoining.userId);

    expect(await lastCountedRemoval(app, bySystem.userId)).toEqual(minutesAgo(6));
    expect(await lastCountedRemoval(app, beforeJoining.userId)).toEqual(minutesAgo(5));
  });

  it('never counts a factor the person removed themselves, nor any other change to their sign-in', async () => {
    const who = await person();
    await adminOfNewOrganization(who.userId);

    await copied(
      event('user.human.mfa.otp.removed', who.subject, minutesAgo(9), who.subject),
      event('user.human.password.changed', who.subject, minutesAgo(8)),
      event('user.locked', who.subject, minutesAgo(7)),
      event('user.human.email.changed', who.subject, minutesAgo(6)),
    );

    expect(await lastCountedRemoval(app, who.userId)).toBeUndefined();
    expect(await createRemovalRestriction({ database: app, clock })(who.userId)).toBeUndefined();
  });

  it('never counts another person’s removal', async () => {
    const who = await person();
    const other = await person();
    await adminOfNewOrganization(who.userId);
    await adminOfNewOrganization(other.userId);

    await copied(event('user.human.mfa.recoverycode.removed', other.subject, minutesAgo(5)));

    expect(await lastCountedRemoval(app, other.userId)).toEqual(minutesAgo(5));
    expect(await lastCountedRemoval(app, who.userId)).toBeUndefined();
  });

  it('counts the latest removal of either kind: the login service’s, or a reset Agent X carried out', async () => {
    const who = await person();
    const org = await adminOfNewOrganization(who.userId);
    await copied(
      event('user.human.mfa.otp.sms.removed', who.subject, minutesAgo(20)),
      event('user.human.mfa.otp.email.removed', who.subject, minutesAgo(10), who.subject),
    );
    expect(await lastCountedRemoval(app, who.userId)).toEqual(minutesAgo(20));

    const resetAt = minutesAgo(2);
    await createPlatformChain({ keys, ids }).recordAlone(app, {
      actor: { type: 'system', id: 'api' },
      action: SECOND_FACTORS_REMOVED,
      details: { person: who.userId, org, reset: ids.next(), at: resetAt.toISOString() },
    });

    expect(await lastCountedRemoval(app, who.userId)).toEqual(resetAt);
    // By the person's ID in any case.
    expect(await lastCountedRemoval(app, who.userId.toUpperCase())).toEqual(resetAt);
  });
});
