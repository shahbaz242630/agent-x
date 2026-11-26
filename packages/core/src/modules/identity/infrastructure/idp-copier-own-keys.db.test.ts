// SA6 (B6-3d, ADR-012 §8, SEC-OPS-04): the copier exempts from the 7 days' restriction a passkey the person added
// inside Agent X, and only that: exactly that passkey, recorded for that person and that login on the platform chain
// before the key was confirmed and no more than 15 minutes before, its record used once. Every other key counts as
// it always has; a key added still ends the person's sessions.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, FixedClock, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import { classOfIdpEvent, FEED_TYPES } from '../domain/idp-event.ts';
import { OWN_KEY_WINDOW_MS, OWN_PASSKEY_REGISTERED } from '../domain/passkey-addition.ts';
import { createIdpEventCopier, IDP_EVENT_COPIED } from './idp-copier.ts';
import type { SecondFactorsHeld } from './idp-factors.ts';
import { type IdpEvent, type IdpEventFeed, PASSKEY_CONFIRMED_EVENT } from './idp-feed.ts';
import { addMembership } from './memberships.ts';
import { createRemovalRestriction } from './removal-restriction.ts';
import { createSessions } from './sessions.ts';
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
const ids = new SequentialIds(0x5a60_0000_0000);
const ISSUER = 'https://auth.example.test';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const WEEK_MS = 7 * 24 * 60 * 60_000;
let clock: FixedClock;

let counter = 0;
const zitadelId = (): string => {
  counter += 1;
  return String(313_000_000_000_000_000n + BigInt(counter));
};

async function person(): Promise<{ userId: string; subject: string }> {
  const subject = zitadelId();
  const userId = await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock, keys, logger: testLogger() });
  const org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: testLogger() }, async (tx, states) => {
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
  return { userId, subject };
}

let sequence = 0;
/** An event about the subject, made five minutes before the test's time unless told. */
function event(type: string, aggregateId: string, changes: Partial<IdpEvent> = {}): IdpEvent {
  sequence += 1;
  const eventClass = classOfIdpEvent(type);
  if (eventClass === undefined) throw new Error(`not a type we copy: ${type}`);
  return {
    type,
    eventClass,
    aggregateType: 'user',
    aggregateId,
    sequence: String(sequence),
    createdAt: new Date(clock.now().getTime() - 5 * 60_000),
    editorUserId: aggregateId,
    ...changes,
  };
}

const feedOf = (events: readonly IdpEvent[]): IdpEventFeed => ({
  eventsBetween: (since, until, most, part) =>
    Promise.resolve(
      events
        .filter((each) => FEED_TYPES[part].includes(each.type))
        .filter((each) => each.createdAt > since && each.createdAt < until)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
        .slice(0, most),
    ),
});

/** The person holds another key beside the new one: without the exemption, the new key always counts. */
const TWO_KEYS: SecondFactorsHeld = { secondFactorsHeld: () => Promise.resolve({ keys: 2, others: 0 }) };

const copy = (events: readonly IdpEvent[]) =>
  createIdpEventCopier({
    database: app,
    feed: feedOf(events),
    keys,
    ids,
    clock,
    issuer: ISSUER,
    outbox: createOutbox({ ids, clock, keys }),
    factors: TWO_KEYS,
    logger: testLogger(),
  }).run();

/** The person's own addition of a passkey, as passkey-additions.ts records it. */
const recordOwn = (facts: { person: string; subject: string; passkey: string }, at: Date) =>
  createPlatformChain({ keys, ids }).recordAlone(app, {
    actor: { type: 'system', id: 'api' },
    action: OWN_PASSKEY_REGISTERED,
    details: { ...facts, at: at.toISOString() },
  });

const copiesOf = async (subject: string, added: IdpEvent) =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select('details')
      .where('action', '=', IDP_EVENT_COPIED)
      .orderBy('seq')
      .execute()
  )
    .map((row) => JSON.parse(row.details) as Record<string, unknown>)
    .filter((details) => details.event === `user:${subject}:${added.sequence}`);

const restrictedUntil = (userId: string) => createRemovalRestriction({ database: app, clock })(userId);

/** A key confirmed `after` the record, with the passkey ID its payload holds. */
const confirmed = (subject: string, passkeyId: string | undefined, at: Date) =>
  event(PASSKEY_CONFIRMED_EVENT, subject, { createdAt: at, ...(passkeyId === undefined ? {} : { passkeyId }) });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date(Date.UTC(2026, 6, 1 + counter, 9)));
});

describe(`SA6: a passkey added inside Agent X (Postgres ${server.version})`, () => {
  /** A record made `before` ms before the key's confirmation, which is five minutes before the test's time. */
  const recordedBefore = (before: number) => new Date(clock.now().getTime() - 5 * 60_000 - before);

  it('B6-3d exempts the person’s own passkey, recorded before it was confirmed, and says so on the copy', async () => {
    const who = await person();
    const passkey = zitadelId();
    await recordOwn({ person: who.userId, subject: who.subject, passkey }, recordedBefore(60_000));
    const added = confirmed(who.subject, passkey, recordedBefore(0));

    await copy([added]);

    expect(await restrictedUntil(who.userId)).toBeUndefined();
    expect(await copiesOf(who.subject, added)).toEqual([
      expect.objectContaining({ ownPasskey: passkey, signInsEnded: expect.any(Number) as number }),
    ]);
    expect((await copiesOf(who.subject, added))[0]).not.toHaveProperty('counts');
  });

  it('B6-3d still ends the person’s sessions on their own passkey added', async () => {
    const who = await person();
    await createSessions({
      ids,
      clock,
      timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 },
      keys,
      logger: testLogger(),
    }).open(app, who.userId, { idpSessionId: 'V1_1', authTime: clock.now(), amr: ['user', 'mfa'] });
    const passkey = zitadelId();
    await recordOwn({ person: who.userId, subject: who.subject, passkey }, recordedBefore(60_000));

    await copy([confirmed(who.subject, passkey, recordedBefore(0))]);

    expect(await app.selectFrom('identity.sessions').select('id').where('user_id', '=', who.userId).execute()).toEqual(
      [],
    );
  });

  it('B6-3d restricts a key added at the login service directly: no record of it', async () => {
    const who = await person();
    const added = confirmed(who.subject, zitadelId(), recordedBefore(0));

    await copy([added]);

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
    expect(await copiesOf(who.subject, added)).toEqual([expect.objectContaining({ counts: 'yes' })]);
  });

  it('B6-3d restricts a key whose passkey ID is not the one recorded', async () => {
    const who = await person();
    await recordOwn({ person: who.userId, subject: who.subject, passkey: zitadelId() }, recordedBefore(60_000));
    const added = confirmed(who.subject, zitadelId(), recordedBefore(0));

    await copy([added]);

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
  });

  it('B6-3d restricts a key whose payload named no passkey ID (one the feed could not read)', async () => {
    const who = await person();
    await recordOwn({ person: who.userId, subject: who.subject, passkey: zitadelId() }, recordedBefore(60_000));
    const added = confirmed(who.subject, undefined, recordedBefore(0));

    await copy([added]);

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
  });

  it("B6-3d restricts a key recorded as another person's, or for another login", async () => {
    const who = await person();
    const other = await person();
    const passkey = zitadelId();
    // The other person's record of this very passkey ID, and a record of it for another login of this person.
    await recordOwn({ person: other.userId, subject: other.subject, passkey }, recordedBefore(60_000));
    await recordOwn({ person: who.userId, subject: other.subject, passkey }, recordedBefore(60_000));
    await recordOwn({ person: other.userId, subject: who.subject, passkey }, recordedBefore(60_000));
    const added = confirmed(who.subject, passkey, recordedBefore(0));

    await copy([added]);

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
  });

  it.each([
    ['confirmed 15 minutes and 1 ms after the record (run out)', OWN_KEY_WINDOW_MS + 1, true],
    ['confirmed 15 minutes after the record (the last moment)', OWN_KEY_WINDOW_MS, false],
    ['confirmed 5 s before the record (the clocks’ tolerance)', -5_000, false],
    ['confirmed 5 s and 1 ms before the record (made before it)', -5_001, true],
  ])('B6-3d judges a key %s', async (_name, after, restricted) => {
    const who = await person();
    const passkey = zitadelId();
    await recordOwn({ person: who.userId, subject: who.subject, passkey }, recordedBefore(after));
    const added = confirmed(who.subject, passkey, recordedBefore(0));

    await copy([added]);

    expect(await restrictedUntil(who.userId)).toEqual(
      restricted ? new Date(added.createdAt.getTime() + WEEK_MS) : undefined,
    );
  });

  it('B6-3d uses a record once: a second confirmation naming the same passkey restricts', async () => {
    const who = await person();
    const passkey = zitadelId();
    await recordOwn({ person: who.userId, subject: who.subject, passkey }, recordedBefore(120_000));
    const first = confirmed(who.subject, passkey, recordedBefore(60_000));
    const second = confirmed(who.subject, passkey, recordedBefore(0));

    await copy([first, second]);

    expect(await copiesOf(who.subject, first)).toEqual([expect.objectContaining({ ownPasskey: passkey })]);
    expect(await copiesOf(who.subject, second)).toEqual([expect.objectContaining({ counts: 'yes' })]);
    expect(await restrictedUntil(who.userId)).toEqual(new Date(second.createdAt.getTime() + WEEK_MS));
  });

  it('B6-3d still restricts the person’s own passkey after a factor removed in the 7 days before', async () => {
    const who = await person();
    const removed = event('user.human.mfa.otp.removed', who.subject, { createdAt: recordedBefore(DAY_LIKE) });
    const passkey = zitadelId();
    await recordOwn({ person: who.userId, subject: who.subject, passkey }, recordedBefore(60_000));
    const added = confirmed(who.subject, passkey, recordedBefore(0));

    await copy([removed, added]);

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
  });

  it('B6-3d takes no record dated ahead of the database’s clock (one only a planted row holds)', async () => {
    const who = await person();
    const passkey = zitadelId();
    // Far past the database's own clock, whatever day the test runs.
    const ahead = new Date('2099-01-01T09:00:00Z');
    clock = new FixedClock(new Date(ahead.getTime() + 6 * 60_000));
    await recordOwn({ person: who.userId, subject: who.subject, passkey }, ahead);
    const added = confirmed(who.subject, passkey, new Date(ahead.getTime() + 60_000));

    await copy([added]);

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
  });
});

/** A factor removed a day before the key: inside the 7 days. */
const DAY_LIKE = 24 * 60 * 60_000;
