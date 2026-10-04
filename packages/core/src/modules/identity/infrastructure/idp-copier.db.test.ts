// B6-2b: copying the login service's admin events into our audit trail, on
// the real migrated schema, as the app role, with a stand-in for the feed:
// each event recorded on each chain of the person's organisations and on the
// platform chain, told to the person and their admins, never twice; where a
// run starts; and what it logs (SEC-OPS-02).
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
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

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { PlatformControlsTables } from '../../platform-controls/index.ts';
import { classOfIdpEvent } from '../domain/idp-event.ts';
import { createIdpEventCopier, IDP_EVENT_COPIED, SIGN_IN_CHANGED } from './idp-copier.ts';
import { IdpFactorsUnavailable, type PasskeysHeld } from './idp-factors.ts';
import { type IdpEvent, type IdpEventFeed, IdpFeedUnavailable } from './idp-feed.ts';
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
const ids = new SequentialIds(0xc6d0_0000_0000);
const ISSUER = 'https://auth.example.test';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
let clock: FixedClock;
let capture: LogCapture;

let subjects = 0;
/** A Zitadel user ID, new each time. */
const zitadelId = (): string => {
  subjects += 1;
  return String(312_000_000_000_000_000n + BigInt(subjects));
};

/** A person who has signed in to Agent X, as Zitadel's subject. */
async function person(): Promise<{ userId: string; subject: string }> {
  const subject = zitadelId();
  return { userId: await userForSubject(app, { issuer: ISSUER, subject }, { ids, clock }), subject };
}

/** A new organisation, with the person as a member when given one. */
async function organization(member?: string, role: 'admin' | 'viewer' = 'viewer'): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: testLogger() }, async (tx, states) => {
    await createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR });
    if (member !== undefined) {
      await addMembership(tx, states, {
        orgId: org,
        id: ids.next(),
        userId: member,
        role,
        joinedAt: clock.now(),
        actor: OPERATOR,
      });
    }
  });
  return org;
}

let sequence = 0;
/** An event of the feed's, about the subject, made a minute before the test's time unless told. */
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
    editorUserId: '312000000000009999',
    ...changes,
  };
}

/** A stand-in for the feed: answers each span with the events after its start and before its end, as Zitadel does, and keeps what was asked. */
function feedOf(events: () => readonly IdpEvent[] | Error) {
  const asked: { since: Date; until: Date; most: number }[] = [];
  const feed: IdpEventFeed = {
    eventsBetween: (since, until, most) => {
      asked.push({ since, until, most });
      const found = events();
      if (found instanceof Error) return Promise.reject(found);
      return Promise.resolve(
        found
          .filter((each) => each.createdAt > since && each.createdAt < until)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
          .slice(0, most),
      );
    },
  };
  return { feed, asked };
}

const copierWith = (feed: IdpEventFeed, passkeys?: PasskeysHeld) =>
  createIdpEventCopier({
    database: app,
    feed,
    keys,
    ids,
    clock,
    issuer: ISSUER,
    outbox: createOutbox({ ids, clock }),
    passkeys,
    logger: testLogger(capture),
  });

/** The platform chain's copies of the event, by organisation. */
const platformCopies = async (key: string) =>
  (
    await app
      .selectFrom('platform_controls.audit_events')
      .select(['actor_id', 'details'])
      .where('action', '=', IDP_EVENT_COPIED)
      .orderBy('seq')
      .execute()
  )
    .map((row): Record<string, unknown> => ({
      actor: row.actor_id,
      ...(JSON.parse(row.details) as Record<string, unknown>),
    }))
    .filter((details) => details.event === key);

const orgRecords = (org: string) =>
  withTenant(app, org, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'actor_id', 'subject_type', 'subject_id', 'details'])
      .where('action', '=', SIGN_IN_CHANGED)
      .orderBy('seq')
      .execute(),
  );

const noticesOf = (org: string) =>
  app
    .selectFrom('notifications.outbox')
    .select(['recipient_user_id', 'kind', 'about_id'])
    .where('org_id', '=', org)
    .orderBy('created_at')
    .orderBy('id')
    .execute();

const lines = (name: string) => capture.lines().filter((line) => line.event === name);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  // Each test a day on from the last, so the events of one aren't in another's span.
  clock = new FixedClock(new Date(Date.UTC(2026, 8, 27 + subjects, 9)));
  capture = new LogCapture();
});

describe(`copying the login service's events (B6-2b, Postgres ${server.version})`, () => {
  // First: a day back is where a chain that has copied nothing yet starts, and this file's database is new.
  it('starts a day back, reads up to a minute ago, and then from the latest event copied', async () => {
    const who = await person();
    await organization(who.userId);
    const older = event('user.locked', who.subject, { createdAt: new Date(clock.now().getTime() - 3_600_000) });
    const { feed, asked } = feedOf(() => [older]);

    await copierWith(feed).run();

    expect(asked[0]).toEqual({
      since: new Date(clock.now().getTime() - 86_400_000),
      until: new Date(clock.now().getTime() - 60_000),
      most: 100,
    });
    asked.length = 0;
    clock.advanceBy(10 * 60_000);
    await copierWith(feed).run();
    // From just before the latest event copied, for Zitadel's span leaves out its own start.
    expect(asked[0]?.since).toEqual(new Date(older.createdAt.getTime() - 1));
    expect(asked[0]?.until).toEqual(new Date(clock.now().getTime() - 60_000));
  });

  it('SEC-OPS-02 records a factor removed on each of the person’s organisations’ chains and the platform’s, and tells them and the admins', async () => {
    const who = await person();
    const first = await organization(who.userId);
    const second = await organization(who.userId, 'admin');
    const removed = event('user.human.mfa.otp.removed', who.subject);
    const { feed } = feedOf(() => [removed]);

    await copierWith(feed).run();

    const key = `user:${who.subject}:${removed.sequence}`;
    for (const org of [first, second]) {
      expect(await orgRecords(org)).toEqual([
        {
          action: 'person.sign_in_changed',
          actor_id: 'api',
          subject_type: 'person',
          subject_id: who.userId,
          details: JSON.stringify({
            at: removed.createdAt.toISOString(),
            by: 'other',
            event: key,
            type: 'user.human.mfa.otp.removed',
          }),
        },
      ]);
      expect(await noticesOf(org)).toEqual([
        { recipient_user_id: who.userId, kind: 'second_factor_removed', about_id: who.userId },
        { recipient_user_id: null, kind: 'second_factor_removed', about_id: who.userId },
      ]);
    }
    expect(await platformCopies(key)).toEqual(
      [first, second]
        .sort()
        .map((org): unknown =>
          expect.objectContaining({ actor: 'api', org, person: who.userId, type: 'user.human.mfa.otp.removed' }),
        ),
    );
    expect(lines('idp_events.copied')).toEqual([expect.objectContaining({ events: 1, records: 2 })]);
  });

  it.each([
    'user.human.mfa.u2f.token.verified',
    'user.human.passwordless.token.verified',
    'user.human.mfa.otp.verified',
  ])(
    'records a factor added (%s) and tells the person and the admins, even one they added themselves (the S68 audit)',
    async (type) => {
      const who = await person();
      const org = await organization(who.userId);
      const added = event(type, who.subject, { editorUserId: who.subject });
      const { feed } = feedOf(() => [added]);

      await copierWith(feed).run();

      expect(await orgRecords(org)).toMatchObject([
        { action: 'person.sign_in_changed', subject_id: who.userId, details: expect.stringContaining(type) as unknown },
      ]);
      expect(await noticesOf(org)).toEqual([
        { recipient_user_id: who.userId, kind: 'second_factor_added', about_id: who.userId },
        { recipient_user_id: null, kind: 'second_factor_added', about_id: who.userId },
      ]);
      const key = `user:${who.subject}:${added.sequence}`;
      expect(await platformCopies(key)).toEqual([expect.objectContaining({ org, by: 'self', type })]);
    },
  );

  it('copies nothing twice: a second run, or the same time read again, records nothing', async () => {
    const who = await person();
    const org = await organization(who.userId);
    const locked = event('user.locked', who.subject, { editorUserId: who.subject });
    const { feed } = feedOf(() => [locked]);

    await copierWith(feed).run();
    clock.advanceBy(10 * 60_000);
    await copierWith(feed).run();

    expect(await orgRecords(org)).toHaveLength(1);
    expect(await noticesOf(org)).toHaveLength(2);
    expect(await platformCopies(`user:${who.subject}:${locked.sequence}`)).toEqual([
      expect.objectContaining({ by: 'self' }),
    ]);
  });

  it('records an event about no one who has signed in, or about the login service itself, on the platform chain alone', async () => {
    const stranger = zitadelId();
    const rights = event('instance.member.added', '312000000000000001', {
      aggregateType: 'instance',
      editorUserId: null,
    });
    const reset = event('user.human.password.code.added', stranger);
    const { feed } = feedOf(() => [rights, reset]);

    await copierWith(feed).run();

    expect(await platformCopies(`instance:312000000000000001:${rights.sequence}`)).toEqual([
      expect.objectContaining({ org: 'none', person: null, by: 'system', type: 'instance.member.added' }),
    ]);
    expect(await platformCopies(`user:${stranger}:${reset.sequence}`)).toEqual([
      expect.objectContaining({ org: 'none', person: null }),
    ]);
    expect(lines('idp.rights_changed')).toEqual([
      expect.objectContaining({ level: 'warn', eventType: 'instance.member.added', by: 'system', organisations: 0 }),
    ]);
  });

  it('records an event about someone who belongs to no organisation on the platform chain alone, naming them', async () => {
    const who = await person();
    const removed = event('user.human.mfa.u2f.token.removed', who.subject);
    const { feed } = feedOf(() => [removed]);

    await copierWith(feed).run();

    expect(await platformCopies(`user:${who.subject}:${removed.sequence}`)).toEqual([
      expect.objectContaining({ org: 'none', person: who.userId, type: 'user.human.mfa.u2f.token.removed' }),
    ]);
  });

  it('tells an organisation it had yet to tell when a run stopped part-way, from where it got to, on the next run', async () => {
    const who = await person();
    const first = await organization(who.userId);
    const second = await organization(who.userId);
    const removed = event('user.human.mfa.otp.removed', who.subject);
    const { feed } = feedOf(() => [removed]);
    const outbox = createOutbox({ ids, clock });
    let failNext = false;
    const failing = {
      ...outbox,
      add: (...args: Parameters<typeof outbox.add>) => {
        if (failNext) return Promise.reject(new Error('the database went away'));
        failNext = true;
        return outbox.add(...args);
      },
    };
    const copier = (sink: typeof outbox) =>
      createIdpEventCopier({
        database: app,
        feed,
        keys,
        ids,
        clock,
        issuer: ISSUER,
        outbox: sink,
        logger: testLogger(capture),
      });

    await copier(failing).run();
    expect(lines('idp_events.run_failed')).toHaveLength(1);
    expect([(await orgRecords(first)).length, (await orgRecords(second)).length].sort()).toEqual([0, 1]);

    clock.advanceBy(10 * 60_000);
    await copier(outbox).run();

    expect(await orgRecords(first)).toHaveLength(1);
    expect(await orgRecords(second)).toHaveLength(1);
    expect(await platformCopies(`user:${who.subject}:${removed.sequence}`)).toHaveLength(2);
  });

  it('logs impersonation as an error and a token issued as a warning, and tells no one of either', async () => {
    const who = await person();
    const org = await organization(who.userId);
    const { feed } = feedOf(() => [event('user.impersonated', who.subject), event('user.token.added', who.subject)]);

    await copierWith(feed).run();

    expect(lines('idp.impersonated')).toEqual([expect.objectContaining({ level: 'error', organisations: 1 })]);
    expect(lines('idp.token_issued')).toEqual([expect.objectContaining({ level: 'warn' })]);
    expect(await orgRecords(org)).toHaveLength(2);
    expect(await noticesOf(org)).toEqual([]);
  });

  it('reads a full page, then the next, until one is not full', async () => {
    const who = await person();
    const org = await organization(who.userId);
    const base = clock.now().getTime() - 30 * 60_000;
    const many = Array.from({ length: 150 }, (_, index) =>
      event('user.human.password.changed', who.subject, { createdAt: new Date(base + index * 1000) }),
    );
    const { feed, asked } = feedOf(() => many);

    await copierWith(feed).run();

    expect(asked).toHaveLength(2);
    expect(await orgRecords(org)).toHaveLength(150);
    // The second page reads the first's last event again, from a millisecond before it, and copies it once.
    expect(lines('idp_events.copied')).toEqual([expect.objectContaining({ events: 151, records: 150 })]);
  });

  it('moves through a burst of more than a page on each page, never reading it again from its start', async () => {
    const who = await person();
    const org = await organization(who.userId);
    const base = clock.now().getTime() - 30 * 60_000;
    const burst = Array.from({ length: 120 }, (_, index) =>
      event('user.human.password.changed', who.subject, { createdAt: new Date(base + index * 40) }),
    );
    const events = [...burst];
    const { feed } = feedOf(() => events);

    await copierWith(feed).run();
    expect(await orgRecords(org)).toHaveLength(120);

    // Another event, well after the burst: every later run reaches it, never held up by the burst.
    events.push(event('user.locked', who.subject, { createdAt: new Date(base + 10 * 60_000) }));
    clock.advanceBy(60_000);
    await copierWith(feed).run();
    clock.advanceBy(60_000);
    await copierWith(feed).run();

    expect(await orgRecords(org)).toHaveLength(121);
    expect(lines('idp_events.tied_page')).toEqual([]);
  });

  it(
    'moves on by what each page holds, run after run, however many events share a few seconds',
    { timeout: 120_000 },
    async () => {
      const who = await person();
      const org = await organization(who.userId);
      const base = clock.now().getTime() - 30 * 60_000;
      const many = Array.from({ length: 1100 }, (_, index) =>
        event('user.token.added', who.subject, { createdAt: new Date(base + index * 3) }),
      );
      const { feed } = feedOf(() => many);

      await copierWith(feed).run();
      // Ten pages: the first a hundred, each after it its last one's last event again and 99 more.
      expect(await orgRecords(org)).toHaveLength(991);
      clock.advanceBy(60_000);
      await copierWith(feed).run();

      expect(await orgRecords(org)).toHaveLength(1100);
    },
  );

  it('reads again the events at a page’s last time that the page cut off, and copies each once', async () => {
    const who = await person();
    const org = await organization(who.userId);
    const base = clock.now().getTime() - 30 * 60_000;
    const spread = Array.from({ length: 98 }, (_, index) =>
      event('user.human.password.changed', who.subject, { createdAt: new Date(base + index * 1000) }),
    );
    const at = new Date(base + 200_000);
    const tied = Array.from({ length: 5 }, () => event('user.locked', who.subject, { createdAt: at }));
    const { feed } = feedOf(() => [...spread, ...tied]);

    await copierWith(feed).run();

    expect(await orgRecords(org)).toHaveLength(103);
    expect(lines('idp_events.tied_page')).toEqual([]);
  });

  it('logs as an error, and passes, a full page all at one time, copied before', async () => {
    const who = await person();
    const org = await organization(who.userId);
    const at = new Date(clock.now().getTime() - 10 * 60_000);
    const same = Array.from({ length: 100 }, () =>
      event('user.human.password.changed', who.subject, { createdAt: at }),
    );
    const later = event('user.unlocked', who.subject, { createdAt: new Date(at.getTime() + 60_000) });
    const { feed } = feedOf(() => [...same, later]);

    await copierWith(feed).run();

    expect(await orgRecords(org)).toHaveLength(101);
    expect(lines('idp_events.tied_page')).toEqual([
      expect.objectContaining({ level: 'error', at: at.toISOString(), events: 100 }),
    ]);
  });

  it('never throws: a feed away is logged, and the next run copies what it can', async () => {
    const who = await person();
    const org = await organization(who.userId);
    let away = true;
    const { feed } = feedOf(() =>
      away ? new IdpFeedUnavailable('it answered 403') : [event('user.unlocked', who.subject)],
    );

    await expect(copierWith(feed).run()).resolves.toBeUndefined();
    expect(lines('idp_events.run_failed')).toEqual([expect.objectContaining({ level: 'warn' })]);
    away = false;
    await copierWith(feed).run();
    expect(await noticesOf(org)).toMatchObject([{ kind: 'sign_in_restored' }, { kind: 'sign_in_restored' }]);
  });

  it('stops between events once its signal is aborted, copying the rest on the next run', async () => {
    const who = await person();
    const org = await organization(who.userId);
    const stopping = new AbortController();
    stopping.abort();
    const { feed } = feedOf(() => [event('user.locked', who.subject)]);

    await copierWith(feed).run(stopping.signal);
    expect(await orgRecords(org)).toEqual([]);
    await copierWith(feed).run();
    expect(await orgRecords(org)).toHaveLength(1);
  });

  it('reads nothing when a minute ago is before where it got to', async () => {
    const who = await person();
    await organization(who.userId);
    const recent = event('user.locked', who.subject, { createdAt: new Date(clock.now().getTime() - 61_000) });
    const { feed, asked } = feedOf(() => [recent]);
    await copierWith(feed).run();
    asked.length = 0;

    clock = new FixedClock(new Date(recent.createdAt.getTime() + 30_000));
    await copierWith(feed).run();

    expect(asked).toEqual([]);
  });
});

describe(`the S68 audit's rules on a copied event (Postgres ${server.version})`, () => {
  /** A stand-in for the reset token's reader: the person holds this many keys, or it can't be read. */
  const holding = (held: number | Error): PasskeysHeld => ({
    passkeysHeld: () => (held instanceof Error ? Promise.reject(held) : Promise.resolve(held)),
  });
  const restrictedUntil = (userId: string) => createRemovalRestriction({ database: app, clock })(userId);
  const sessionsOf = async (userId: string) =>
    (await app.selectFrom('identity.sessions').select('id').where('user_id', '=', userId).execute()).length;
  const signIn = (userId: string) =>
    createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } }).open(app, userId, {
      idpSessionId: 'V1_1',
      authTime: clock.now(),
      amr: ['pwd', 'user', 'mfa'],
    });
  const WEEK_MS = 7 * DAY_MS;

  it.each(['user.human.mfa.u2f.token.verified', 'user.human.passwordless.token.verified'])(
    'leaves a person’s first key (%s) free: no restriction',
    async (type) => {
      const who = await person();
      await organization(who.userId, 'admin');
      const added = event(type, who.subject, { editorUserId: who.subject });

      await copierWith(feedOf(() => [added]).feed, holding(1)).run();

      expect(await restrictedUntil(who.userId)).toBeUndefined();
      expect(await platformCopies(`user:${who.subject}:${added.sequence}`)).toEqual([
        expect.not.objectContaining({ counts: 'yes' }),
      ]);
    },
  );

  it('restricts a person for 7 days from a second key added, even by themselves', async () => {
    const who = await person();
    await organization(who.userId, 'admin');
    const added = event('user.human.passwordless.token.verified', who.subject, { editorUserId: who.subject });

    let reads = 0;
    const counting: PasskeysHeld = {
      passkeysHeld: () => {
        reads += 1;
        return Promise.resolve(2);
      },
    };
    const { feed } = feedOf(() => [added]);

    await copierWith(feed, counting).run();

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
    expect(await platformCopies(`user:${who.subject}:${added.sequence}`)).toEqual([
      expect.objectContaining({ counts: 'yes', by: 'self' }),
    ]);
    // Decided once: the same event read again asks the login service nothing.
    clock.advanceBy(60_000);
    await copierWith(feed, counting).run();
    expect(reads).toBe(1);
  });

  it('restricts a key added within 7 days of a key removed, even their only one: removing theirs, then adding one’s own', async () => {
    const who = await person();
    await organization(who.userId, 'admin');
    const removed = event('user.human.mfa.u2f.token.removed', who.subject, {
      editorUserId: who.subject,
      createdAt: new Date(clock.now().getTime() - 20 * 60_000),
    });
    const added = event('user.human.mfa.u2f.token.verified', who.subject, { editorUserId: who.subject });

    await copierWith(feedOf(() => [removed, added]).feed, holding(1)).run();

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
  });

  it.each([
    ['in one run', true],
    ['in two runs', false],
  ])(
    'restricts a swap: one’s own key added, then the person’s removed by them, %s (the S68 review)',
    async (_how, together) => {
      const who = await person();
      await organization(who.userId, 'admin');
      const added = event('user.human.mfa.u2f.token.verified', who.subject, {
        editorUserId: who.subject,
        createdAt: new Date(clock.now().getTime() - 20 * 60_000),
      });
      const removed = event('user.human.passwordless.token.removed', who.subject, { editorUserId: who.subject });
      // Read live, the count is one: the person's key is gone by the time the addition is judged.
      if (together) {
        await copierWith(feedOf(() => [added, removed]).feed, holding(1)).run();
      } else {
        await copierWith(feedOf(() => [added]).feed, holding(1)).run();
        await copierWith(feedOf(() => [added, removed]).feed, holding(1)).run();
      }

      expect(await restrictedUntil(who.userId)).toEqual(new Date(removed.createdAt.getTime() + WEEK_MS));
      expect(await platformCopies(`user:${who.subject}:${removed.sequence}`)).toEqual([
        expect.objectContaining({ counts: 'yes', by: 'self' }),
      ]);
    },
  );

  it('leaves a person’s own key removed free when the key added before was more than 7 days before', async () => {
    const who = await person();
    await organization(who.userId, 'admin');
    const added = event('user.human.mfa.u2f.token.verified', who.subject, { editorUserId: who.subject });
    await copierWith(feedOf(() => [added]).feed, holding(1)).run();
    expect(await platformCopies(`user:${who.subject}:${added.sequence}`)).toHaveLength(1);
    clock.advanceBy(WEEK_MS + 1);
    const removed = event('user.human.passwordless.token.removed', who.subject, { editorUserId: who.subject });

    await copierWith(feedOf(() => [added, removed]).feed, holding(1)).run();

    expect(await platformCopies(`user:${who.subject}:${removed.sequence}`)).toEqual([
      expect.not.objectContaining({ counts: 'yes' }),
    ]);
    // The tests after this one start after its clock: each starts a day on per person made.
    for (let day = 0; day < 9; day += 1) zitadelId();
  });

  it('leaves a person’s own key removed free when no key was added in the 7 days before', async () => {
    const who = await person();
    await organization(who.userId, 'admin');
    const removed = event('user.human.mfa.u2f.token.removed', who.subject, { editorUserId: who.subject });

    await copierWith(feedOf(() => [removed]).feed, holding(1)).run();

    expect(await restrictedUntil(who.userId)).toBeUndefined();
  });

  it('leaves a key added more than 7 days after a removal free, if it is the only one', async () => {
    const who = await person();
    await organization(who.userId, 'admin');
    // The removal, copied now; the key, a moment past 7 days later. (The copier reads only forward, so the clock moves on.)
    const removed = event('user.human.mfa.u2f.token.removed', who.subject, { editorUserId: who.subject });
    await copierWith(feedOf(() => [removed]).feed, holding(0)).run();
    expect(await platformCopies(`user:${who.subject}:${removed.sequence}`)).toHaveLength(1);
    clock.advanceBy(WEEK_MS + 1);
    const added = event('user.human.mfa.u2f.token.verified', who.subject, { editorUserId: who.subject });

    await copierWith(feedOf(() => [removed, added]).feed, holding(1)).run();

    expect(await platformCopies(`user:${who.subject}:${added.sequence}`)).toEqual([
      expect.not.objectContaining({ counts: 'yes' }),
    ]);
    // The tests after this one start after its clock: each starts a day on per person made.
    for (let day = 0; day < 9; day += 1) zitadelId();
  });

  it.each([
    ['no reset token to read them with', undefined],
    ['an answer it can’t judge', holding(new IdpFactorsUnavailable('reading the factors: it answered 500'))],
  ])('counts a key added when the keys can’t be read (%s): the rule fails closed', async (_why, passkeys) => {
    const who = await person();
    await organization(who.userId, 'admin');
    const added = event('user.human.mfa.u2f.token.verified', who.subject, { editorUserId: who.subject });

    await copierWith(feedOf(() => [added]).feed, passkeys).run();

    expect(await restrictedUntil(who.userId)).toEqual(new Date(added.createdAt.getTime() + WEEK_MS));
    expect(lines('idp_events.keys_unread')).toHaveLength(passkeys === undefined ? 0 : 1);
  });

  it('never counts an app code added, whatever the person holds', async () => {
    const who = await person();
    await organization(who.userId, 'admin');
    const added = event('user.human.mfa.otp.verified', who.subject, { editorUserId: who.subject });

    await copierWith(feedOf(() => [added]).feed, holding(5)).run();

    expect(await restrictedUntil(who.userId)).toBeUndefined();
  });

  it.each([
    'user.human.mfa.u2f.token.verified',
    'user.human.mfa.otp.removed',
    'user.human.password.changed',
    'user.human.email.changed',
    'user.locked',
  ])('ends every Agent X session of the person on %s, once, whatever organisations they belong to', async (type) => {
    const who = await person();
    await organization(who.userId);
    await organization(who.userId, 'admin');
    await signIn(who.userId);
    await signIn(who.userId);
    const changed = event(type, who.subject);
    const { feed } = feedOf(() => [changed]);

    await copierWith(feed, holding(1)).run();

    expect(await sessionsOf(who.userId)).toBe(0);
    const copies = await platformCopies(`user:${who.subject}:${changed.sequence}`);
    expect(copies).toHaveLength(2);
    // Ended once, on the first organisation's copy: the other's records none.
    expect(copies.filter((copy) => 'signInsEnded' in copy)).toEqual([expect.objectContaining({ signInsEnded: 2 })]);
    // Signed in again since, and joined another organisation: the same event read again, and copied
    // there for the first time, ends nothing.
    await signIn(who.userId);
    const joined = await organization(who.userId);
    clock.advanceBy(60_000);
    await copierWith(feed, holding(1)).run();
    expect(await platformCopies(`user:${who.subject}:${changed.sequence}`)).toEqual(
      expect.arrayContaining([expect.objectContaining({ org: joined })]) as unknown,
    );
    expect(await sessionsOf(who.userId)).toBe(1);
  });

  it('ends the sessions of a person in no organisation too', async () => {
    const who = await person();
    await signIn(who.userId);
    const locked = event('user.locked', who.subject);

    await copierWith(feedOf(() => [locked]).feed).run();

    expect(await sessionsOf(who.userId)).toBe(0);
  });

  it('ends no session on a login unlocked or a token issued', async () => {
    const who = await person();
    await organization(who.userId);
    await signIn(who.userId);

    await copierWith(
      feedOf(() => [event('user.unlocked', who.subject), event('user.token.added', who.subject)]).feed,
    ).run();

    expect(await sessionsOf(who.userId)).toBe(1);
  });
});
