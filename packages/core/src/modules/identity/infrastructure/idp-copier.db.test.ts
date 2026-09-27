// B6-2b: copying the login service's admin events into our audit trail, on
// the real migrated schema, as the app role, with a stand-in for the feed:
// each event recorded on each chain of the person's organisations and on the
// platform chain, told to the person and their admins, never twice; where a
// run starts; and what it logs (SEC-OPS-02).
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOutbox, type NotificationsTables } from '../../notifications/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import type { PlatformControlsTables } from '../../platform-controls/index.ts';
import { classOfIdpEvent } from '../domain/idp-event.ts';
import { createIdpEventCopier, IDP_EVENT_COPIED, SIGN_IN_CHANGED } from './idp-copier.ts';
import { type IdpEvent, type IdpEventFeed, IdpFeedUnavailable } from './idp-feed.ts';
import { addMembership } from './memberships.ts';
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

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

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
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, async (tx, states) => {
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

/** A stand-in for the feed: answers each span with the events in it, and keeps what was asked. */
function feedOf(events: () => readonly IdpEvent[] | Error) {
  const asked: { since: Date; until: Date; most: number }[] = [];
  const feed: IdpEventFeed = {
    eventsBetween: (since, until, most) => {
      asked.push({ since, until, most });
      const found = events();
      if (found instanceof Error) return Promise.reject(found);
      return Promise.resolve(
        found
          .filter((each) => each.createdAt >= since && each.createdAt <= until)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
          .slice(0, most),
      );
    },
  };
  return { feed, asked };
}

const copierWith = (feed: IdpEventFeed) =>
  createIdpEventCopier({
    database: app,
    feed,
    keys,
    ids,
    clock,
    issuer: ISSUER,
    outbox: createOutbox({ ids, clock }),
    logger: loggerFor(capture),
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
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, loggerFor(new LogCapture()));
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
    expect(asked[0]?.since.getTime()).toBeGreaterThanOrEqual(older.createdAt.getTime());
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

    expect(asked.length).toBe(2);
    expect(await orgRecords(org)).toHaveLength(150);
    expect(lines('idp_events.copied')).toEqual([expect.objectContaining({ events: 151, records: 150 })]);
  });

  it('stops, saying so, when a full page holds nothing new: more events at one time than a page', async () => {
    const who = await person();
    await organization(who.userId);
    const at = new Date(clock.now().getTime() - 10 * 60_000);
    const same = Array.from({ length: 100 }, () =>
      event('user.human.password.changed', who.subject, { createdAt: at }),
    );
    const { feed, asked } = feedOf(() => same);

    await copierWith(feed).run();

    expect(asked.length).toBe(2);
    expect(lines('idp_events.stuck')).toEqual([expect.objectContaining({ level: 'warn', at: at.toISOString() })]);
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
