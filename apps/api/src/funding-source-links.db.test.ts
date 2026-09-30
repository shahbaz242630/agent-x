// D2-3b (BR-01, BR-02, SEC-PTR-08): linking the organisation's bank account
// through the use case the routes call, on the real migrated schema, as the
// app role, with the fake partner over its own records in the same database,
// as staging runs it. The routes' answers are funding-sources.test.ts; the
// tables themselves are the funding-sources module's own tests.
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { addLink, type FundingSourcesTables, MOST_LINKS_STARTED_A_DAY } from '@agentx/core/modules/funding-sources';
import {
  addMembership,
  type IdentityTables,
  MEMBERSHIPS,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  createDatabaseRecords,
  createFakeRail,
  type FakePartnerTables,
  type FakeRail,
  RailUnavailable,
} from '@agentx/core/modules/providers';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createFundingSourceLinks,
  railFor,
  type FundingSourceLinks,
  LINK_CONFIRM_OPERATION,
  LINK_START_OPERATION,
  type LinkConfirmWrite,
  linkIdFor,
  type LinkingMember,
  type LinkStartWrite,
} from './funding-source-links.ts';

type Tables = IdentityTables &
  FundingSourcesTables &
  FakePartnerTables &
  OrganizationsTables &
  DirectoryTables &
  AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xd23b_0000_0000);
const MINUTE_MS = 60_000;
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000aa';

let clock: FixedClock;
let rail: FakeRail;
let links: FundingSourceLinks;

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let people = 0;

/** A person with a membership in the organisation. */
async function member(org: string, role: Role): Promise<LinkingMember & { readonly membershipId: string }> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `funding-links-${String(people)}` },
    { ids, clock },
  );
  const membershipId = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, membershipId };
}

async function organization(): Promise<string> {
  const org = ids.next();
  await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return org;
}

let keysUsed = 0;
const keyed = (who: LinkingMember, operation: string, key = `key-${String((keysUsed += 1))}`): IdempotentRequest => ({
  orgId: who.orgId,
  client: { kind: 'user', id: who.userId },
  operation,
  key,
  payload: '{}',
});

const start = (who: LinkingMember, key?: string) =>
  links.start(who, keyed(who, LINK_START_OPERATION, key), CORRELATION);
const confirm = (who: LinkingMember, linkId: string, key?: string) =>
  links.confirm(who, keyed(who, LINK_CONFIRM_OPERATION, key), linkId, CORRELATION);

const startedOf = (write: LinkStartWrite) => {
  if (write.outcome !== 'started') throw new Error(`not started: ${JSON.stringify(write)}`);
  return write;
};
const confirmedOf = (write: LinkConfirmWrite) => {
  if (write.outcome !== 'confirmed') throw new Error(`not confirmed: ${JSON.stringify(write)}`);
  return write;
};

/** The partner's session for a started link: the last part of the page's address. */
const sessionOf = (authoriseUrl: string): string => authoriseUrl.slice(authoriseUrl.lastIndexOf('/') + 1);

const rows = (org: string) =>
  withTenant(app, org, async (tx) => ({
    links: await tx.selectFrom('funding_sources.links').select(['id', 'outcome', 'source_id']).execute(),
    sources: await tx.selectFrom('funding_sources.sources').select(['id', 'link_id', 'status']).execute(),
  }));

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
  rail = createFakeRail({ clock, ids, records: createDatabaseRecords(app) });
  links = createFundingSourceLinks({
    database: app,
    keys,
    ids,
    clock,
    rail,
    partner: 'fake',
    logger: loggerFor(new LogCapture()),
  });
});

describe(`starting a link (D2-3b, Postgres ${server.version})`, () => {
  it('adds the link, open, with the partner’s session, and gives the partner’s page', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');

    const { link, authoriseUrl } = startedOf(await start(admin));

    expect(authoriseUrl).toMatch(/^https:\/\/bank\.fake-partner\.invalid\/authorise\/fake-link-/);
    expect(link).toMatchObject({
      partner: 'fake',
      sessionRef: sessionOf(authoriseUrl),
      outcome: 'open',
      sourceId: null,
      createdAt: clock.now(),
      expiresAt: new Date(clock.now().getTime() + 15 * MINUTE_MS),
    });
    expect((await rows(org)).links).toEqual([{ id: link.id, outcome: null, source_id: null }]);
  });

  it('answers a retry of the same write with the first link and its session', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const first = startedOf(await start(admin, 'same'));

    expect(startedOf(await start(admin, 'same'))).toEqual(first);
    expect((await rows(org)).links).toHaveLength(1);
  });

  it('refuses anyone but an active admin, adding nothing', async () => {
    const org = await organization();
    for (const role of ['approver', 'developer', 'viewer'] as const) {
      expect(await start(await member(org, role))).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    }
    expect((await rows(org)).links).toEqual([]);
  });

  it('refuses an admin whose membership is deactivated, adding nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    await withSignedStates(app, org, { keys, ids, logger: loggerFor(new LogCapture()) }, (tx, states) =>
      states.changeStatus(tx, MEMBERSHIPS, { orgId: org, id: admin.membershipId }, 'deactivate', {
        actor: OPERATOR,
        action: 'membership.deactivated',
        details: {},
      }),
    );

    expect(await start(admin)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect((await rows(org)).links).toEqual([]);
  });

  it('answers PARTNER_UNAVAILABLE, adding nothing, while the partner doesn’t answer or none is set up', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const unavailable = { outcome: 'refused', status: 503, code: 'PARTNER_UNAVAILABLE' };
    rail.bank.goDown();
    expect(await start(admin)).toEqual(unavailable);
    rail.bank.comeBack();
    const none = createFundingSourceLinks({
      database: app,
      keys,
      ids,
      clock,
      rail: undefined,
      partner: 'none',
      logger: loggerFor(new LogCapture()),
    });
    expect(await none.start(admin, keyed(admin, LINK_START_OPERATION), CORRELATION)).toEqual(unavailable);
    expect(await none.confirm(admin, keyed(admin, LINK_CONFIRM_OPERATION), ids.next(), CORRELATION)).toEqual(
      unavailable,
    );
    expect((await rows(org)).links).toEqual([]);
  });

  it(`refuses the ${String(MOST_LINKS_STARTED_A_DAY + 1)}st link in 24 hours, and takes one again a day on`, async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    for (let started = 0; started < MOST_LINKS_STARTED_A_DAY; started += 1) startedOf(await start(admin));
    expect(await start(admin)).toEqual({ outcome: 'refused', status: 409, code: 'LINK_STARTS_SPENT' });
    clock.advanceBy(24 * 60 * MINUTE_MS);
    startedOf(await start(admin));
  });

  it('asks the partner for nothing when the start would be refused: past the budget, or not an admin', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    for (let started = 0; started < MOST_LINKS_STARTED_A_DAY; started += 1) startedOf(await start(admin));
    // Down, so a call to it would answer PARTNER_UNAVAILABLE instead.
    rail.bank.goDown();

    expect(await start(admin)).toEqual({ outcome: 'refused', status: 409, code: 'LINK_STARTS_SPENT' });
    expect(await start(await member(org, 'viewer'))).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
  });

  it('starts one link, not two, from the day’s last, two starts at once: the organisation’s lock orders them', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    for (let started = 1; started < MOST_LINKS_STARTED_A_DAY; started += 1) startedOf(await start(admin));
    // Another start of the organisation's, part-way: its lock taken, not yet committed.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))', [
        `agentx.funding-links:${org}`,
      ]);
      const both = within(20_000, Promise.all([start(admin), start(admin)]), 'the two starts');
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('commit');

      const outcomes = (await both).map((each) => (each.outcome === 'refused' ? each.code : each.outcome)).sort();
      expect(outcomes).toEqual(['LINK_STARTS_SPENT', 'started']);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    expect((await rows(org)).links).toHaveLength(MOST_LINKS_STARTED_A_DAY);
  });
});

describe(`the partner the config names (D2-3b, Postgres ${server.version})`, () => {
  it('is none without one, and the fake over the database’s records with it', async () => {
    expect(railFor(undefined, { database: app, clock, ids })).toBeUndefined();
    const fake = railFor({ mode: 'fake' }, { database: app, clock, ids });
    expect(await fake?.capabilities()).toEqual({
      beneficiaryRoutes: ['hosted', 'pass_through'],
      stablePayeeIdentity: true,
    });
  });
});

describe(`failures passed on, never answered as refusals (D2-3b, Postgres ${server.version})`, () => {
  /** The use case over `partner`, and `rail` standing in for the partner. */
  const over = (partner: string, stand: Partial<FakeRail> = {}) =>
    createFundingSourceLinks({
      database: app,
      keys,
      ids,
      clock,
      rail: { ...rail, ...stand },
      partner,
      logger: loggerFor(new LogCapture()),
    });

  it('passes on a partner failure that isn’t a missing answer', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const failing = over('fake', { startSourceLink: () => Promise.reject(new TypeError('the adapter broke')) });

    await expect(failing.start(admin, keyed(admin, LINK_START_OPERATION), CORRELATION)).rejects.toThrow(
      'the adapter broke',
    );
  });

  it('passes on a failure inside the write: a partner’s name the link can’t keep', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');

    await expect(over('Not A Name').start(admin, keyed(admin, LINK_START_OPERATION), CORRELATION)).rejects.toThrow(
      'lower-case words',
    );
    expect((await rows(org)).links).toEqual([]);
  });

  it('passes on a failure of a read: a link ID the database won’t take', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');

    await expect(confirm(admin, 'not-a-uuid')).rejects.toThrow();
  });

  /** The fake partner's link sessions for the organisation: how many it was asked to open. */
  const partnerSessions = (org: string) =>
    withTenant(app, org, (tx) =>
      tx.selectFrom('fake_partner.records').select('ref').where('kind', '=', 'link').execute(),
    );

  it('asks the partner under the same link for a request sent again, so it opens one session, not one a send (the S68 audit)', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');

    const answers = [await start(admin, 'again'), await start(admin, 'again'), await start(admin, 'again')];

    expect(new Set(answers.map((answer) => JSON.stringify(answer))).size).toBe(1);
    expect(await partnerSessions(org)).toHaveLength(1);
    expect((await rows(org)).links).toHaveLength(1);
  });

  it('makes the link’s ID from the key and whose it is: another key, or another admin’s same key, another link', async () => {
    const org = await organization();
    const first = await member(org, 'admin');
    const second = await member(org, 'admin');

    const made = [
      startedOf(await start(first, 'shared')).link.id,
      startedOf(await start(first, 'other')).link.id,
      startedOf(await start(second, 'shared')).link.id,
    ];

    expect(new Set(made).size).toBe(3);
    // RFC 9562's version 8, as the routes' UUIDs take.
    for (const id of made) expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(await partnerSessions(org)).toHaveLength(3);
  });

  it('answers PARTNER_UNAVAILABLE to a retry while the partner doesn’t answer, the link kept', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link } = startedOf(await start(admin, 'retried'));
    const down = over('fake', { startSourceLink: () => Promise.reject(new RailUnavailable()) });

    expect(await down.start(admin, keyed(admin, LINK_START_OPERATION, 'retried'), CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });
    expect((await rows(org)).links).toEqual([{ id: link.id, outcome: null, source_id: null }]);
  });

  it.each([
    ['a script', 'javascript:alert(1)'],
    ['data', 'data:text/html,<p>your bank</p>'],
    ['plain HTTP', 'http://bank.fake-partner.invalid/authorise/x'],
    ['another host', 'https://bank.fake-partner.invalid.example/authorise/x'],
    ['a name in it', 'https://someone@bank.fake-partner.invalid/authorise/x'],
    ['a password in it', 'https://:words@bank.fake-partner.invalid/authorise/x'],
    ['no address at all', 'not a page'],
  ])('never sends a person to a partner’s page that is %s, adding nothing (the S68 audit)', async (_what, page) => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const odd = over('fake', {
      startSourceLink: async (input) => ({ ...(await rail.startSourceLink(input)), authoriseUrl: page }),
    });

    expect(await odd.start(admin, keyed(admin, LINK_START_OPERATION), CORRELATION)).toEqual({
      outcome: 'refused',
      status: 503,
      code: 'PARTNER_UNAVAILABLE',
    });
    expect((await rows(org)).links).toEqual([]);
  });

  it('refuses a key used again once its record was swept, its link taken: IDEMPOTENCY_KEY_REUSED', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    // What a start with this key left 30 days ago, its key's record swept since: the link its key names.
    const request = keyed(admin, LINK_START_OPERATION, 'swept');
    await withTenant(app, org, (tx) =>
      addLink(tx, {
        orgId: org,
        id: linkIdFor(request),
        startedBy: admin.membershipId,
        partner: 'fake',
        sessionRef: 'fake-link-from-long-ago',
        expiresAt: new Date(clock.now().getTime() - 29 * 86_400_000),
        createdAt: new Date(clock.now().getTime() - 30 * 86_400_000),
      }),
    );

    expect(await links.start(admin, request, CORRELATION)).toEqual({
      outcome: 'refused',
      status: 409,
      code: 'IDEMPOTENCY_KEY_REUSED',
    });
    expect((await rows(org)).links).toHaveLength(1);
  });
});

describe(`confirming a link with the partner (D2-3b, Postgres ${server.version})`, () => {
  it('leaves the link open while the business hasn’t finished at its bank', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link } = startedOf(await start(admin));

    expect(confirmedOf(await confirm(admin, link.id))).toMatchObject({ link: { outcome: 'open' }, source: null });
  });

  it('adds the source the partner confirms, ACTIVE, and settles the link with it, once', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link, authoriseUrl } = startedOf(await start(admin));
    const consentId = await rail.bank.approve(org, sessionOf(authoriseUrl), ACCOUNT);

    const { link: settled, source } = confirmedOf(await confirm(admin, link.id));

    expect(settled).toMatchObject({ outcome: 'linked', settledAt: clock.now() });
    expect(source).toMatchObject({
      id: settled.sourceId,
      linkId: link.id,
      partner: 'fake',
      status: 'ACTIVE',
      availability: 'ACTIVE',
      accountConsentId: consentId,
      summary: { holderName: 'Jasmine AI FZ-LLC', accountType: 'sme', hint: 'AE…6026' },
    });
    // Asked again, by another request: answered as it stands, no second source.
    expect(confirmedOf(await confirm(admin, link.id))).toEqual({ outcome: 'confirmed', link: settled, source });
    expect((await rows(org)).sources).toEqual([{ id: settled.sourceId, link_id: link.id, status: 'ACTIVE' }]);
  });

  it('asks the partner again when asked again with the same key while it waited: nothing of a wait is kept', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link, authoriseUrl } = startedOf(await start(admin));
    expect(confirmedOf(await confirm(admin, link.id, 'polling')).link.outcome).toBe('open');
    await rail.bank.approve(org, sessionOf(authoriseUrl), ACCOUNT);

    expect(confirmedOf(await confirm(admin, link.id, 'polling')).link.outcome).toBe('linked');
  });

  it('adds one source, not two, for two confirms at once: the second finds the link settled', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link, authoriseUrl } = startedOf(await start(admin));
    await rail.bank.approve(org, sessionOf(authoriseUrl), ACCOUNT);
    // Something else holds the link for a change: both confirms queue behind it, then ask the partner, then settle.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holder.query('select 1 from funding_sources.links where id = $1 for no key update', [link.id]);
      const both = within(20_000, Promise.all([confirm(admin, link.id), confirm(admin, link.id)]), 'the two confirms');
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('commit');

      const [first, second] = (await both).map(confirmedOf);
      expect(first?.link.outcome).toBe('linked');
      expect(second).toEqual(first);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    expect((await rows(org)).sources).toHaveLength(1);
  });

  it('settles a link turned down at the bank as rejected, with no source', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link, authoriseUrl } = startedOf(await start(admin));
    await rail.bank.reject(org, sessionOf(authoriseUrl));

    expect(confirmedOf(await confirm(admin, link.id))).toMatchObject({
      link: { outcome: 'rejected', sourceId: null },
      source: null,
    });
  });

  it('settles a link the bank never saw approved as expired, once the partner stops waiting', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link } = startedOf(await start(admin));
    clock.advanceBy(15 * MINUTE_MS);

    expect(confirmedOf(await confirm(admin, link.id))).toMatchObject({ link: { outcome: 'expired' } });
  });

  it('never adds a source gone at the partner before Agent X confirmed it: settled rejected', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link, authoriseUrl } = startedOf(await start(admin));
    const consentId = await rail.bank.approve(org, sessionOf(authoriseUrl), ACCOUNT);
    await rail.bank.changeConsent(org, consentId, 'Revoked');

    expect(confirmedOf(await confirm(admin, link.id))).toMatchObject({ link: { outcome: 'rejected' }, source: null });
    expect((await rows(org)).sources).toEqual([]);
  });

  it('answers NOT_FOUND for a link the organisation didn’t start, never asking the partner (SEC-PTR-08)', async () => {
    const org = await organization();
    const other = await organization();
    const admin = await member(org, 'admin');
    const otherAdmin = await member(other, 'admin');
    const { link } = startedOf(await start(otherAdmin));
    // Down, so any call to it would answer PARTNER_UNAVAILABLE instead.
    rail.bank.goDown();

    const notFound = { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
    expect(await confirm(admin, link.id)).toEqual(notFound);
    expect(await confirm(admin, ids.next())).toEqual(notFound);
  });

  it('answers PARTNER_UNAVAILABLE and leaves the link open while the partner doesn’t answer', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const { link, authoriseUrl } = startedOf(await start(admin));
    await rail.bank.approve(org, sessionOf(authoriseUrl), ACCOUNT);
    rail.bank.goDown();

    expect(await confirm(admin, link.id)).toEqual({ outcome: 'refused', status: 503, code: 'PARTNER_UNAVAILABLE' });
    expect((await rows(org)).links).toEqual([{ id: link.id, outcome: null, source_id: null }]);
    rail.bank.comeBack();
    expect(confirmedOf(await confirm(admin, link.id)).link.outcome).toBe('linked');
  });

  it('refuses anyone but an active admin, settling nothing', async () => {
    const org = await organization();
    const admin = await member(org, 'admin');
    const developer = await member(org, 'developer');
    const { link, authoriseUrl } = startedOf(await start(admin));
    await rail.bank.approve(org, sessionOf(authoriseUrl), ACCOUNT);

    expect(await confirm(developer, link.id)).toEqual({ outcome: 'refused', status: 403, code: 'FORBIDDEN' });
    expect((await rows(org)).sources).toEqual([]);
  });
});
