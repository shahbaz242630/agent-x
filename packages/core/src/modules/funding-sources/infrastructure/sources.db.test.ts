// D2-2: links and funding sources (0029), on the real migrated schema, as the
// app role, with sources as the fake partner confirms them. A link is added
// open and settled once; a source is added from the partner's answer, ACTIVE,
// sealed, never another organisation's or one already gone; brought up to the
// partner's later answers (recorded only when they change; ENDED, for good,
// when the partner says it is gone); suspended and reactivated by Agent X;
// and no account number is ever written. What the owner can do past the app
// is sources-tamper.db.test.ts.
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import {
  createTestDatabase,
  FixedClock,
  findLeaks,
  LogCapture,
  SequentialIds,
  type TestDatabase,
} from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import {
  createFakeRail,
  type FundingSourceState,
  type LinkOutcome,
  SANDBOX_ACCOUNTS,
  type SourceLookup,
  USUAL_CONTROLS,
} from '../../providers/index.ts';
import { addLink, LinkNotOpen, linkOf, settleLink } from './links.ts';
import {
  addSource,
  endUnknownToPartner,
  MOST_SOURCES_A_PAGE,
  NotThisSource,
  SOURCES,
  sourceOf,
  sourcesPage,
  updateFromPartner,
} from './sources.ts';
import type { FundingSourcesTables } from './tables.ts';

type Tables = FundingSourcesTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xd2b0_0000_0000);
const clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
const DAY_MS = 86_400_000;
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

const capture = new LogCapture();
const services = () => ({
  keys,
  ids,
  logger: createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  }),
});

/** The fake partner, in memory: the bank's side of each test. */
const rail = createFakeRail({ clock, ids: new SequentialIds(0xfa0_0000) });

const organization = async (): Promise<string> => {
  const id = ids.next();
  await withSignedStates(app, id, services(), (tx, states) =>
    createOrganization(tx, states, { id, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  return id;
};

function sourceOfAnswer(outcome: LinkOutcome | SourceLookup): FundingSourceState {
  if (outcome.kind !== 'linked' && outcome.kind !== 'found') throw new Error(`No source: ${outcome.kind}`);
  return outcome.source;
}

/** A link started at the partner and approved at the bank with `accountId`; the source as the partner confirms it. */
async function confirmed(orgId: string, accountId = ACCOUNT) {
  const linkId = ids.next();
  const session = await rail.startSourceLink({ organizationId: orgId, linkId });
  const consentId = await rail.bank.approve(orgId, session.sessionRef, accountId);
  const state = sourceOfAnswer(await rail.confirmSourceLink({ organizationId: orgId, linkId }));
  return { linkId, session, consentId, state };
}

const addTheLink = (orgId: string, { linkId, session }: Awaited<ReturnType<typeof confirmed>>) =>
  withTenant(app, orgId, (tx) =>
    addLink(tx, {
      orgId,
      id: linkId,
      startedBy: ids.next(),
      partner: 'fake',
      sessionRef: session.sessionRef,
      expiresAt: session.expiresAt,
      createdAt: clock.now(),
    }),
  );

/** A source linked as D2-3 will: the link added, then in one transaction the source added and the link settled. */
async function linkedSource(orgId: string, accountId = ACCOUNT) {
  const answer = await confirmed(orgId, accountId);
  await addTheLink(orgId, answer);
  const id = ids.next();
  const recorded = await withSignedStates(app, orgId, services(), async (tx, states) => {
    const link = await linkOf(tx, { orgId, id: answer.linkId }, 'change');
    expect(link?.outcome).toBe('open');
    const added = await addSource(tx, states, {
      orgId,
      id,
      linkId: answer.linkId,
      partner: 'fake',
      state: answer.state,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    await settleLink(tx, { orgId, id: answer.linkId }, { outcome: 'linked', sourceId: id }, clock.now());
    return added;
  });
  return { ...answer, id, recorded };
}

const read = (orgId: string, id: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => sourceOf(tx, states, { orgId, id }, 'share'));

const found = async (orgId: string, id: string) => {
  const check = await read(orgId, id);
  if (check.outcome !== 'found') throw new Error(`Not found: ${check.outcome}`);
  return check.source;
};

/** The partner's answer now, brought into the source. */
const refresh = (orgId: string, id: string, externalRef: string) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const state = sourceOfAnswer(await rail.getSourceState({ organizationId: orgId, externalRef }));
    const check = await sourceOf(tx, states, { orgId, id }, 'change');
    if (check.outcome !== 'found') throw new Error(`Not found: ${check.outcome}`);
    return updateFromPartner(tx, states, { orgId, id }, check, { state, actor: OPERATOR });
  });

const events = (orgId: string, id: string) =>
  withTenant(app, orgId, (tx) =>
    tx
      .selectFrom('audit.events')
      .select(['action', 'subject_version', 'details'])
      .where('subject_type', '=', 'funding_source')
      .where('subject_id', '=', id)
      .orderBy('seq')
      .execute(),
  );

const changeStatus = (orgId: string, id: string, event: 'suspend' | 'reactivate' | 'end') =>
  withSignedStates(app, orgId, services(), (tx, states) =>
    states.changeStatus(tx, SOURCES, { orgId, id }, event, {
      actor: OPERATOR,
      action: `funding_source.${event}`,
      details: {},
    }),
  );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(
    { ...database.connection('app'), maxConnections: 4 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`a link (D2-2, Postgres ${server.version})`, () => {
  it('is added open, and settled once with the source it made', async () => {
    const org = await organization();
    const { linkId, session, id } = await linkedSource(org);
    const link = await withTenant(app, org, (tx) => linkOf(tx, { orgId: org, id: linkId }, 'share'));
    expect(link).toMatchObject({
      id: linkId,
      partner: 'fake',
      sessionRef: session.sessionRef,
      expiresAt: session.expiresAt,
      outcome: 'linked',
      sourceId: id,
      settledAt: clock.now(),
    });
    await expect(
      withTenant(app, org, (tx) => settleLink(tx, { orgId: org, id: linkId }, { outcome: 'rejected' }, clock.now())),
    ).rejects.toThrow(LinkNotOpen);
  });

  it.each(['rejected', 'expired', 'unknown'] as const)('is settled %s with no source', async (outcome) => {
    const org = await organization();
    const answer = await confirmed(org);
    await addTheLink(org, answer);
    const key = { orgId: org, id: answer.linkId };
    await withTenant(app, org, (tx) => settleLink(tx, key, { outcome }, clock.now()));
    expect(await withTenant(app, org, (tx) => linkOf(tx, key, 'share'))).toMatchObject({ outcome, sourceId: null });
  });

  it('is open until settled, and no link of that ID can be settled', async () => {
    const org = await organization();
    const answer = await confirmed(org);
    await addTheLink(org, answer);
    expect(await withTenant(app, org, (tx) => linkOf(tx, { orgId: org, id: answer.linkId }, 'change'))).toMatchObject({
      outcome: 'open',
      sourceId: null,
      settledAt: null,
    });
    await expect(
      withTenant(app, org, (tx) => settleLink(tx, { orgId: org, id: ids.next() }, { outcome: 'unknown' }, clock.now())),
    ).rejects.toThrow(LinkNotOpen);
  });

  it('is another organisation’s to no one: none of that ID there', async () => {
    const org = await organization();
    const other = await organization();
    const answer = await confirmed(org);
    await addTheLink(org, answer);
    expect(
      await withTenant(app, other, (tx) => linkOf(tx, { orgId: other, id: answer.linkId }, 'share')),
    ).toBeUndefined();
  });

  it('holds an end to its shape: a source for a link that made one, none for one that didn’t', async () => {
    const org = await organization();
    const { id } = await linkedSource(org);
    const answer = await confirmed(org);
    await addTheLink(org, answer);
    const set = (outcome: string, sourceId: string | null) =>
      withTenant(app, org, (tx) =>
        tx
          .updateTable('funding_sources.links')
          .set({ outcome, source_id: sourceId, settled_at: clock.now() })
          .where('id', '=', answer.linkId)
          .execute(),
      );
    await expect(set('rejected', id)).rejects.toThrow('settled_once_with_its_end');
    await expect(set('linked', null)).rejects.toThrow('settled_once_with_its_end');
  });

  it('refuses a partner’s name that isn’t one, before any SQL runs', async () => {
    const org = await organization();
    await expect(
      withTenant(app, org, (tx) =>
        addLink(tx, {
          orgId: org,
          id: ids.next(),
          startedBy: ids.next(),
          partner: 'Fake Partner',
          sessionRef: 'fake-link-1',
          expiresAt: new Date(clock.now().getTime() + DAY_MS),
          createdAt: clock.now(),
        }),
      ),
    ).rejects.toThrow('lower-case words');
  });
});

describe(`a funding source (D2-2, Postgres ${server.version})`, () => {
  it('is added ACTIVE from the partner’s answer, every authority field sealed', async () => {
    const org = await organization();
    const { id, linkId, state } = await linkedSource(org);
    expect(await found(org, id)).toEqual({
      id,
      linkId,
      partner: 'fake',
      externalRef: state.externalRef,
      status: 'ACTIVE',
      availability: 'ACTIVE',
      consentStatus: 'Authorized',
      accountConsentId: state.accountConsentId,
      replacesConsentId: null,
      consentExpiresAt: state.consentExpiresAt,
      controls: USUAL_CONTROLS,
      summary: { holderName: 'Jasmine AI FZ-LLC', accountType: 'sme', hint: 'AE…6026' },
      partnerChangedAt: state.statusChangedAt,
    });
  });

  it('records its linking with the partner’s facts, never the holder’s name', async () => {
    const org = await organization();
    const { id, linkId, state } = await linkedSource(org);
    const [linked, ...more] = await events(org, id);
    expect(more).toEqual([]);
    expect(linked).toMatchObject({ action: 'funding_source.linked', subject_version: 1 });
    expect(JSON.parse(linked?.details ?? '{}')).toMatchObject({
      linkId,
      partner: 'fake',
      availability: 'ACTIVE',
      consentStatus: 'Authorized',
      accountConsentId: state.accountConsentId,
      consentExpiresAt: state.consentExpiresAt.toISOString(),
    });
    expect(linked?.details).not.toContain('Jasmine');
  });

  it('is found by no other organisation', async () => {
    const org = await organization();
    const other = await organization();
    const { id } = await linkedSource(org);
    expect(await read(other, id)).toEqual({ outcome: 'missing' });
  });

  it('is refused for another organisation’s answer, one already gone, or a partner’s name that isn’t one', async () => {
    const org = await organization();
    const other = await organization();
    const answer = await confirmed(org);
    await addTheLink(org, answer);
    const add = (state: FundingSourceState, partner = 'fake') =>
      withSignedStates(app, org, services(), (tx, states) =>
        addSource(tx, states, {
          orgId: org,
          id: ids.next(),
          linkId: answer.linkId,
          partner,
          state,
          createdAt: clock.now(),
          actor: OPERATOR,
        }),
      );
    await expect(add({ ...answer.state, organizationId: other })).rejects.toThrow("another organisation's");
    await expect(add({ ...answer.state, availability: 'UNAVAILABLE' })).rejects.toThrow('never added');
    await expect(add(answer.state, 'Fake')).rejects.toThrow('lower-case words');
  });

  it('is one a partner reference: the same reference can’t be added twice', async () => {
    const org = await organization();
    const first = await linkedSource(org);
    const answer = await confirmed(org);
    await addTheLink(org, answer);
    await expect(
      withSignedStates(app, org, services(), (tx, states) =>
        addSource(tx, states, {
          orgId: org,
          id: ids.next(),
          linkId: answer.linkId,
          partner: 'fake',
          state: { ...answer.state, externalRef: first.state.externalRef },
          createdAt: clock.now(),
          actor: OPERATOR,
        }),
      ),
    ).rejects.toThrow('one_source_a_reference');
  });

  it('is suspended by the business and reactivated; once ended it never comes back', async () => {
    const org = await organization();
    const { id } = await linkedSource(org);
    expect(await changeStatus(org, id, 'suspend')).toMatchObject({ outcome: 'changed', to: 'SUSPENDED' });
    expect((await found(org, id)).status).toBe('SUSPENDED');
    expect(await changeStatus(org, id, 'reactivate')).toMatchObject({ outcome: 'changed', to: 'ACTIVE' });
    expect(await changeStatus(org, id, 'end')).toMatchObject({ outcome: 'changed', to: 'ENDED' });
    expect(await changeStatus(org, id, 'reactivate')).toMatchObject({ outcome: 'refused' });
    expect((await found(org, id)).status).toBe('ENDED');
  });
});

describe(`a funding source brought up to the partner’s answer (D2-2, Postgres ${server.version})`, () => {
  it('records nothing when the partner’s answer is unchanged', async () => {
    const org = await organization();
    const { id, state } = await linkedSource(org);
    clock.advanceBy(60_000);
    const before = await found(org, id);
    expect(await refresh(org, id, state.externalRef)).toEqual(before);
    expect(await events(org, id)).toHaveLength(1);
  });

  it('records the bank’s suspension and its return, each once', async () => {
    const org = await organization();
    const { id, state, consentId } = await linkedSource(org);
    await rail.bank.changeConsent(org, consentId, 'Suspended');
    expect(await refresh(org, id, state.externalRef)).toMatchObject({ status: 'ACTIVE', availability: 'SUSPENDED' });
    expect(await found(org, id)).toMatchObject({
      status: 'ACTIVE',
      availability: 'SUSPENDED',
      consentStatus: 'Suspended',
    });
    await rail.bank.changeConsent(org, consentId, 'Authorized');
    await refresh(org, id, state.externalRef);
    expect((await events(org, id)).map((event) => event.action)).toEqual([
      'funding_source.linked',
      'funding_source.partner_changed',
      'funding_source.partner_changed',
    ]);
    expect((await found(org, id)).availability).toBe('ACTIVE');
  });

  it('takes a renewal’s new consent and controls, under the same reference', async () => {
    const org = await organization();
    const { id, state, consentId } = await linkedSource(org);
    const controls = { ...USUAL_CONTROLS, maxPaymentMinor: 9_000_000_000_000n, maxPeriodPayments: 7 };
    const renewed = await rail.bank.renew(org, state.externalRef, controls);
    await refresh(org, id, state.externalRef);
    expect(await found(org, id)).toMatchObject({
      externalRef: state.externalRef,
      accountConsentId: renewed,
      replacesConsentId: consentId,
      controls,
    });
  });

  it.each(['Revoked', 'Consumed'] as const)(
    'ends the source for good once the partner says %s, whatever Agent X held',
    async (status) => {
      const org = await organization();
      const { id, state, consentId } = await linkedSource(org);
      await changeStatus(org, id, 'suspend');
      await rail.bank.changeConsent(org, consentId, status);
      expect(await refresh(org, id, state.externalRef)).toMatchObject({ status: 'ENDED', availability: 'UNAVAILABLE' });
      expect(await found(org, id)).toMatchObject({
        status: 'ENDED',
        availability: 'UNAVAILABLE',
        consentStatus: status,
      });
      await refresh(org, id, state.externalRef);
      expect((await events(org, id)).map((event) => event.action)).toEqual([
        'funding_source.linked',
        'funding_source.suspend',
        'funding_source.partner_changed',
        'funding_source.ended',
      ]);
    },
  );

  it('ends at the consent’s expiry, as the partner then says', async () => {
    const org = await organization();
    const { id, state } = await linkedSource(org);
    clock.advanceBy(366 * DAY_MS);
    expect(await refresh(org, id, state.externalRef)).toMatchObject({ status: 'ENDED', consentStatus: 'Expired' });
  });

  it.each([
    ['its availability', (state: FundingSourceState) => ({ ...state, availability: 'SUSPENDED' as const })],
    ['the partner’s word for it', (state: FundingSourceState) => ({ ...state, consentStatus: 'Suspended' })],
    ['its consent', (state: FundingSourceState) => ({ ...state, accountConsentId: 'fake-consent-other' })],
    ['the consent it renewed', (state: FundingSourceState) => ({ ...state, replacesConsentId: 'fake-consent-old' })],
    [
      'its expiry',
      (state: FundingSourceState) => ({ ...state, consentExpiresAt: new Date(state.consentExpiresAt.getTime() - 1) }),
    ],
    ['its currency', (state: FundingSourceState) => ({ ...state, controls: { ...state.controls, currency: 'USD' } })],
    [
      'its period',
      (state: FundingSourceState) => ({ ...state, controls: { ...state.controls, period: 'week' as const } }),
    ],
    [
      'its most a payment',
      (state: FundingSourceState) => ({ ...state, controls: { ...state.controls, maxPaymentMinor: 1n } }),
    ],
    [
      'its most a period',
      (state: FundingSourceState) => ({ ...state, controls: { ...state.controls, maxPeriodMinor: 1n } }),
    ],
    [
      'its most payments a period',
      (state: FundingSourceState) => ({ ...state, controls: { ...state.controls, maxPeriodPayments: 1 } }),
    ],
    [
      'its holder’s name',
      (state: FundingSourceState) => ({ ...state, summary: { ...state.summary, holderName: 'Renamed LLC' } }),
    ],
    [
      'its account type',
      (state: FundingSourceState) => ({ ...state, summary: { ...state.summary, accountType: 'corporate' as const } }),
    ],
    ['its hint', (state: FundingSourceState) => ({ ...state, summary: { ...state.summary, hint: 'AE…0000' } })],
    [
      'when it last changed',
      (state: FundingSourceState) => ({ ...state, statusChangedAt: new Date(state.statusChangedAt.getTime() + 1) }),
    ],
  ])('records an answer that changes %s alone', async (_, changed) => {
    const org = await organization();
    const { id, state } = await linkedSource(org);
    const answer = changed(state);
    const now = await withSignedStates(app, org, services(), async (tx, states) => {
      const check = await sourceOf(tx, states, { orgId: org, id }, 'change');
      if (check.outcome !== 'found') throw new Error(`Not found: ${check.outcome}`);
      return updateFromPartner(tx, states, { orgId: org, id }, check, { state: answer, actor: OPERATOR });
    });
    expect((await events(org, id)).map((event) => event.action)).toEqual([
      'funding_source.linked',
      'funding_source.partner_changed',
    ]);
    expect(await found(org, id)).toEqual(now);
  });

  it('refuses an answer for another source, or another organisation’s, before any SQL runs', async () => {
    const org = await organization();
    const other = await organization();
    const { id, state } = await linkedSource(org);
    const { state: elsewhere } = await confirmed(org, 'corporate-treasury-listed-acct-04');
    const bring = (answer: FundingSourceState) =>
      withSignedStates(app, org, services(), async (tx, states) => {
        const check = await sourceOf(tx, states, { orgId: org, id }, 'change');
        if (check.outcome !== 'found') throw new Error(`Not found: ${check.outcome}`);
        return updateFromPartner(tx, states, { orgId: org, id }, check, { state: answer, actor: OPERATOR });
      });
    await expect(bring(elsewhere)).rejects.toThrow(NotThisSource);
    await expect(bring({ ...state, organizationId: other })).rejects.toThrow(NotThisSource);
    expect(await events(org, id)).toHaveLength(1);
  });

  it('changes nothing for an answer older than the one it holds: two refreshes crossing (D2-4)', async () => {
    const org = await organization();
    const { id, state } = await linkedSource(org);
    const before = await found(org, id);
    const older = {
      ...state,
      availability: 'SUSPENDED' as const,
      consentStatus: 'Suspended',
      statusChangedAt: new Date(state.statusChangedAt.getTime() - 1),
    };
    const now = await withSignedStates(app, org, services(), async (tx, states) => {
      const check = await sourceOf(tx, states, { orgId: org, id }, 'change');
      if (check.outcome !== 'found') throw new Error(`Not found: ${check.outcome}`);
      return updateFromPartner(tx, states, { orgId: org, id }, check, { state: older, actor: OPERATOR });
    });
    expect(now).toEqual(before);
    expect(await found(org, id)).toEqual(before);
    expect(await events(org, id)).toHaveLength(1);
  });
});

describe(`a funding source the partner no longer knows (D2-4, Postgres ${server.version})`, () => {
  const endUnknown = (orgId: string, id: string) =>
    withSignedStates(app, orgId, services(), async (tx, states) => {
      const check = await sourceOf(tx, states, { orgId, id }, 'change');
      if (check.outcome !== 'found') throw new Error(`Not found: ${check.outcome}`);
      return endUnknownToPartner(tx, states, { orgId, id }, check, OPERATOR);
    });

  it.each(['ACTIVE', 'SUSPENDED'] as const)('ends from %s, recorded as unknown to the partner', async (from) => {
    const org = await organization();
    const { id } = await linkedSource(org);
    if (from === 'SUSPENDED') await changeStatus(org, id, 'suspend');

    const now = await endUnknown(org, id);

    expect(now.status).toBe('ENDED');
    expect(await found(org, id)).toEqual(now);
    const last = (await events(org, id)).at(-1);
    expect(last?.action).toBe('funding_source.ended');
    expect(JSON.parse(String(last?.details))).toMatchObject({ unknownToPartner: true, statusTo: 'ENDED' });
  });

  it('leaves an ended source as it is, recording nothing', async () => {
    const org = await organization();
    const { id } = await linkedSource(org);
    await changeStatus(org, id, 'end');
    const recorded = (await events(org, id)).length;

    expect((await endUnknown(org, id)).status).toBe('ENDED');
    expect(await events(org, id)).toHaveLength(recorded);
  });
});

describe(`a page of an organisation's funding sources (D2-4, Postgres ${server.version})`, () => {
  const page = (orgId: string, after: string | null, limit: number) =>
    withSignedStates(app, orgId, services(), (tx, states) => sourcesPage(tx, states, orgId, { after, limit }));

  it('holds its own sources alone, in order of ID, a page at a time', async () => {
    const org = await organization();
    const other = await organization();
    const mine = [
      await linkedSource(org),
      await linkedSource(org, 'sme-trading-business-acct-01'),
      await linkedSource(org, 'corporate-treasury-listed-acct-01'),
    ];
    await linkedSource(other);
    const [first, second, third] = await Promise.all(mine.map(({ id }) => found(org, id)));

    expect(await page(org, null, 2)).toEqual({ outcome: 'listed', sources: [first, second], next: second?.id });
    expect(await page(org, second?.id ?? null, 2)).toEqual({ outcome: 'listed', sources: [third], next: null });
    // A page exactly full is the last when nothing follows it.
    expect(await page(org, null, 3)).toEqual({ outcome: 'listed', sources: [first, second, third], next: null });
    expect(await page(org, null, MOST_SOURCES_A_PAGE)).toEqual({
      outcome: 'listed',
      sources: [first, second, third],
      next: null,
    });
  });

  it('is empty for an organisation with none', async () => {
    const org = await organization();
    expect(await page(org, null, 1)).toEqual({ outcome: 'listed', sources: [], next: null });
  });

  it.each([0, MOST_SOURCES_A_PAGE + 1, 1.5])('refuses a page of %j, before any SQL runs', async (limit) => {
    const org = await organization();
    await expect(page(org, null, limit)).rejects.toThrow(RangeError);
  });
});

describe(`what the app may do to the tables (D2-2, Postgres ${server.version})`, () => {
  it('writes no account number: every sandbox account linked, neither table holds one', async () => {
    const org = await organization();
    for (const account of SANDBOX_ACCOUNTS) await linkedSource(org, account.AccountId);
    const ibans = SANDBOX_ACCOUNTS.flatMap((account) => account.AccountIdentifiers.map((each) => each.Identification));
    const rows = await database
      .as('backup')
      .query<{ text: string }>(
        'select (select pg_catalog.string_agg(s::text, $1) from funding_sources.sources s) || (select pg_catalog.string_agg(l::text, $1) from funding_sources.links l) as text',
        ['\n'],
      );
    expect(rows[0]?.text).toContain('AE…6026');
    expect(findLeaks(rows[0]?.text ?? '', ibans)).toEqual([]);
  });

  it('lets the app neither delete nor change when a source was added, or who started a link', async () => {
    const as = database.as('app');
    await expect(as.query('delete from funding_sources.sources')).rejects.toThrow('permission denied');
    await expect(as.query('delete from funding_sources.links')).rejects.toThrow('permission denied');
    await expect(as.query('update funding_sources.sources set created_at = created_at')).rejects.toThrow(
      'permission denied',
    );
    await expect(as.query('update funding_sources.links set started_by = started_by')).rejects.toThrow(
      'permission denied',
    );
  });
});
