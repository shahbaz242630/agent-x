// D2-1: the fake partner's records (0028) on the real migrated schema, as the
// app role. The records in memory and in the database keep the same
// contract; in the database the partner outlives a restart and is the same
// partner to every process (a second fake over the same table stands in for
// the bank's steps run elsewhere); two calls with the same ID at once give
// one link or payee (the race forced: the first holds its step open once it
// has added, until the second queues behind it); one organisation's records
// are never another's; and no
// account number is ever written (PRD Phase 1: no raw bank details in the
// database).
import { createDatabase, type Database } from '@agentx/platform/db';
import {
  createTestDatabase,
  findLeaks,
  FixedClock,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
} from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { uuidV7Ids } from '../../../shared-kernel/index.ts';
import type { LinkOutcome, SourceLookup } from '../domain/rail.ts';
import { createFakeRail, type FakeRailOptions } from './fake-rail.ts';
import {
  createDatabaseRecords,
  createMemoryRecords,
  type FakePartnerStore,
  type FakePartnerTables,
  type FakeRecord,
  type FakeRecords,
} from './fake-records.ts';
import { SANDBOX_ACCOUNTS } from './sandbox-accounts.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<FakePartnerTables>;

const START = new Date('2026-10-01T08:00:00Z');
const ORG = '0199a0f0-0000-7000-8000-00000000d2a1';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000d2a2';
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const IBANS = SANDBOX_ACCOUNTS.flatMap((account) => account.AccountIdentifiers.map((each) => each.Identification));
const [JASMINE = ''] = IBANS;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<FakePartnerTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** A fresh reference for each test, so tests sharing the database never meet. */
let count = 0;
const fresh = (prefix: string): string => {
  count += 1;
  return `${prefix}-${String(count)}`;
};

const link = (ref: string, alias = `session-${ref}`): FakeRecord<'link'> => ({
  ref,
  alias,
  body: { expiresAt: START.toISOString(), outcome: 'open' },
});

function sourceOf(outcome: LinkOutcome | SourceLookup) {
  if (outcome.kind !== 'linked' && outcome.kind !== 'found') throw new Error(`No source: ${outcome.kind}`);
  return outcome.source;
}

const stores: readonly (readonly [string, () => FakePartnerStore])[] = [
  ['in memory', createMemoryRecords],
  ['in the database', () => createDatabaseRecords(app)],
];

describe.each(stores)(`the fake partner's records %s (D2-1, Postgres ${server.version})`, (where, storeOf) => {
  it('adds a record once: adding it again adds nothing and keeps the first', async () => {
    const store = storeOf();
    const ref = fresh('link');
    expect(await store.within(ORG, (records) => records.add('link', link(ref)))).toBe(true);
    expect(await store.within(ORG, (records) => records.add('link', link(ref, 'another-session')))).toBe(false);
    expect(await store.within(ORG, (records) => records.get('link', ref))).toEqual(link(ref));
  });

  it('finds a record by its alias, and replaces it whole', async () => {
    const store = storeOf();
    const ref = fresh('link');
    await store.within(ORG, (records) => records.add('link', link(ref)));
    const rejected: FakeRecord<'link'> = {
      ...link(ref, `moved-${ref}`),
      body: { ...link(ref).body, outcome: 'rejected' },
    };
    await store.within(ORG, (records) => records.update('link', rejected));
    expect(await store.within(ORG, (records) => records.byAlias('link', `moved-${ref}`))).toEqual(rejected);
    expect(await store.within(ORG, (records) => records.byAlias('link', `session-${ref}`))).toBeUndefined();
  });

  it('keeps a kind’s records apart from another kind’s of the same reference', async () => {
    const store = storeOf();
    const ref = fresh('shared');
    await store.within(ORG, (records) => records.add('link', link(ref)));
    expect(await store.within(ORG, (records) => records.get('registration', ref))).toBeUndefined();
    expect(await store.within(ORG, (records) => records.byAlias('source', `session-${ref}`))).toBeUndefined();
  });

  it('shows one organisation’s records to no other: none by reference, none by alias', async () => {
    const store = storeOf();
    const ref = fresh('link');
    await store.within(ORG, (records) => records.add('link', link(ref)));
    expect(await store.within(OTHER_ORG, (records) => records.get('link', ref))).toBeUndefined();
    expect(await store.within(OTHER_ORG, (records) => records.byAlias('link', `session-${ref}`))).toBeUndefined();
    expect(await store.within(OTHER_ORG, (records) => records.add('link', link(ref)))).toBe(true);
    expect(await store.within(OTHER_ORG, (records) => Promise.resolve(records.organizationId))).toBe(OTHER_ORG);
  });

  it('gives copies: changing what it gave changes nothing it holds', async () => {
    const store = storeOf();
    const ref = fresh('link');
    const added = link(ref);
    await store.within(ORG, (records) => records.add('link', added));
    Object.assign(added.body, { outcome: 'rejected' });
    const read = await store.within(ORG, (records) => records.get('link', ref));
    Object.assign(read?.body ?? {}, { outcome: 'rejected' });
    expect((await store.within(ORG, (records) => records.get('link', ref)))?.body.outcome).toBe('open');
  });

  it('refuses to replace a record that isn’t there', async () => {
    const store = storeOf();
    const ref = fresh('link');
    await expect(store.within(ORG, (records) => records.update('link', link(ref)))).rejects.toThrow();
    expect(await store.within(ORG, (records) => records.get('link', ref))).toBeUndefined();
  });

  it('refuses a second record of a kind with the same alias, added or replaced', async () => {
    const store = storeOf();
    const [ref, other, alias] = [fresh('link'), fresh('link'), fresh('session')];
    await store.within(ORG, (records) => records.add('link', link(ref, alias)));
    await expect(store.within(ORG, (records) => records.add('link', link(other, alias)))).rejects.toThrow();
    await store.within(ORG, (records) => records.add('link', link(other)));
    await expect(store.within(ORG, (records) => records.update('link', link(other, alias)))).rejects.toThrow();
    expect(await store.within(ORG, (records) => records.byAlias('link', alias))).toEqual(link(ref, alias));
  });

  it('undoes a step that fails part way: nothing of it is kept', async () => {
    const store = storeOf();
    const ref = fresh('link');
    await expect(
      store.within(ORG, async (records) => {
        await records.add('link', link(ref));
        throw new Error('the step failed');
      }),
    ).rejects.toThrow('the step failed');
    // In memory a step isn't undone, as it has no transaction: only the database's is.
    const kept = await store.within(ORG, (records) => records.get('link', ref));
    expect(kept === undefined).toBe(where === 'in the database');
  });
});

describe(`the fake partner on the database (D2-1, Postgres ${server.version})`, () => {
  /** A fake over the database's records: another one is another process, or the same after a restart. */
  const partner = (options: Partial<FakeRailOptions> = {}) =>
    createFakeRail({
      clock: new FixedClock(START),
      ids: uuidV7Ids,
      records: createDatabaseRecords(app),
      ...options,
    });

  it('outlives a restart: a link started before it is approved and confirmed after, by other processes', async () => {
    const linkId = fresh('link');
    const session = await partner().startSourceLink({ organizationId: ORG, linkId });
    const consentId = await partner().bank.approve(ORG, session.sessionRef, ACCOUNT);
    const source = sourceOf(await partner().confirmSourceLink({ organizationId: ORG, linkId }));
    expect(source).toMatchObject({ accountConsentId: consentId, availability: 'ACTIVE', summary: { hint: 'AE…6026' } });
    await partner().bank.changeConsent(ORG, consentId, 'Suspended');
    const later = sourceOf(await partner().getSourceState({ organizationId: ORG, externalRef: source.externalRef }));
    expect(later.availability).toBe('SUSPENDED');
    const renewed = await partner().bank.renew(ORG, source.externalRef);
    expect(
      sourceOf(await partner().getSourceState({ organizationId: ORG, externalRef: source.externalRef })),
    ).toMatchObject({ accountConsentId: renewed, replacesConsentId: consentId, availability: 'ACTIVE' });
  });

  it('keeps a payee’s hosted form open across processes, and its registration after', async () => {
    const registrationId = fresh('reg');
    const hosted = { route: 'hosted', organizationId: ORG, registrationId } as const;
    const waiting = await partner().registerBeneficiary(hosted);
    if (waiting.kind !== 'waiting') throw new Error(`Not waiting: ${waiting.kind}`);
    await partner().bank.fillForm(ORG, waiting.formUrl, { name: 'Jasmine AI FZ-LLC', iban: JASMINE });
    const registered = await partner().getBeneficiaryState({ organizationId: ORG, registrationId });
    expect(registered).toMatchObject({ kind: 'registered', beneficiary: { registrationId, nameCheck: 'match' } });
    expect(await partner().registerBeneficiary(hosted)).toEqual(registered);
  });

  /**
   * The first party of a forced race: a step that has added `record` and is
   * held open, its row not yet committed, until the test lets it go.
   */
  async function heldOpen(add: (records: FakeRecords) => Promise<boolean>) {
    let letGo = (): void => undefined;
    const released = new Promise<void>((resolve) => {
      letGo = resolve;
    });
    let added = (): void => undefined;
    const hasAdded = new Promise<void>((resolve) => {
      added = resolve;
    });
    const step = createDatabaseRecords(app).within(ORG, async (records) => {
      expect(await add(records)).toBe(true);
      added();
      await released;
    });
    // A step that fails before it has added fails the test at once, rather than leaving it to time out.
    await Promise.race([hasAdded, step]);
    return {
      finish: async () => {
        letGo();
        await step;
      },
    };
  }

  it('gives one session to two starts of the same link at once: the second waits, then answers the first’s', async () => {
    const linkId = fresh('link');
    const first = link(linkId, fresh('session'));
    const held = await heldOpen((records) => records.add('link', first));
    const second = partner().startSourceLink({ organizationId: ORG, linkId });
    await waitUntilQueued(database.as('admin'), 1);
    await held.finish();
    expect((await second).sessionRef).toBe(first.alias);
    expect(await partner().startSourceLink({ organizationId: ORG, linkId })).toEqual(await second);
  });

  it('registers one payee for two registrations of the same ID at once: the second waits, then answers the first’s', async () => {
    const registrationId = fresh('reg');
    const beneficiary = {
      beneficiaryRef: fresh('held-beneficiary'),
      payeeIdentity: null,
      nameCheck: 'match',
      maskedName: 'J****** A* F*****',
      hint: 'AE…6026',
      registeredAt: START.toISOString(),
    } as const;
    const held = await heldOpen((records) =>
      records.add('registration', { ref: registrationId, alias: null, body: { form: null, outcome: { beneficiary } } }),
    );
    const payee = { name: 'Jasmine AI FZ-LLC', iban: JASMINE };
    const second = partner().registerBeneficiary({ route: 'pass_through', organizationId: ORG, registrationId, payee });
    await waitUntilQueued(database.as('admin'), 1);
    await held.finish();
    expect(await second).toMatchObject({
      kind: 'registered',
      beneficiary: { beneficiaryRef: beneficiary.beneficiaryRef },
    });
  });

  it('answers another organisation’s link and source as none', async () => {
    const linkId = fresh('link');
    const session = await partner().startSourceLink({ organizationId: ORG, linkId });
    await partner().bank.approve(ORG, session.sessionRef, ACCOUNT);
    const source = sourceOf(await partner().confirmSourceLink({ organizationId: ORG, linkId }));
    expect(await partner().confirmSourceLink({ organizationId: OTHER_ORG, linkId })).toEqual({
      kind: 'refused',
      reason: 'unknown',
    });
    expect(await partner().getSourceState({ organizationId: OTHER_ORG, externalRef: source.externalRef })).toEqual({
      kind: 'not_found',
    });
    await expect(partner().bank.approve(OTHER_ORG, session.sessionRef, ACCOUNT)).rejects.toThrow('No link waiting');
  });

  it('writes no account number: every account linked and registered both ways, the table holds none', async () => {
    for (const [index, account] of SANDBOX_ACCOUNTS.entries()) {
      const linkId = fresh('link');
      const session = await partner().startSourceLink({ organizationId: ORG, linkId });
      await partner().bank.approve(ORG, session.sessionRef, account.AccountId);
      const iban = account.AccountIdentifiers[0]?.Identification ?? '';
      const payee = { name: account.AccountHolderName, iban };
      await partner().registerBeneficiary({
        route: 'pass_through',
        organizationId: ORG,
        registrationId: fresh('reg'),
        payee,
      });
      const hosted = await partner().registerBeneficiary({
        route: 'hosted',
        organizationId: ORG,
        registrationId: fresh('reg'),
      });
      if (hosted.kind !== 'waiting') throw new Error(`Form ${String(index)} not waiting`);
      await partner().bank.fillForm(ORG, hosted.formUrl, payee);
    }
    const rows = await database
      .as('backup')
      .query<{ text: string }>(
        'select org_id::text || kind || ref || coalesce(alias, $1) || body::text as text from fake_partner.records',
        [''],
      );
    expect(rows.length).toBeGreaterThan(SANDBOX_ACCOUNTS.length * 3);
    // The fake's own IDs are random UUIDs inside other text (`fake-consent-<uuid>`), and now and then one's groups
    // read as an IBAN with valid check digits (main after #202). They hold no account number, so they are taken out
    // first; every sandbox IBAN is still looked for as itself, and every IBAN's shape in what is left.
    const text = rows.map((row) => row.text.replaceAll(UUID, 'id')).join('\n');
    expect(findLeaks(text, IBANS)).toEqual([]);
  });

  it('shows the app nothing outside an organisation’s transaction: the tenant wall fails closed', async () => {
    await partner().startSourceLink({ organizationId: ORG, linkId: fresh('link') });
    const { rows } = await sql`select count(*)::int as seen from fake_partner.records`.execute(app);
    expect(rows).toEqual([{ seen: 0 }]);
  });

  it('lets the app neither delete a record nor change what it is about', async () => {
    const ref = fresh('link');
    await createDatabaseRecords(app).within(ORG, (records) => records.add('link', link(ref)));
    const as = database.as('app');
    await expect(as.query('delete from fake_partner.records')).rejects.toThrow('permission denied');
    await expect(as.query('update fake_partner.records set ref = ref')).rejects.toThrow('permission denied');
    await expect(as.query('update fake_partner.records set org_id = org_id')).rejects.toThrow('permission denied');
    await expect(as.query('update fake_partner.records set kind = kind')).rejects.toThrow('permission denied');
  });
});
