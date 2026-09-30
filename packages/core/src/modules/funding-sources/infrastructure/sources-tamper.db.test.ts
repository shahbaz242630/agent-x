// FX-TAMPER on a funding source (SEC-DB-10, D2-2), as the database's owner:
// agentx_owner, the role the migration job logs in as, holding none of the
// app's keys, working inside one organisation through @agentx/testing's
// tamperAsOwner, as an agent is tested (agents-tamper.db.test.ts).
//
// Each change to what a source may fund (Agent X's status, the partner's
// availability, the reference, the consent and its expiry, the bank's
// controls) or to what is shown of it (the holder's name) is denied by the
// row check, with the SEV-1 alarm, and puts the organisation on its
// integrity hold. The live schema guard, with the product's own list, is
// clean before and after each case.
import { createDatabase, type Database, liveSchemaProblems, withTenant } from '@agentx/platform/db';
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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { AUTHORITY_TABLES } from '../../../authority-tables.ts';
import { type AuditTables, type TamperSign, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { createFakeRail } from '../../providers/index.ts';
import { addLink, settleLink } from './links.ts';
import { addSource, SOURCES, sourceOf, sourcesPage } from './sources.ts';
import type { FundingSourcesTables } from './tables.ts';

type Tables = FundingSourcesTables & OrganizationsTables & DirectoryTables & AuditTables;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. The owner has none of them. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xd2c0);
const clock = new FixedClock(new Date('2026-10-01T08:00:00Z'));
const rail = createFakeRail({ clock, ids: new SequentialIds(0xfb0_0000) });

const loggerFor = (destination: LogCapture) =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });

let capture: LogCapture;
let owner: OwnerTamper;
let org: string;

const services = () => ({ keys, ids, logger: loggerFor(capture) });
const quiet = () => ({ keys, ids, logger: loggerFor(new LogCapture()) });
const OPERATOR = { type: 'system' as const, id: 'test-operator' };

/** A source of this test's organisation, linked through the fake partner, made logging to a capture of its own. */
async function linkedSource(): Promise<string> {
  const linkId = ids.next();
  const session = await rail.startSourceLink({ organizationId: org, linkId });
  await rail.bank.approve(org, session.sessionRef, 'sme-rak-trading-emirati-acct-01');
  const outcome = await rail.confirmSourceLink({ organizationId: org, linkId });
  if (outcome.kind !== 'linked') throw new Error(`Not linked: ${outcome.kind}`);
  const id = ids.next();
  await withTenant(app, org, (tx) =>
    addLink(tx, {
      orgId: org,
      id: linkId,
      startedBy: ids.next(),
      partner: 'fake',
      sessionRef: session.sessionRef,
      expiresAt: session.expiresAt,
      createdAt: clock.now(),
    }),
  );
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    await addSource(tx, states, {
      orgId: org,
      id,
      linkId,
      partner: 'fake',
      state: outcome.source,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    await settleLink(tx, { orgId: org, id: linkId }, { outcome: 'linked', sourceId: id }, clock.now());
  });
  return id;
}

const readSource = (id: string) =>
  withSignedStates(app, org, services(), (tx, states) => sourceOf(tx, states, { orgId: org, id }, 'share'));

const hold = () => withSignedStates(app, org, services(), (tx, states) => states.integrityHold(tx, org, 'none'));

const end = (id: string) =>
  withSignedStates(app, org, quiet(), (tx, states) =>
    states.changeStatus(tx, SOURCES, { orgId: org, id }, 'end', {
      actor: OPERATOR,
      action: 'funding_source.ended',
      details: {},
    }),
  );

const guard = (): Promise<string[]> => liveSchemaProblems(app, { ...ROLES, authorityTables: AUTHORITY_TABLES });

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** Denied with the alarm on the source, and the organisation held for it. */
async function deniedAndHeld(id: string, sign: TamperSign): Promise<void> {
  expect(await readSource(id)).toEqual({ outcome: 'tampered', sign });
  expect(lines('audit.integrity_failed')).toEqual([
    expect.objectContaining({
      level: 'error',
      chain: 'organisation',
      check: 'state',
      reason: sign,
      subjectType: 'funding_source',
      objectId: id,
      orgId: org,
    }),
  ]);
  expect(await hold()).toMatchObject({ outcome: 'held' });
  expect(lines('audit.integrity_hold_set')).toEqual([
    expect.objectContaining({ orgId: org, reason: sign, subjectType: 'funding_source' }),
  ]);
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, loggerFor(new LogCapture()));
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(async () => {
  capture = new LogCapture();
  org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  owner = await tamperAsOwner(database, SOURCES, org);
  expect(await guard()).toEqual([]);
});

afterEach(async () => {
  await owner.end();
  expect(await guard()).toEqual([]);
});

describe(`FX-TAMPER as the owner on a funding source: denied by the row check, and held (Postgres ${server.version})`, () => {
  it('an ended source made active again, with the status guard switched off for it', async () => {
    const id = await linkedSource();
    await end(id);
    await owner.withoutStatusGuard(() => owner.setColumn(id, 'status', 'ACTIVE'));

    await deniedAndHeld(id, 'seal');
  });

  it('the live guard sees a wider grant on the links, and the sources’ status guard dropped outright (the S68 audit)', async () => {
    const asOwner = database.as('owner');
    const product = () =>
      liveSchemaProblems(app, {
        ...ROLES,
        authorityTables: AUTHORITY_TABLES,
        statusGuardedTables: AUTHORITY_TABLES.filter((table) => table.rules !== undefined).map(({ table }) => table),
      });
    const [trigger] = await asOwner.query<{ definition: string }>(
      `select pg_catalog.pg_get_triggerdef(oid) as definition from pg_catalog.pg_trigger
        where tgrelid = 'funding_sources.sources'::regclass and tgname = 'status_guard'`,
    );
    await asOwner.query('grant delete on funding_sources.links to agentx_app');
    await asOwner.query('drop trigger status_guard on funding_sources.sources');
    try {
      const found = await product();
      expect(found).toContainEqual(expect.stringMatching(/DELETE on funding_sources\.links/));
      expect(found).toContain('funding_sources.sources carries no status_guard');
    } finally {
      await asOwner.query('revoke delete on funding_sources.links from agentx_app');
      // eslint-disable-next-line agentx/no-string-built-sql -- the trigger's own definition, as Postgres wrote it
      await asOwner.query(trigger?.definition ?? '');
    }
    expect(await product()).toEqual([]);
  });

  it('the partner’s availability rewritten', async () => {
    const id = await linkedSource();
    await owner.setColumn(id, 'availability', 'SUSPENDED');

    await deniedAndHeld(id, 'seal');
  });

  it('pointed at another partner reference', async () => {
    const id = await linkedSource();
    await owner.setColumn(id, 'external_ref', 'fake-source-planted');

    await deniedAndHeld(id, 'seal');
  });

  it('its consent swapped', async () => {
    const id = await linkedSource();
    await owner.setColumn(id, 'account_consent_id', 'fake-consent-planted');

    await deniedAndHeld(id, 'seal');
  });

  it('its consent’s expiry stretched', async () => {
    const id = await linkedSource();
    await owner.setColumn(id, 'consent_expires_at', '2099-01-01T00:00:00Z');

    await deniedAndHeld(id, 'seal');
  });

  it('the bank’s most a payment widened', async () => {
    const id = await linkedSource();
    await owner.setColumn(id, 'max_payment_minor', '999999999999');

    await deniedAndHeld(id, 'seal');
  });

  it('its currency changed', async () => {
    const id = await linkedSource();
    await owner.setColumn(id, 'currency', 'USD');

    await deniedAndHeld(id, 'seal');
  });

  it.each([
    ['partner', 'another_partner'],
    ['availability', 'PENDING'],
    ['consent_status', 'Suspended'],
    ['replaces_consent_id', 'fake-consent-planted'],
    ['limit_period', 'year'],
    ['max_period_minor', '999999999999'],
    ['max_period_payments', 100000],
    ['account_type', 'corporate'],
    ['hint', 'AE…0000'],
    ['partner_changed_at', '2030-01-01T00:00:00Z'],
  ] as const)('its %s changed', async (column, value) => {
    const id = await linkedSource();
    await owner.setColumn(id, column, value);

    await deniedAndHeld(id, 'seal');
  });

  it('moved to another link', async () => {
    const id = await linkedSource();
    const other = ids.next();
    await owner.query(
      "insert into funding_sources.links (org_id, id, started_by, partner, session_ref, expires_at, created_at) values ($1, $2, $3, 'fake', 'fake-link-other', now() + interval '1 day', now())",
      [org, other, ids.next()],
    );
    await owner.setColumn(id, 'link_id', other);

    await deniedAndHeld(id, 'seal');
  });

  it('an ended source rolled back to its saved, validly signed, active state', async () => {
    const id = await linkedSource();
    const saved = await owner.saveRow(id);
    await end(id);
    await owner.withoutStatusGuard(() => owner.restoreRow(saved));

    await deniedAndHeld(id, 'pointer');
  });

  it('deleted, which the app role cannot do', async () => {
    const id = await linkedSource();
    await owner.query(
      'update funding_sources.links set source_id = null, outcome = null, settled_at = null where source_id = $1',
      [id],
    );
    await owner.deleteRow(id);

    await deniedAndHeld(id, 'deleted');
  });

  it('planted with no event: a source no link made', async () => {
    const linkId = ids.next();
    const id = ids.next();
    await owner.query(
      "insert into funding_sources.links (org_id, id, started_by, partner, session_ref, expires_at, created_at) values ($1, $2, $3, 'fake', 'fake-link-planted', now() + interval '1 day', now())",
      [org, linkId, ids.next()],
    );
    await owner.query(
      "insert into funding_sources.sources (org_id, id, link_id, partner, external_ref, status, availability, consent_status, account_consent_id, consent_expires_at, currency, limit_period, max_payment_minor, max_period_minor, max_period_payments, holder_name, account_type, hint, partner_changed_at, created_at) values ($1, $2, $3, 'fake', 'fake-source-planted', 'ACTIVE', 'ACTIVE', 'Authorized', 'fake-consent-planted', now() + interval '1 year', 'AED', 'month', 999999999999, 999999999999, 1000, 'Planted LLC', 'sme', 'AE…0000', now(), now())",
      [org, id, linkId],
    );

    await deniedAndHeld(id, 'unsigned');
  });

  it('a page holding one source rewritten: the whole page refused, not the rest shown (D2-4)', async () => {
    const kept = await linkedSource();
    const id = await linkedSource();
    await owner.setColumn(id, 'availability', 'SUSPENDED');

    const page = await withSignedStates(app, org, services(), (tx, states) =>
      sourcesPage(tx, states, org, { after: null, limit: 50 }),
    );

    expect(page).toEqual({ outcome: 'tampered', sign: 'seal' });
    expect(kept).not.toBe(id);
    expect(await hold()).toMatchObject({ outcome: 'held' });
  });

  it('its events stripped of their seals', async () => {
    const id = await linkedSource();
    await owner.stripSeals(id);

    await deniedAndHeld(id, 'unsigned');
  });

  it('another account’s holder shown', async () => {
    const id = await linkedSource();
    await owner.setColumn(id, 'holder_name', 'Someone Else LLC');

    await deniedAndHeld(id, 'seal');
  });

  it('the app role given DELETE on the sources: the guard names the right', async () => {
    await owner.query('grant delete on funding_sources.sources to agentx_app');
    try {
      expect(await guard()).toEqual(['agentx_app may DELETE on funding_sources.sources']);
    } finally {
      await owner.query('revoke delete on funding_sources.sources from agentx_app');
    }
  });
});
