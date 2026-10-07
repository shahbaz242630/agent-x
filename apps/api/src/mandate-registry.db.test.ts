// Phase 2 B2: drafting and reading mandates, composed in the API, on the real
// migrated schema as the app role, with a signed agent, a funding source
// linked through the fake partner and signed suppliers: an admin drafts one
// for an active agent with no mandate open, on the organisation's own
// usable source and suppliers, within the bank consent unless flexible;
// every refusal by its code; a retry answered from the mandate; two drafts at
// once (forced); a later draft replacing the one waiting, none for a revoked
// or expired mandate; the day's budget; and every member reads them, a
// source changed since by the bank shown as warnings.
import { AGENTS } from '@agentx/core/modules/agents';
import { withSignedStates } from '@agentx/core/modules/audit';
import { SOURCES } from '@agentx/core/modules/funding-sources';
import { acceptDraft, MANDATE_VERSIONS, mandateOf, MANDATES, MOST_DRAFTS_A_DAY } from '@agentx/core/modules/mandates';
import { createDatabase, type Database, lockName, withTenant } from '@agentx/platform/db';
import {
  createTestDatabase,
  FixedClock,
  holdNamedLock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  waitUntilQueued,
  within,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  createMandateRegistry,
  DRAFT_OPERATION,
  type MandateDraft,
  type MandateRegistry,
  REDRAFT_OPERATION,
} from './mandate-registry.ts';
import {
  AED,
  draftedOf,
  keys,
  type Member,
  mandateWorld,
  type MandateWorldTables,
  OPERATOR,
  refused,
  type World,
} from './mandate-world.helper.test.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<MandateWorldTables>;

const ids = new SequentialIds(0xb2a0_0000_0000);
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b2';

let clock: FixedClock;
let registry: MandateRegistry;

const { quiet, member, world, termsOf, keyed, partnerSays } = mandateWorld({
  app: () => app,
  clock: () => clock,
  ids,
  name: 'mandate-registry',
});

/** A draft within the source's consent, for the world's agent unless another is named. */
const draftOf = (w: World, overrides: Partial<MandateDraft['terms']> = {}, agentId = w.agent): MandateDraft => ({
  agentId,
  timeZone: null,
  splitWindowHours: null,
  terms: termsOf(w, overrides),
});

const draft = (who: Member, given: MandateDraft, key?: string) =>
  registry.draft(who, keyed(who, DRAFT_OPERATION, key), given, CORRELATION);

const redraft = (who: Member, mandateId: string, terms: MandateDraft['terms']) =>
  registry.redraft(who, keyed(who, REDRAFT_OPERATION), mandateId, terms, CORRELATION);

/** Accepts the draft waiting (B3's acceptDraft), then expires the mandate. */
async function acceptedThenExpired(w: World, drafted: ReturnType<typeof draftedOf>): Promise<void> {
  const key = { orgId: w.org, id: drafted.mandate.id };
  const pending = drafted.pending?.version;
  if (pending === undefined) throw new Error('no draft waiting');
  await withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await mandateOf(tx, states, key, 'change');
    if (read.outcome !== 'found') throw new Error('the mandate was not found');
    await acceptDraft(tx, states, read, {
      orgId: w.org,
      versionId: pending.id,
      acceptedBy: pending.draftedBy,
      acceptedAt: clock.now(),
      actor: OPERATOR,
      details: {},
    });
    await states.changeStatus(tx, MANDATES, key, 'expire', { actor: OPERATOR, action: 'mandate.expire', details: {} });
  });
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<MandateWorldTables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-06T08:00:00Z'));
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger: testLogger(new LogCapture()) });
});

describe('drafting a mandate (B2)', () => {
  it('an admin drafts one, waiting for acceptance, answered with its draft and no warning', async () => {
    const w = await world();
    const drafted = draftedOf(await draft(w.admin, draftOf(w)));

    expect(drafted.mandate).toMatchObject({
      agentId: w.agent,
      timeZone: 'Asia/Dubai',
      splitWindowHours: 24,
      status: 'PENDING_ACCEPTANCE',
      currentVersionId: null,
    });
    expect(drafted.current).toBeNull();
    expect(drafted.pending).toMatchObject({ version: { version: 1, purpose: 'Office supplies' }, consentWarnings: [] });
    const actions = await withTenant(app, w.org, (tx) =>
      tx.selectFrom('audit.events').select('action').where('subject_id', '=', drafted.mandate.id).execute(),
    );
    expect(actions).toEqual([{ action: 'mandate.drafted' }]);
  });

  it('keeps the zone and window given', async () => {
    const w = await world();
    const drafted = draftedOf(await draft(w.admin, { ...draftOf(w), timeZone: 'Europe/London', splitWindowHours: 48 }));

    expect(drafted.mandate).toMatchObject({ timeZone: 'Europe/London', splitWindowHours: 48 });
  });

  it('answers a retry from the mandate, drafting nothing twice', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w), 'the-same-key'));
    const again = draftedOf(await draft(w.admin, draftOf(w), 'the-same-key'));

    expect(again.mandate.id).toBe(first.mandate.id);
  });

  it.each(['approver', 'developer', 'viewer'] as const)('refuses a member who is a %s', async (role) => {
    const w = await world();
    expect(await draft(await member(w.org, role), draftOf(w))).toEqual(refused(403, 'FORBIDDEN'));
  });

  it('refuses an agent not the organisation’s, or suspended', async () => {
    const w = await world();
    expect(await draft(w.admin, draftOf(w, {}, ids.next()))).toEqual(refused(404, 'NOT_FOUND'));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspend',
        details: {},
      }),
    );
    expect(await draft(w.admin, draftOf(w))).toEqual(refused(409, 'AGENT_NOT_ACTIVE'));
  });

  it('refuses a second mandate for an agent with one waiting, in force or suspended; one revoked frees it', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));

    expect(await draft(w.admin, draftOf(w))).toEqual(refused(409, 'MANDATE_OPEN'));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, MANDATES, { orgId: w.org, id: first.mandate.id }, 'revoke', {
        actor: OPERATOR,
        action: 'mandate.revoke',
        details: {},
      }),
    );
    draftedOf(await draft(w.admin, draftOf(w)));
  });

  it('refuses to draft past an open mandate tampered with: INTEGRITY_FAILED', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    const owner = await tamperAsOwner(database, MANDATES, w.org);
    try {
      await owner.query(
        "update mandates.mandates set status = 'ACTIVE', current_version_id = pending_version_id, pending_version_id = null, accepted_by = $2, accepted_at = now() where id = $1",
        [first.mandate.id, first.pending?.version.draftedBy],
      );
    } finally {
      await owner.end();
    }

    expect(await draft(w.admin, draftOf(w))).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it('refuses a supplier or a source not the organisation’s', async () => {
    const [w, other] = [await world(), await world()];

    expect(await draft(w.admin, draftOf(w, { supplierIds: [w.suppliers[0] ?? '', other.suppliers[0] ?? ''] }))).toEqual(
      refused(409, 'SUPPLIER_UNKNOWN'),
    );
    expect(await draft(w.admin, draftOf(w, { fundingSourceId: other.source }))).toEqual(
      refused(409, 'SOURCE_NOT_USABLE'),
    );
  });

  it('refuses an end the edge let by that has passed on the server’s clock: 400, not 500', async () => {
    const w = await world();
    expect(await draft(w.admin, draftOf(w, { endsAt: clock.now() }))).toEqual(refused(400, 'BAD_REQUEST'));
  });

  it('refuses a source whose consent has run out, and still shows a mandate drawn on it', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    await partnerSays(w, { consentExpiresAt: clock.now() });

    expect(await redraft(w.admin, first.mandate.id, draftOf(w).terms)).toEqual(refused(409, 'SOURCE_NOT_USABLE'));
    expect(await registry.show(w.org, first.mandate.id, CORRELATION)).toMatchObject({ outcome: 'found' });
  });

  it('refuses a strict mandate past the bank consent, and keeps a flexible one with its warning, in its event too', async () => {
    const w = await world();
    const past = { perOrderLimit: AED(w.maxPayment + 1n), monthlyLimit: AED(w.maxPayment * 2n) };

    expect(await draft(w.admin, draftOf(w, past))).toEqual(refused(409, 'MANDATE_PAST_CONSENT'));
    const kept = draftedOf(await draft(w.admin, draftOf(w, { ...past, consentLimits: 'flexible' })));
    const warning = 'the per-order limit is above the bank consent’s per payment';
    expect(kept.pending?.consentWarnings).toEqual([warning]);
    const events = await withTenant(app, w.org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['action', 'details'])
        .where('subject_id', '=', kept.pending?.version.id ?? '')
        .execute(),
    );
    expect(
      events.map(({ action, details }) => [action, (JSON.parse(details) as Record<string, unknown>).consentWarnings]),
    ).toEqual([['mandate_version.drafted', warning]]);
  });

  it('drafts one of two asked at once for an agent, the other refused, never both (forced: the drafting lock held)', async () => {
    const w = await world();
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName('mandates', w.org));
      const asking = within(
        20_000,
        Promise.all([draft(w.admin, draftOf(w)), draft(w.admin, draftOf(w))]),
        'the drafts',
      );
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('commit');
      const outcomes = (await asking).map((write) => (write.outcome === 'refused' ? write.code : write.outcome));

      expect(outcomes.toSorted()).toEqual(['MANDATE_OPEN', 'drafted']);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
  });
});

describe('drafting a later version (B2)', () => {
  it('replaces the draft waiting, the mandate as it was', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    const second = draftedOf(await redraft(w.admin, first.mandate.id, draftOf(w, { purpose: 'Stationery' }).terms));

    expect(second.mandate).toMatchObject({ id: first.mandate.id, status: 'PENDING_ACCEPTANCE' });
    expect(second.pending).toMatchObject({ version: { version: 2, purpose: 'Stationery' } });
  });

  it('refuses one for a mandate ended, or none of the organisation’s', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, MANDATES, { orgId: w.org, id: first.mandate.id }, 'revoke', {
        actor: OPERATOR,
        action: 'mandate.revoke',
        details: {},
      }),
    );

    expect(await redraft(w.admin, first.mandate.id, draftOf(w).terms)).toEqual(refused(409, 'MANDATE_ENDED'));
    expect(await redraft(w.admin, ids.next(), draftOf(w).terms)).toEqual(refused(404, 'NOT_FOUND'));
  });

  it('refuses one for a mandate expired', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    await acceptedThenExpired(w, first);

    expect(await redraft(w.admin, first.mandate.id, draftOf(w).terms)).toEqual(refused(409, 'MANDATE_ENDED'));
  });

  it(`spends the day's budget of ${String(MOST_DRAFTS_A_DAY)} drafts, and refuses the next until a day has passed`, async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    for (let made = 1; made < MOST_DRAFTS_A_DAY; made += 1) {
      draftedOf(await redraft(w.admin, first.mandate.id, draftOf(w).terms));
    }

    expect(await redraft(w.admin, first.mandate.id, draftOf(w).terms)).toEqual(refused(409, 'MANDATE_DRAFTS_SPENT'));
    clock.advanceBy(24 * 60 * 60 * 1000 + 1);
    draftedOf(await redraft(w.admin, first.mandate.id, draftOf(w).terms));
  }, 60_000);
});

describe('reading mandates (B2)', () => {
  it('lists and shows them to every member', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    const viewer = await member(w.org, 'viewer');

    expect(await registry.list(viewer.orgId, { after: null, limit: 10 }, CORRELATION)).toMatchObject({
      outcome: 'listed',
      mandates: [{ id: first.mandate.id, purpose: 'Office supplies', status: 'PENDING_ACCEPTANCE' }],
      next: null,
    });
    expect(await registry.show(viewer.orgId, first.mandate.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      pending: { version: { version: 1 } },
    });
    expect(await registry.show(viewer.orgId, ids.next(), CORRELATION)).toEqual(refused(404, 'NOT_FOUND'));
  });

  it('refuses to show a mandate whose version or source was changed past the app: INTEGRITY_FAILED', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    const ofSources = await tamperAsOwner(database, SOURCES, w.org);
    try {
      await ofSources.setColumn(w.source, 'holder_name', 'Someone Else LLC');
    } finally {
      await ofSources.end();
    }
    expect(await registry.show(w.org, first.mandate.id, CORRELATION)).toEqual(refused(503, 'INTEGRITY_FAILED'));

    const other = await world();
    const second = draftedOf(await draft(other.admin, draftOf(other)));
    const ofVersions = await tamperAsOwner(database, MANDATE_VERSIONS, other.org);
    try {
      await ofVersions.query('alter table mandates.versions disable trigger made_once');
      await ofVersions.setColumn(second.pending?.version.id ?? '', 'purpose', 'Anything at all');
    } finally {
      await ofVersions.query('alter table mandates.versions enable trigger made_once');
      await ofVersions.end();
    }
    expect(await registry.show(other.org, second.mandate.id, CORRELATION)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it('shows a version whose source’s currency has since changed, the change as its warning', async () => {
    const w = await world();
    const first = draftedOf(await draft(w.admin, draftOf(w)));
    await partnerSays(w, { controls: { ...w.state.controls, currency: 'USD' } });

    expect(await registry.show(w.org, first.mandate.id, CORRELATION)).toMatchObject({
      outcome: 'found',
      pending: { consentWarnings: ['the mandate is not in its funding source’s currency'] },
    });
  });
});
