// Phase 2 B3: accepting a mandate's draft, composed in the API, on the real
// migrated schema as the app role, with a signed agent, a funding source
// linked through the fake partner, signed suppliers and a draft made by the
// registry: an admin asks, signs in again with a passkey and confirms; the
// draft in force, ACTIVE for a first, the next superseding it; the evidence
// on the accept event; every refusal by its code; a step-up that isn't a
// passkey, has run out or was asked for another draft; a tampered mandate of
// the agent; and the lock order against the admin's demotion.
import { createHash } from 'node:crypto';

import { addAgent, AGENTS, type AgentsTables } from '@agentx/core/modules/agents';
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  addLink,
  addSource,
  type FundingSourcesTables,
  settleLink,
  sourceOf,
  updateFromPartner,
} from '@agentx/core/modules/funding-sources';
import {
  addMembership,
  createSessions,
  createStepUpChallenges,
  type IdentityTables,
  type Role,
  userForSubject,
} from '@agentx/core/modules/identity';
import { MANDATES, type MandatesTables } from '@agentx/core/modules/mandates';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createFakeRail, type FundingSourceState } from '@agentx/core/modules/providers';
import { addSupplier, type SuppliersTables } from '@agentx/core/modules/suppliers';
import { money } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  confirmedWhileDemoted,
  createTestDatabase,
  FixedClock,
  LogCapture,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import {
  ACCEPT_CONFIRM_OPERATION,
  ACCEPT_OPERATION,
  type AcceptAsked,
  createMandateAcceptance,
  type MandateAcceptance,
  type MandateAccepted,
} from './mandate-acceptance.ts';
import {
  createMandateRegistry,
  DRAFT_OPERATION,
  type MandateDraft,
  type MandateRegistry,
  type MandateWrite,
  REDRAFT_OPERATION,
} from './mandate-registry.ts';
import type { SessionMember } from './use-case-work.ts';

type Tables = IdentityTables &
  MandatesTables &
  AgentsTables &
  FundingSourcesTables &
  SuppliersTables &
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
const ids = new SequentialIds(0xb3a0_0000_0000);
const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const CORRELATION = '0199a0f0-0000-7000-8000-0000000000b3';
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';
const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const APP_CODE = ['pwd', 'otp', 'mfa'] as const;

let clock: FixedClock;
let registry: MandateRegistry;
let acceptance: MandateAcceptance;

const quiet = () => ({ keys, ids, logger: testLogger() });
const challenges = () => createStepUpChallenges({ ids, clock });

type Member = SessionMember & { readonly membershipId: string };

interface World {
  readonly org: string;
  readonly admin: Member;
  readonly agent: string;
  readonly source: string;
  readonly state: FundingSourceState;
  readonly suppliers: readonly string[];
}

let people = 0;

/** A person with a session and a membership in the organisation. */
async function member(org: string, role: Role): Promise<Member> {
  people += 1;
  const userId = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `mandate-acceptance-${String(people)}` },
    { ids, clock },
  );
  const sessions = createSessions({ ids, clock, timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
  const { sessionId } = await sessions.open(app, userId, {
    idpSessionId: 'V1_1',
    authTime: clock.now(),
    amr: [...PASSKEY],
  });
  const membershipId = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addMembership(tx, states, { orgId: org, id: membershipId, userId, role, joinedAt: clock.now(), actor: OPERATOR }),
  );
  return { orgId: org, userId, sessionId, membershipId };
}

/** An organisation with an admin, an active agent, a source linked through the fake partner, and two suppliers. */
async function world(): Promise<World> {
  const org = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
  );
  const admin = await member(org, 'admin');
  const agent = ids.next();
  await withSignedStates(app, org, quiet(), (tx, states) =>
    addAgent(tx, states, {
      orgId: org,
      id: agent,
      name: 'Purchasing agent',
      owner: admin.membershipId,
      scopes: ['requests:write'],
      createdAt: clock.now(),
      actor: OPERATOR,
    }),
  );
  const rail = createFakeRail({ clock, ids: new SequentialIds(0xfa0_b300_0000) });
  const linkId = ids.next();
  const session = await rail.startSourceLink({ organizationId: org, linkId });
  await rail.bank.approve(org, session.sessionRef, ACCOUNT);
  const answer = await rail.confirmSourceLink({ organizationId: org, linkId });
  if (answer.kind !== 'linked') throw new Error(`not linked: ${answer.kind}`);
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
  const source = ids.next();
  await withSignedStates(app, org, quiet(), async (tx, states) => {
    await addSource(tx, states, {
      orgId: org,
      id: source,
      linkId,
      partner: 'fake',
      state: answer.source,
      createdAt: clock.now(),
      actor: OPERATOR,
    });
    await settleLink(tx, { orgId: org, id: linkId }, { outcome: 'linked', sourceId: source }, clock.now());
  });
  const suppliers = [ids.next(), ids.next()];
  for (const id of suppliers) {
    await withSignedStates(app, org, quiet(), (tx, states) =>
      addSupplier(tx, states, keys, {
        orgId: org,
        id,
        versionId: ids.next(),
        supplier: {
          displayName: 'Gulf Office Supplies LLC',
          contacts: { phone: '+971501234567', email: null, tradeLicence: null },
          source: { kind: 'registry', ref: 'DED-123456' },
        },
        enteredBy: ids.next(),
        createdAt: clock.now(),
        actor: OPERATOR,
      }),
    );
  }
  return { org, admin, agent, source, state: answer.source, suppliers };
}

const AED = (minor: bigint) => money(minor, 'AED');

const termsOf = (w: World, overrides: Partial<MandateDraft['terms']> = {}): MandateDraft['terms'] => {
  const most = w.state.controls.maxPaymentMinor;
  return {
    purpose: 'Office supplies',
    perOrderLimit: AED(most),
    monthlyLimit: AED(most * 2n),
    approvalThreshold: AED(most / 2n),
    supplierIds: [...w.suppliers].sort(),
    fundingSourceId: w.source,
    splitCheck: true,
    consentLimits: 'strict',
    endsAt: null,
    ...overrides,
  };
};

let keysUsed = 0;
const keyed = (who: Member, operation: string): IdempotentRequest => {
  keysUsed += 1;
  return {
    orgId: who.orgId,
    client: { kind: 'user', id: who.userId },
    operation,
    key: `key-${String(keysUsed)}`,
    payload: '{}',
  };
};

const draftedOf = (write: MandateWrite) => {
  if (write.outcome !== 'drafted') throw new Error(`not drafted: ${JSON.stringify(write)}`);
  return write;
};

/** A mandate drafted for the world's agent: its ID and its draft's. */
async function drafted(w: World, overrides: Partial<MandateDraft['terms']> = {}) {
  const write = draftedOf(
    await registry.draft(
      w.admin,
      keyed(w.admin, DRAFT_OPERATION),
      { agentId: w.agent, timeZone: null, splitWindowHours: null, terms: termsOf(w, overrides) },
      CORRELATION,
    ),
  );
  return { id: write.mandate.id, versionId: write.pending?.version.id ?? '' };
}

/** A later draft of the mandate: its ID. */
async function redrafted(w: World, mandateId: string, overrides: Partial<MandateDraft['terms']> = {}) {
  const write = draftedOf(
    await registry.redraft(w.admin, keyed(w.admin, REDRAFT_OPERATION), mandateId, termsOf(w, overrides), CORRELATION),
  );
  return write.pending?.version.id ?? '';
}

const ask = (who: Member, mandateId: string, versionId: string) =>
  acceptance.accept(who, keyed(who, ACCEPT_OPERATION), mandateId, versionId, CORRELATION);

const confirm = (who: Member, mandateId: string, challengeId: string, key?: IdempotentRequest) =>
  acceptance.acceptConfirm(who, key ?? keyed(who, ACCEPT_CONFIRM_OPERATION), mandateId, challengeId, CORRELATION);

const askedFor = (write: AcceptAsked): string => {
  if (write.outcome !== 'asked') throw new Error(`not asked: ${JSON.stringify(write)}`);
  return write.stepUpChallengeId;
};

const acceptedOf = (write: MandateAccepted) => {
  if (write.outcome !== 'accepted') throw new Error(`not accepted: ${JSON.stringify(write)}`);
  return write;
};

const stepUp = (who: Member, challengeId: string, amr: readonly string[] = PASSKEY) =>
  challenges().recordEvidence(app, challengeId, who.sessionId, {
    authTime: clock.now(),
    amr,
    idpSessionId: 'V1_2',
    idTokenHash: createHash('sha256').update('an ID token').digest(),
  });

/** Asks, signs in again with `amr` and confirms: the confirm's answer. */
async function accepted(w: World, mandateId: string, versionId: string, amr: readonly string[] = PASSKEY) {
  const challengeId = askedFor(await ask(w.admin, mandateId, versionId));
  await stepUp(w.admin, challengeId, amr);
  return confirm(w.admin, mandateId, challengeId);
}

const refused = (status: number, code: string) => ({ outcome: 'refused', status, code });

/** The mandate's events, oldest first, with their details read. */
const eventsAbout = async (org: string, mandateId: string) =>
  (
    await withTenant(app, org, (tx) =>
      tx
        .selectFrom('audit.events')
        .select(['action', 'details'])
        .where('subject_type', '=', 'mandate')
        .where('subject_id', '=', mandateId)
        .orderBy('seq')
        .execute(),
    )
  ).map(({ action, details }) => ({ action, details: JSON.parse(details) as Record<string, unknown> }));

/** Moves the mandate by `event`, as B4 will. */
const moved = (w: World, mandateId: string, event: 'suspend' | 'resume' | 'revoke') =>
  withSignedStates(app, w.org, quiet(), (tx, states) =>
    states.changeStatus(tx, MANDATES, { orgId: w.org, id: mandateId }, event, {
      actor: OPERATOR,
      action: `mandate.${event}`,
      details: {},
    }),
  );

/** The source brought up to the partner's answer changed by `change`, as a refresh would. */
async function partnerSays(w: World, change: Partial<FundingSourceState>): Promise<void> {
  const key = { orgId: w.org, id: w.source };
  await withSignedStates(app, w.org, quiet(), async (tx, states) => {
    const read = await sourceOf(tx, states, key, 'change');
    if (read.outcome !== 'found') throw new Error('the source was not found');
    await updateFromPartner(tx, states, key, read, {
      state: { ...w.state, statusChangedAt: clock.now(), ...change },
      actor: OPERATOR,
    });
  });
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  clock = new FixedClock(new Date('2026-10-07T08:00:00Z'));
  const logger = testLogger(new LogCapture());
  registry = createMandateRegistry({ database: app, keys, ids, clock, logger });
  acceptance = createMandateAcceptance({ database: app, keys, ids, clock, challenges: challenges(), logger });
});

describe('accepting a mandate’s draft (B3)', () => {
  it('an admin accepts the first draft with a passkey: ACTIVE, the draft in force, the evidence on its event', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);
    const done = acceptedOf(await confirm(w.admin, id, challengeId));

    expect(done.mandate).toMatchObject({
      status: 'ACTIVE',
      currentVersionId: versionId,
      pendingVersionId: null,
      acceptedBy: w.admin.membershipId,
      acceptedAt: clock.now(),
    });
    expect(done.current?.version.id).toBe(versionId);
    expect(done.pending).toBeNull();
    const events = await eventsAbout(w.org, id);
    expect(events.map(({ action }) => action)).toEqual(['mandate.drafted', 'mandate.accepted', 'mandate.activated']);
    expect(events[1]?.details).toMatchObject({
      versionId,
      replaced: null,
      termsHash: done.current?.version.termsHash,
      stepUpChallengeId: challengeId,
      methods: 'pwd user mfa',
    });
  });

  it('a later draft accepted supersedes the version in force, the mandate staying ACTIVE', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    const second = await redrafted(w, id, { purpose: 'Stationery' });
    const done = acceptedOf(await accepted(w, id, second));

    expect(done.mandate).toMatchObject({ status: 'ACTIVE', currentVersionId: second, pendingVersionId: null });
    expect(done.current?.version).toMatchObject({ version: 2, purpose: 'Stationery' });
    const events = await eventsAbout(w.org, id);
    expect(events.at(-1)).toMatchObject({
      action: 'mandate.accepted',
      details: { versionId: second, replaced: versionId },
    });
  });

  it('answers a confirm retried with its key from the mandate, accepting nothing twice', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);
    const key = keyed(w.admin, ACCEPT_CONFIRM_OPERATION);
    acceptedOf(await confirm(w.admin, id, challengeId, key));

    expect(acceptedOf(await confirm(w.admin, id, challengeId, key)).mandate.status).toBe('ACTIVE');
    expect((await eventsAbout(w.org, id)).filter(({ action }) => action === 'mandate.accepted')).toHaveLength(1);
  });
});

describe('the step-up an acceptance needs (B3, SEC-HA-12)', () => {
  it('refuses a step-up signed in again without a passkey, the draft still waiting', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);

    expect(await accepted(w, id, versionId, APP_CODE)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await registry.show(w.org, id, CORRELATION)).toMatchObject({ mandate: { status: 'PENDING_ACCEPTANCE' } });
  });

  it('refuses a step-up never signed in again for, or run out', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const unsigned = askedFor(await ask(w.admin, id, versionId));
    expect(await confirm(w.admin, id, unsigned)).toEqual(refused(403, 'STEP_UP_FAILED'));

    const late = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, late);
    clock.advanceBy(301_000);
    expect(await confirm(w.admin, id, late)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });

  it('refuses a step-up asked for a draft a newer one has replaced, and an ask naming the replaced one', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);
    await redrafted(w, id, { purpose: 'Stationery' });

    expect(await confirm(w.admin, id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_NOT_WAITING'));
  });
});

describe('the step-up bound to the mandate as it stood (B3)', () => {
  it('refuses a step-up asked before the mandate changed, though its draft is the same: suspended and resumed between', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    const second = await redrafted(w, id);
    const challengeId = askedFor(await ask(w.admin, id, second));
    await stepUp(w.admin, challengeId);
    await moved(w, id, 'suspend');
    await moved(w, id, 'resume');

    expect(await confirm(w.admin, id, challengeId)).toEqual(refused(403, 'STEP_UP_FAILED'));
  });
});

describe('what acceptance refuses (B3)', () => {
  it.each(['approver', 'developer', 'viewer'] as const)('a member who is a %s', async (role) => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    expect(await ask(await member(w.org, role), id, versionId)).toEqual(refused(403, 'FORBIDDEN'));
  });

  it('a mandate none of the organisation’s, or revoked', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    expect(await ask(w.admin, ids.next(), versionId)).toEqual(refused(404, 'NOT_FOUND'));
    await moved(w, id, 'revoke');
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_ENDED'));
  });

  it('a suspended mandate’s new draft, until it is resumed', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    const second = await redrafted(w, id);
    await moved(w, id, 'suspend');

    expect(await ask(w.admin, id, second)).toEqual(refused(409, 'MANDATE_SUSPENDED'));
  });

  it('an ACTIVE mandate with no draft waiting', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    acceptedOf(await accepted(w, id, versionId));
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_NOT_WAITING'));
  });

  it('a suspended agent’s mandate', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    await withSignedStates(app, w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, AGENTS, { orgId: w.org, id: w.agent }, 'suspend', {
        actor: OPERATOR,
        action: 'agent.suspend',
        details: {},
      }),
    );
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'AGENT_NOT_ACTIVE'));
  });

  it('a draft whose end has passed since it was drafted', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w, { endsAt: new Date(clock.now().getTime() + 3_600_000) });
    clock.advanceBy(3_600_000);
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_DRAFT_EXPIRED'));
  });

  it('a draft whose source can no longer fund, or whose consent the bank has since lowered past it', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const most = w.state.controls.maxPaymentMinor;
    await partnerSays(w, { controls: { ...w.state.controls, maxPaymentMinor: most - 1n } });
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'MANDATE_PAST_CONSENT'));

    clock.advanceBy(1000);
    await partnerSays(w, { consentExpiresAt: clock.now() });
    expect(await ask(w.admin, id, versionId)).toEqual(refused(409, 'SOURCE_NOT_USABLE'));
  });

  it('a mandate whose agent was changed past the app: INTEGRITY_FAILED', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const owner = await tamperAsOwner(database, AGENTS, w.org);
    try {
      await owner.setColumn(w.agent, 'scopes', 'requests:read requests:write');
    } finally {
      await owner.end();
    }
    expect(await ask(w.admin, id, versionId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });

  it('any mandate of the agent tampered with, though the open-mandate query missed it (FX-TAMPER, S89 review)', async () => {
    const w = await world();
    const first = await drafted(w);
    const owner = await tamperAsOwner(database, MANDATES, w.org);
    try {
      await owner.query("update mandates.mandates set status = 'REVOKED' where id = $1", [first.id]);
    } finally {
      await owner.end();
    }
    const second = await drafted(w);

    expect(await ask(w.admin, second.id, second.versionId)).toEqual(refused(503, 'INTEGRITY_FAILED'));
  });
});

describe(`the confirm's lock order against the admin's demotion (ADR-006 §6, Postgres ${server.version})`, () => {
  it('holds its step-up challenges before the admin’s membership, so their demotion at the same moment waits, never deadlocks', async () => {
    const w = await world();
    const { id, versionId } = await drafted(w);
    const challengeId = askedFor(await ask(w.admin, id, versionId));
    await stepUp(w.admin, challengeId);

    const done = await confirmedWhileDemoted(
      database,
      { challengeId, orgId: w.org, membershipId: w.admin.membershipId },
      () => confirm(w.admin, id, challengeId),
    );

    expect(acceptedOf(done).mandate.status).toBe('ACTIVE');
  });
});
