// The mandates' database tests' shared world (Phase 2 B4; S89's simplify
// review): an organisation with an admin, an active agent, a funding source
// linked through the fake partner and two signed suppliers, the people and
// keys the use cases take, a mandate drafted and accepted, the step-up's
// sign-in, and the reads the tests make of them. A helper,
// not a test: Vitest leaves `*.helper.test.ts` out (vitest.config.ts), and
// the name keeps it with the tests, which alone may import @agentx/testing.
import { createHash, randomBytes } from 'node:crypto';

import { addAgent, addAgentKey, agentKeyText, type AgentsTables, keySecretMessage } from '@agentx/core/modules/agents';
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
import { acceptDraft, mandateOf, MANDATES, type MandatesTables } from '@agentx/core/modules/mandates';
import type { NotificationsTables } from '@agentx/core/modules/notifications';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createFakeRail, type FundingSourceState } from '@agentx/core/modules/providers';
import { addSupplier, supplierOf, type SuppliersTables, verifySupplier } from '@agentx/core/modules/suppliers';
import { DAY_MS, money } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { type FixedClock, SequentialIds, testLogger } from '@agentx/testing';

import { DRAFT_OPERATION, type MandateDraft, type MandateRegistry, type MandateWrite } from './mandate-registry.ts';
import type { SessionMember } from './use-case-work.ts';

export type MandateWorldTables = IdentityTables &
  MandatesTables &
  AgentsTables &
  FundingSourcesTables &
  SuppliersTables &
  OrganizationsTables &
  DirectoryTables &
  NotificationsTables &
  AuditTables;

export const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
export const OPERATOR = { type: 'system' as const, id: 'test-operator' };
export const PASSKEY = ['pwd', 'user', 'mfa'] as const;
const ACCOUNT = 'sme-rak-trading-emirati-acct-01';

export type Member = SessionMember & { readonly membershipId: string };

export interface World {
  readonly org: string;
  readonly admin: Member;
  readonly agent: string;
  readonly source: string;
  /** The source's consent per payment, in fils. */
  readonly maxPayment: bigint;
  /** The source as the partner answered it when linked. */
  readonly state: FundingSourceState;
  readonly suppliers: readonly string[];
}

export const AED = (minor: bigint) => money(minor, 'AED');

export const refused = (status: number, code: string) => ({ outcome: 'refused', status, code });

/** The step-up an ask answered with. */
export const askedFor = (write: { readonly outcome: string; readonly stepUpChallengeId?: string }): string => {
  if (write.outcome !== 'asked' || write.stepUpChallengeId === undefined) {
    throw new Error(`not asked: ${JSON.stringify(write)}`);
  }
  return write.stepUpChallengeId;
};

export const draftedOf = (write: MandateWrite) => {
  if (write.outcome !== 'drafted') throw new Error(`not drafted: ${JSON.stringify(write)}`);
  return write;
};

/**
 * The world's makers and reads for one test file: `app` and `clock` are read
 * at each call, as the file sets them in its hooks; `name` keeps its people's
 * subjects apart from another file's.
 */
export function mandateWorld({
  app,
  clock,
  ids,
  name,
}: {
  readonly app: () => Database<MandateWorldTables>;
  readonly clock: () => FixedClock;
  readonly ids: SequentialIds;
  readonly name: string;
}) {
  const quiet = () => ({ keys, ids, logger: testLogger() });
  let people = 0;
  let keysUsed = 0;

  /** A person with a session (signed in with a passkey) and a membership in the organisation. */
  async function member(org: string, role: Role): Promise<Member> {
    people += 1;
    const userId = await userForSubject(
      app(),
      { issuer: 'https://auth.example.test', subject: `${name}-${String(people)}` },
      { ids, clock: clock() },
    );
    const sessions = createSessions({ ids, clock: clock(), timeouts: { idleSeconds: 1800, absoluteSeconds: 43_200 } });
    const { sessionId } = await sessions.open(app(), userId, {
      idpSessionId: 'V1_1',
      authTime: clock().now(),
      amr: [...PASSKEY],
    });
    const membershipId = ids.next();
    await withSignedStates(app(), org, quiet(), (tx, states) =>
      addMembership(tx, states, {
        orgId: org,
        id: membershipId,
        userId,
        role,
        joinedAt: clock().now(),
        actor: OPERATOR,
      }),
    );
    return { orgId: org, userId, sessionId, membershipId };
  }

  /** An organisation with an admin, an active agent, a source linked through the fake partner, and two suppliers. */
  async function world(): Promise<World> {
    const now = clock().now();
    const org = ids.next();
    await withSignedStates(app(), org, quiet(), (tx, states) =>
      createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR }),
    );
    const admin = await member(org, 'admin');
    const agent = ids.next();
    await withSignedStates(app(), org, quiet(), (tx, states) =>
      addAgent(tx, states, {
        orgId: org,
        id: agent,
        name: 'Purchasing agent',
        owner: admin.membershipId,
        scopes: ['requests:write'],
        createdAt: now,
        actor: OPERATOR,
      }),
    );
    // Each world's partner is a fake of its own, so its IDs may repeat another world's.
    const rail = createFakeRail({ clock: clock(), ids: new SequentialIds(0xfa0_0000_0000) });
    const linkId = ids.next();
    const session = await rail.startSourceLink({ organizationId: org, linkId });
    await rail.bank.approve(org, session.sessionRef, ACCOUNT);
    const answer = await rail.confirmSourceLink({ organizationId: org, linkId });
    if (answer.kind !== 'linked') throw new Error(`not linked: ${answer.kind}`);
    await withTenant(app(), org, (tx) =>
      addLink(tx, {
        orgId: org,
        id: linkId,
        startedBy: ids.next(),
        partner: 'fake',
        sessionRef: session.sessionRef,
        expiresAt: session.expiresAt,
        createdAt: now,
      }),
    );
    const source = ids.next();
    await withSignedStates(app(), org, quiet(), async (tx, states) => {
      await addSource(tx, states, {
        orgId: org,
        id: source,
        linkId,
        partner: 'fake',
        state: answer.source,
        createdAt: now,
        actor: OPERATOR,
      });
      await settleLink(tx, { orgId: org, id: linkId }, { outcome: 'linked', sourceId: source }, now);
    });
    const suppliers = [ids.next(), ids.next()];
    for (const id of suppliers) {
      await withSignedStates(app(), org, quiet(), (tx, states) =>
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
          createdAt: now,
          actor: OPERATOR,
        }),
      );
    }
    const maxPayment = answer.source.controls.maxPaymentMinor;
    return { org, admin, agent, source, maxPayment, state: answer.source, suppliers };
  }

  /** Terms within the source's consent: the per-order limit what it allows per payment. */
  const termsOf = (w: World, overrides: Partial<MandateDraft['terms']> = {}): MandateDraft['terms'] => ({
    purpose: 'Office supplies',
    perOrderLimit: AED(w.maxPayment),
    monthlyLimit: AED(w.maxPayment * 2n),
    approvalThreshold: AED(w.maxPayment / 2n),
    supplierIds: [...w.suppliers].sort(),
    fundingSourceId: w.source,
    splitCheck: true,
    consentLimits: 'strict',
    endsAt: null,
    ...overrides,
  });

  /** A write's idempotency key: a fresh one unless named. */
  const keyed = (who: SessionMember | Member, operation: string, key?: string): IdempotentRequest => {
    keysUsed += 1;
    return {
      orgId: who.orgId,
      client: { kind: 'user', id: who.userId },
      operation,
      key: key ?? `key-${String(keysUsed)}`,
      payload: '{}',
    };
  };

  /** The source brought up to the partner's answer changed by `change`, as a refresh would. */
  async function partnerSays(w: World, change: Partial<FundingSourceState>): Promise<void> {
    const key = { orgId: w.org, id: w.source };
    await withSignedStates(app(), w.org, quiet(), async (tx, states) => {
      const read = await sourceOf(tx, states, key, 'change');
      if (read.outcome !== 'found') throw new Error('the source was not found');
      await updateFromPartner(tx, states, key, read, {
        state: { ...w.state, statusChangedAt: clock().now(), ...change },
        actor: OPERATOR,
      });
    });
  }

  /** The object's events (a mandate's unless named), oldest first, with their details read. */
  const eventsAbout = async (org: string, objectId: string, subject = 'mandate') =>
    (
      await withTenant(app(), org, (tx) =>
        tx
          .selectFrom('audit.events')
          .select(['action', 'actor_type', 'details'])
          .where('subject_type', '=', subject)
          .where('subject_id', '=', objectId)
          .orderBy('seq')
          .execute(),
      )
    ).map(({ action, actor_type, details }) => ({
      action,
      actorType: actor_type,
      details: JSON.parse(details) as Record<string, unknown>,
    }));

  /** The organisation's notices, as the outbox holds them. */
  const noticesOf = (org: string) =>
    withTenant(app(), org, (tx) =>
      tx.selectFrom('notifications.outbox').select(['kind', 'about_id', 'recipient_user_id']).orderBy('id').execute(),
    );

  /** A mandate drafted by the registry for the world's agent: its ID and its draft's. */
  async function drafted(registry: MandateRegistry, w: World, overrides: Partial<MandateDraft['terms']> = {}) {
    const write = draftedOf(
      await registry.draft(
        w.admin,
        keyed(w.admin, DRAFT_OPERATION),
        { agentId: w.agent, timeZone: null, splitWindowHours: null, terms: termsOf(w, overrides) },
        'test-correlation',
      ),
    );
    return { id: write.mandate.id, versionId: write.pending?.version.id ?? '' };
  }

  /** The draft waiting made the version in force (B3's acceptDraft, past the use case): ACTIVE, for a first. */
  async function acceptedPastTheUseCase(w: World, mandateId: string): Promise<void> {
    const key = { orgId: w.org, id: mandateId };
    await withSignedStates(app(), w.org, quiet(), async (tx, states) => {
      const read = await mandateOf(tx, states, key, 'change');
      if (read.outcome !== 'found') throw new Error('the mandate was not found');
      const versionId = read.mandate.pendingVersionId;
      if (versionId === null) throw new Error('no draft waiting');
      await acceptDraft(tx, states, read, {
        orgId: w.org,
        versionId,
        acceptedBy: w.admin.membershipId,
        acceptedAt: clock().now(),
        actor: OPERATOR,
        details: {},
      });
    });
  }

  /** A mandate drafted for the world's agent and accepted: ACTIVE. Its ID. */
  async function inForce(registry: MandateRegistry, w: World, overrides: Partial<MandateDraft['terms']> = {}) {
    const { id } = await drafted(registry, w, overrides);
    await acceptedPastTheUseCase(w, id);
    return id;
  }

  /** The supplier verified by the world's admin, as E3 does. */
  const verified = (w: World, id: string) =>
    withSignedStates(app(), w.org, quiet(), async (tx, states) => {
      const found = await supplierOf(tx, states, { orgId: w.org, id }, 'change');
      if (found.outcome !== 'found') throw new Error(`not found: ${found.outcome}`);
      await verifySupplier(tx, states, { orgId: w.org, id }, found, {
        verifiedBy: w.admin.membershipId,
        actor: OPERATOR,
      });
    });

  /** A second agent of the world's organisation with a mandate in force on `terms` and a key: acting as it. */
  async function secondAgent(registry: MandateRegistry, w: World, terms: Partial<MandateDraft['terms']> = {}) {
    const other = ids.next();
    await withSignedStates(app(), w.org, quiet(), (tx, states) =>
      addAgent(tx, states, {
        orgId: w.org,
        id: other,
        name: 'Second purchasing agent',
        owner: w.admin.membershipId,
        scopes: ['requests:write'],
        createdAt: clock().now(),
        actor: OPERATOR,
      }),
    );
    const theirs = { ...w, agent: other };
    await inForce(registry, theirs, terms);
    return agentKey(theirs);
  }

  /** The mandate moved by `event`, past the use cases. */
  const movedPastTheUseCase = (w: World, id: string, event: 'suspend' | 'resume' | 'revoke' | 'expire') =>
    withSignedStates(app(), w.org, quiet(), (tx, states) =>
      states.changeStatus(tx, MANDATES, { orgId: w.org, id }, event, {
        actor: OPERATOR,
        action: `mandate.${event}`,
        details: {},
      }),
    );

  /**
   * A key of the agent (the world's unless named), live for 90 days: as the
   * agent's key check finds it, with its text as the agent sends it.
   */
  async function agentKey(
    w: World,
    agentId = w.agent,
  ): Promise<{ orgId: string; agentId: string; keyId: string; text: string }> {
    const keyId = ids.next();
    const secret = randomBytes(32);
    const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(keyId, secret));
    await withSignedStates(app(), w.org, quiet(), (tx, states) =>
      addAgentKey(tx, states, {
        orgId: w.org,
        id: keyId,
        agentId,
        scopes: ['requests:write'],
        secretMac: mac,
        secretKeyVersion: keyVersion,
        expiresAt: new Date(clock().now().getTime() + 90 * DAY_MS),
        createdAt: clock().now(),
        actor: OPERATOR,
      }),
    );
    return { orgId: w.org, agentId, keyId, text: agentKeyText(keyId, secret) };
  }

  /** The member signs in again for the step-up, by `amr`: a passkey unless named. */
  const stepUp = (who: Member, challengeId: string, amr: readonly string[] = PASSKEY) =>
    createStepUpChallenges({ ids, clock: clock() }).recordEvidence(app(), challengeId, who.sessionId, {
      authTime: clock().now(),
      amr,
      idpSessionId: 'V1_2',
      idTokenHash: createHash('sha256').update('an ID token').digest(),
    });

  return {
    quiet,
    member,
    world,
    termsOf,
    keyed,
    partnerSays,
    eventsAbout,
    noticesOf,
    drafted,
    acceptedPastTheUseCase,
    inForce,
    movedPastTheUseCase,
    agentKey,
    verified,
    secondAgent,
    stepUp,
  };
}
