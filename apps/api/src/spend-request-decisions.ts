// Deciding a spend request and reserving its capacity, in one transaction
// (ADR-006 §6–§11; PRD §4.2, §5.2; BR-06–BR-09, BR-22; partner decisions 2, 4
// and 5; Phase 2 D4): the agent's request weighed by the decision engine
// against what the organisation gave it, recorded with its decision and
// moved by it, and, when it holds capacity (ALLOW or REQUIRE_APPROVAL), its
// reservation and its order claim made with it. The agent's route comes with
// D4r.
//
// Lock order (ADR-006 §6), each read through its signed state:
// - 0: the idempotency key (the work's write);
// - 2: the organisation FOR SHARE, refused while FROZEN (ORG_FROZEN: nothing
//   made, the key unused, ADR-007 §4);
// - 3, 3a: the agent and the key it came with FOR SHARE, the key live and
//   the agent's (UNAUTHENTICATED: a revocation committed first wins);
// - 4: the agent's open mandate and its version in force, then the mandate's
//   policy and the organisation's, FOR SHARE;
// - 5: the source the agent named FOR SHARE;
// - 6: the supplier FOR NO KEY UPDATE, serialising the duplicate check;
// - 7: the agent's month FOR NO KEY UPDATE, serialising the monthly check
//   (decision 4: the agent's, under all its mandates);
// - then the checks, each a statement of its own after the locks; the
//   request (8); its reservation and claim (11); its two signed events (12).
//
// Whatever the organisation can't give (no mandate, another organisation's
// supplier or source, a suspended agent) is still a request, decided DENY or
// REQUIRE_NEW_MANDATE with its reasons and moved to DENIED: the agent learns
// why, and the evidence keeps it. Only what can't be recorded is refused
// with nothing made: a currency the deployment doesn't take, a frozen
// organisation, a key no longer live, anything tampered with.
//
// The whole transaction is tried again after a deadlock or a serialisation
// failure (A2). Its claim never finds the order taken: the supplier's lock
// serialises its own orders, and no two suppliers hold one payee key at once
// (0033's `one_supplier_a_payee`), a key moving only by a change of the
// supplier holding it, which that lock waits for. So a claim taken meanwhile
// is something past the app, and fails the request (D3's `taken`).
import { agentKeyOf, agentOf, isLiveKey } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { mayFund, sourceOf } from '@agentx/core/modules/funding-sources';
import {
  type LimitReservationsTables,
  lockAgentMonth,
  monthSpent,
  reserve,
} from '@agentx/core/modules/limit-reservations';
import { currencyAllowed, openMandateOfAgent, type PolicyVersionRecord } from '@agentx/core/modules/mandates';
import { ORGANIZATIONS, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  decide,
  type DecisionInput,
  decisionInputText,
  type MandateInForce,
  type PolicyRules,
} from '@agentx/core/modules/policies';
import {
  claimOrder,
  hasOpenClaim,
  holdsCapacity,
  insertRequest,
  type NewRequest,
  requestOf,
  signRequest,
  type SpendRequestRecord,
  type SpendRequestsTables,
} from '@agentx/core/modules/spend-requests';
import { supplierOf } from '@agentx/core/modules/suppliers';
import { type Clock, type IdGenerator, type Money, money } from '@agentx/core/shared-kernel';
import {
  type Database,
  type DatabaseTransaction,
  type IdempotentRequest,
  isUnwritten,
  retryingTransaction,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { MandateRefused, type MandateTables, policyRulesIn, versionIn } from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork } from './use-case-work.ts';

/** The agent's write, as its idempotency keys name it. */
export const DECIDE_OPERATION = 'spend-requests.create';

export type DecisionTables = MandateTables & SpendRequestsTables & LimitReservationsTables & OrganizationsTables;
type DecisionTx = DatabaseTransaction<DecisionTables>;

/** The agent acting, as its key's check found it (D4r's access hook). */
export interface AgentActing {
  readonly orgId: string;
  readonly agentId: string;
  /** The key the request came with: kept on the request as evidence. */
  readonly keyId: string;
}

/** A request as the engine weighs it: the simulator's may name no order. */
export interface SpendWeighed {
  readonly amount: Money;
  readonly supplierId: string;
  readonly fundingSourceId: string;
  /** The supplier's own invoice or order number, as written (decision 6); null: none named, none checked. */
  readonly orderReference: string | null;
}

/** What the agent asks to pay, its edge checks passed (D4r). */
export interface SpendAskedByAgent extends SpendWeighed {
  readonly orderReference: string;
  readonly purpose: string;
}

export type SpendRequestDecided =
  | { readonly outcome: 'decided'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface SpendRequestDecisions {
  decideAndReserve(
    agent: AgentActing,
    idempotent: IdempotentRequest,
    asked: SpendAskedByAgent,
    correlationId: string,
  ): Promise<SpendRequestDecided>;
}

/** A policy's version in force as the engine weighs it; null for one never set. */
const rulesOf = (read: { readonly current: PolicyVersionRecord } | null): PolicyRules | null =>
  read === null ? null : { ...read.current, versionId: read.current.id };

/** The agent's mandate in force as the engine weighs it, with the zone its months start in. */
export type MandateWeighed = MandateInForce & { readonly timeZone: string };

/** A currency the deployment doesn't take is refused: nothing is weighed in it (422). */
export async function currencyTaken(tx: DecisionTx, currency: string): Promise<void> {
  if (!(await currencyAllowed(tx, currency))) throw new MandateRefused(422, 'CURRENCY_NOT_ALLOWED');
}

/** A read tampered with refuses the request: nothing is decided on what can't be believed. */
const believed = (read: { readonly outcome: string }): void => {
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
};

/** Levels 2–3: the organisation not frozen, and the agent. */
export async function agentIn(
  tx: DecisionTx,
  states: SignedStates,
  { orgId, agentId }: { readonly orgId: string; readonly agentId: string },
) {
  // The organisation always exists while its requests can be made.
  const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
  if (organization.outcome !== 'verified') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (organization.fields.get('status') === 'FROZEN') throw new MandateRefused(409, 'ORG_FROZEN');
  const agent = await agentOf(tx, states, { orgId, id: agentId }, 'share');
  believed(agent);
  // A key's check, or a mandate's own row, found it, and agents are never deleted (0019's grants).
  if (agent.outcome !== 'found') throw new Error(`An agent is missing: ${agentId}`);
  return agent.agent;
}

/** Levels 2–3a: the organisation not frozen, the agent, and the key it came with, still live and its own. */
async function actingIn(tx: DecisionTx, states: SignedStates, acting: AgentActing, now: Date) {
  const agent = await agentIn(tx, states, acting);
  const key = await agentKeyOf(tx, states, { orgId: acting.orgId, id: acting.keyId }, 'share');
  believed(key);
  if (key.outcome !== 'found' || key.key.agentId !== agent.id || !isLiveKey(key.key, now)) {
    throw new MandateRefused(401, 'UNAUTHENTICATED');
  }
  return { agent, keyId: key.key.id };
}

/**
 * Level 4: the agent's open mandate with its version in force (a draft grants
 * nothing) and the zone its months start in, then the mandate's policy and the
 * organisation's.
 */
async function authorityIn(tx: DecisionTx, states: SignedStates, orgId: string, agentId: string) {
  const open = await openMandateOfAgent(tx, states, orgId, agentId);
  believed(open);
  let mandate: MandateWeighed | null = null;
  if (open.outcome === 'found' && open.mandate.currentVersionId !== null) {
    const version = await versionIn(tx, states, orgId, open.mandate.id, open.mandate.currentVersionId);
    mandate = { ...version, ...open.mandate, versionId: version.id };
  }
  const mandatePolicy = mandate === null ? null : rulesOf(await policyRulesIn(tx, states, orgId, mandate.id));
  const organizationPolicy = rulesOf(await policyRulesIn(tx, states, orgId, orgId));
  return { mandate, mandatePolicy, organizationPolicy };
}

/**
 * Levels 5 and 6: the source asked for, and the supplier, with whether its
 * order is claimed already. A decision holds the supplier FOR NO KEY UPDATE
 * (`change`), serialising its orders; the simulator only FOR SHARE, so it
 * never queues a decision behind it (C4's review).
 */
async function payingIn(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  asked: SpendWeighed,
  supplierLock: 'share' | 'change',
) {
  const source = await sourceOf(tx, states, { orgId, id: asked.fundingSourceId }, 'share');
  believed(source);
  const supplier = await supplierOf(tx, states, { orgId, id: asked.supplierId }, supplierLock);
  believed(supplier);
  if (supplier.outcome !== 'found') return { source, supplier: null, order: null, duplicateOrder: false };
  // The simulator may weigh a request with no order named: no duplicate is then looked for.
  if (asked.orderReference === null) return { source, supplier: supplier.supplier, order: null, duplicateOrder: false };
  const order = {
    supplierId: supplier.supplier.id,
    payeeKey: supplier.supplier.payeeKey,
    reference: asked.orderReference,
  };
  return { source, supplier: supplier.supplier, order, duplicateOrder: await hasOpenClaim(tx, order) };
}

/** The policies in force for the agent's mandate, as the engine weighs them. */
export interface PoliciesWeighed {
  readonly organizationPolicy: PolicyRules | null;
  readonly mandatePolicy: PolicyRules | null;
}

/**
 * Levels 4–7 and what the engine weighs, shared with the simulator (C4): the
 * agent's authority, the source and supplier, the agent's month and its
 * total. A decision locks the supplier and the month (`decides`, `monthOf`
 * locking it); the simulator only reads them, and `rules` lets it put
 * proposed policies in place of those in force.
 */
export async function weigh(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  agent: { readonly id: string; readonly status: string },
  asked: SpendWeighed,
  {
    now,
    decides,
    monthOf,
    rules = (inForce) => inForce,
  }: {
    readonly now: Date;
    /** A decision's locks (true), or the simulator's reads (false). */
    readonly decides: boolean;
    readonly monthOf: (zoneIfNew: string) => Promise<string>;
    readonly rules?: (inForce: PoliciesWeighed, mandate: MandateWeighed | null) => PoliciesWeighed;
  },
) {
  const { mandate, ...inForce } = await authorityIn(tx, states, orgId, agent.id);
  const { mandatePolicy, organizationPolicy } = rules(inForce, mandate);
  const { source, supplier, order, duplicateOrder } = await payingIn(
    tx,
    states,
    orgId,
    asked,
    decides ? 'change' : 'share',
  );
  // 7: the agent's month, under a mandate: none without one, as nothing is then weighed against it.
  const month = mandate === null ? null : await monthOf(mandate.timeZone);
  const spent = month === null ? 0n : await monthSpent(tx, { agentId: agent.id, month });
  const currency = mandate?.perOrderLimit.currency ?? asked.amount.currency;
  const input: DecisionInput = {
    request: { amount: asked.amount, supplierId: asked.supplierId, fundingSourceId: asked.fundingSourceId },
    now,
    agent: { id: agent.id, status: agent.status },
    mandate,
    supplierStatus: supplier?.status ?? null,
    sourceMayFund: source.outcome === 'found' && mayFund(source.source, now),
    organizationPolicy,
    mandatePolicy,
    monthSpent: money(spent, currency),
    // The split aggregate comes with D5: until then no split order is counted.
    splitOpen: money(0n, currency),
    duplicateOrder,
  };
  return { input, mandate, supplier, order, month };
}

export function createSpendRequestDecisions({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Database<DecisionTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): SpendRequestDecisions {
  // The mandates' refusal: the decision reads mandates, versions and policies through their reads.
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  /** Everything in the lock order, the decision, and what it makes: the request's ID. */
  async function decided(
    tx: DecisionTx,
    states: SignedStates,
    acting: AgentActing,
    idempotencyKey: string,
    asked: SpendAskedByAgent,
  ): Promise<string> {
    const { orgId, agentId } = acting;
    const now = clock.now();
    await currencyTaken(tx, asked.amount.currency);
    const { agent, keyId } = await actingIn(tx, states, acting, now);
    const { input, mandate, supplier, order, month } = await weigh(tx, states, orgId, agent, asked, {
      now,
      decides: true,
      monthOf: (zoneIfNew) => lockAgentMonth(tx, { orgId, agentId, zoneIfNew, at: now }),
    });
    const made = decide(input);
    const requestId = ids.next();
    const hash = keys.mac('decision-hash', [
      'spend-request-decision',
      orgId.toLowerCase(),
      requestId,
      decisionInputText(input),
    ]);
    const request: NewRequest = {
      orgId,
      id: requestId,
      agentId: agent.id,
      agentKeyId: keyId,
      mandate: mandate === null ? null : { id: mandate.id, versionId: mandate.versionId },
      organizationPolicyVersionId: made.versions.organizationPolicy,
      mandatePolicyVersionId: made.versions.mandatePolicy,
      supplierId: asked.supplierId.toLowerCase(),
      supplierVersionId: supplier?.currentVersionId ?? null,
      fundingSourceId: asked.fundingSourceId.toLowerCase(),
      amount: asked.amount,
      purpose: asked.purpose,
      orderReference: asked.orderReference,
      idempotencyKey,
      inputHash: Buffer.from(hash.mac).toString('hex'),
      inputHashKeyVersion: hash.keyVersion,
      decision: made.decision,
      reasons: made.reasons,
      createdAt: now,
    };

    await insertRequest(tx, request);
    if (holdsCapacity(made.decision)) {
      // Capacity is held only on a mandate in force, by a supplier of the organisation's (decide's checks).
      if (mandate === null || month === null || order === null) throw new Error('capacity held with nothing weighed');
      await reserve(tx, {
        orgId,
        id: ids.next(),
        requestId,
        agentId: agent.id,
        mandateId: mandate.id,
        month,
        supplierId: order.supplierId,
        payeeKey: order.payeeKey,
        amountMinor: asked.amount.minor,
        currency: asked.amount.currency,
        reservedAt: now,
      });
      const claimed = await claimOrder(tx, { ...order, orgId, id: ids.next(), requestId, claimedAt: now });
      // The supplier held and its payee key its own alone: see the top of this file.
      if (claimed === 'taken') throw new Error(`An order held by its supplier was claimed meanwhile: ${requestId}`);
    }
    await signRequest(tx, states, request, { type: 'agent', id: agent.id });
    return requestId;
  }

  return {
    async decideAndReserve(agent, idempotent, asked, correlationId) {
      const done = await retryingTransaction(logger.child({ correlationId }), DECIDE_OPERATION, () =>
        work.write(agent, idempotent, correlationId, async (tx, states) => ({
          status: 201,
          resourceId: await decided(tx, states, agent, idempotent.key, asked),
        })),
      );
      if (isUnwritten(done)) return done;
      return work.answered(agent.orgId, correlationId, async (tx, states) => {
        const found = await requestOf(tx, states, { orgId: agent.orgId, id: done.result.resourceId });
        believed(found);
        // Requests are never deleted (0039's grants): one just made, or answered for its key, is there.
        if (found.outcome !== 'found') throw new Error(`A decided spend request is missing: ${done.result.resourceId}`);
        return { outcome: 'decided' as const, request: found.request };
      });
    },
  };
}
