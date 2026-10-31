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
// - then the checks, in one statement of their own after the locks, never the
//   locking one (4D2d P12; with the mandate's split check on, the payee's
//   reservations in its rolling window, across agents: D5, serialised by the
//   supplier's lock); the
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
import { AGENT_KEYS, agentKeyOf, agentOf, AGENTS, isLiveKey } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { mayFund, SOURCES, sourceOf } from '@agentx/core/modules/funding-sources';
import {
  type LimitReservationsTables,
  lockAgentMonth,
  reserveStatement,
  sealNewZone,
} from '@agentx/core/modules/limit-reservations';
import {
  allowedCurrencyRead,
  MANDATE_VERSIONS,
  openMandateGathered,
  openMandateOfAgent,
  POLICIES,
  POLICY_VERSIONS,
  type PolicyVersionRecord,
} from '@agentx/core/modules/mandates';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS, type OrganizationsTables } from '@agentx/core/modules/organizations';
import {
  decide,
  type DecisionInput,
  decisionFacts,
  decisionInputText,
  type MandateInForce,
  type PolicyRules,
} from '@agentx/core/modules/policies';
import {
  claimAnswered,
  claimStatement,
  totalsWeighed,
  type HeldAs,
  holdsCapacity,
  type ApprovalWaitHours,
  insertRequestStatement,
  LONGEST_APPROVAL_WAIT,
  type NewRequest,
  requestOf,
  sealPayee,
  signRequest,
  type SpendRequestRecord,
  type SpendRequestsTables,
} from '@agentx/core/modules/spend-requests';
import { SUPPLIERS, supplierOf } from '@agentx/core/modules/suppliers';
import { type Clock, type IdGenerator, type Money, money, windowStart } from '@agentx/core/shared-kernel';
import {
  type Database,
  type DatabaseTransaction,
  type GatheredRow,
  type IdempotentRequest,
  isUnwritten,
  noStatementTimes,
  retryingTransaction,
  statementTimesForLog,
  timingStatements,
  sendTogether,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type AgentTurns, createAgentTurns, TurnWaitExceeded } from './agent-turns.ts';
import {
  choicesHistory,
  consentOf,
  organizationChoicesOf,
  overLimitHistories,
  MandateRefused,
  type MandateTables,
  policyRulesIn,
  toldAdminsAndApprovers,
  overLimitOf,
  versionIn,
} from './mandate-reads.ts';
import { consentCeilingOf } from './over-limit-choice.ts';
import { type Refused, refused } from './refused.ts';
import { createUseCaseWork } from './use-case-work.ts';

/** The agent's write, as its idempotency keys name it. */
export const DECIDE_OPERATION = 'spend-requests.create';

export type DecisionTables = MandateTables &
  SpendRequestsTables &
  LimitReservationsTables &
  OrganizationsTables &
  NotificationsTables;
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

/** A policy's version as the engine weighs it; null for none. */
export const versionRules = (version: PolicyVersionRecord | null): PolicyRules | null =>
  version === null ? null : { ...version, versionId: version.id };

/** A policy's version in force as the engine weighs it; null for one never set. */
const rulesOf = (read: { readonly current: PolicyVersionRecord } | null): PolicyRules | null =>
  versionRules(read?.current ?? null);

/** The agent's mandate in force as the engine weighs it, with the zone its months start in and its split window. */
export type MandateWeighed = MandateInForce & { readonly timeZone: string; readonly splitWindowHours: number };

/** A currency the deployment doesn't take is refused: nothing is weighed in it (422). */
/** A read tampered with refuses the request: nothing is decided on what can't be believed. */
const believed = (read: { readonly outcome: string }): void => {
  if (read.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
};

/** A decided request, read and verified for its answer: INTEGRITY_FAILED if tampered with. */
async function answerOf(tx: DecisionTx, states: SignedStates, orgId: string, id: string): Promise<SpendRequestRecord> {
  const found = await requestOf(tx, states, { orgId, id });
  believed(found);
  // Requests are never deleted (0039's grants): one just made, or answered for its key, is there.
  if (found.outcome !== 'found') throw new Error(`A decided spend request is missing: ${id}`);
  return found.request;
}

/** Level 2: the organisation, refused while frozen (ORG_FROZEN). */
export async function notFrozen(tx: DecisionTx, states: SignedStates, orgId: string): Promise<void> {
  // The organisation always exists while its requests can be made.
  const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
  if (organization.outcome !== 'verified') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (organization.fields.get('status') === 'FROZEN') throw new MandateRefused(409, 'ORG_FROZEN');
}

/** Levels 2–3: the organisation not frozen, and the agent. */
export async function agentIn(
  tx: DecisionTx,
  states: SignedStates,
  { orgId, agentId }: { readonly orgId: string; readonly agentId: string },
) {
  await notFrozen(tx, states, orgId);
  return agentAlone(tx, states, { orgId, agentId });
}

/** Level 3: the agent, read FOR SHARE (an approval's, after the organisation and the member's membership: 2a). */
export async function agentAlone(
  tx: DecisionTx,
  states: SignedStates,
  { orgId, agentId }: { readonly orgId: string; readonly agentId: string },
) {
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
 * organisation's, with whether an admin chose its monthly cap (E2). Or the
 * `draft` being accepted in its place, which a carry weighs its pending
 * requests under (E4c).
 */
export async function authorityIn(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  agentId: string,
  version: 'inForce' | 'draft' = 'inForce',
  mandateFound?: { readonly id: string | null },
) {
  const mandate = await mandateWeighedIn(tx, states, orgId, agentId, version, mandateFound);
  return { mandate, ...(await policiesIn(tx, states, orgId, mandate)) };
}

/** Level 4's first half: the agent's open mandate with the version asked for, or null for none; `mandateFound`: its ID as a gather found it. */
export async function mandateWeighedIn(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  agentId: string,
  version: 'inForce' | 'draft' = 'inForce',
  mandateFound?: { readonly id: string | null },
): Promise<MandateWeighed | null> {
  const open = await openMandateOfAgent(tx, states, orgId, agentId, mandateFound);
  believed(open);
  const found = open.outcome === 'found' ? open.mandate : null;
  const versionId = (version === 'draft' ? found?.pendingVersionId : found?.currentVersionId) ?? null;
  if (found === null || versionId === null) return null;
  const read = await versionIn(tx, states, orgId, found.id, versionId);
  // Drafted before E9 (decision 23): no choice, refused as it always was.
  const overLimit = (await overLimitOf(tx, states, orgId, found.id, read.id)) ?? 'refuse';
  return { ...read, ...found, versionId: read.id, overLimit };
}

/**
 * Level 4's second half, after the mandates: the mandate's policy and the
 * organisation's, with whether an admin chose its monthly cap (E2), and the
 * approval wait it chose (E6), from the same read of its version's event. A
 * policy change's confirm (E5d) reads them here once it holds its policy for
 * the change, never before: a row read FOR SHARE isn't raised to change.
 */
export async function policiesIn(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  mandate: { readonly id: string } | null,
): Promise<PoliciesWeighed> {
  const mandatePolicy = mandate === null ? null : rulesOf(await policyRulesIn(tx, states, orgId, mandate.id));
  const organization = await policyRulesIn(tx, states, orgId, orgId);
  return { mandatePolicy, ...(await organizationWeighed(tx, states, orgId, organization?.current ?? null)) };
}

/**
 * The organisation's policies as the engine weighs them under its version
 * `current` (null: never set), with that version's choices: policiesIn's,
 * and the waiting-rejections job's under the version a change replaced (G8b).
 */
export async function organizationWeighed(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  current: PolicyVersionRecord | null,
): Promise<Omit<PoliciesWeighed, 'mandatePolicy'>> {
  const chosen = await organizationChoicesOf(tx, states, orgId, current);
  return {
    organizationPolicy: versionRules(current),
    organizationCapChosen: chosen.capChoice !== null,
    approvalWait: chosen.approvalWait,
  };
}

/**
 * Levels 5 and 6: the source asked for, and the supplier, with the order to
 * look for among the claims once the locks are held. A decision holds the
 * supplier FOR NO KEY UPDATE (`change`), serialising its orders; the simulator FOR SHARE, as all its
 * reads (C4's review): simulations never wait on each other, and a decision
 * waits at most the moment one takes, each person's simulations rate-limited.
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
  if (supplier.outcome !== 'found') return { source, supplier: null, order: null };
  const found = supplier.supplier;
  // The simulator may weigh a request with no order named: no duplicate is then looked for.
  const order =
    asked.orderReference === null
      ? null
      : { supplierId: found.id, payeeKey: found.payeeKey, reference: asked.orderReference };
  return { source, supplier: found, order };
}

/** The policies in force for the agent's mandate, as the engine weighs them. */
export interface PoliciesWeighed {
  readonly organizationPolicy: PolicyRules | null;
  readonly organizationCapChosen: boolean;
  readonly mandatePolicy: PolicyRules | null;
  /** The organisation's chosen approval wait (E6), or null: not chosen, so 72 hours (partner, S119). */
  readonly approvalWait: ApprovalWaitHours | null;
}

/**
 * Levels 4–7 and what the engine weighs, shared with the simulator (C4): the
 * agent's authority, the source and supplier, the agent's month and its
 * total. A decision locks the supplier and the month (`decides`, `monthOf`
 * locking it); the simulator only reads them, and `rules` lets it put
 * proposed policies in place of those in force. `except`: an approval's own
 * request (Phase 3 B4b), whose reservation and claim aren't counted; the split
 * total still counts it, as over the threshold it only asks for an approval.
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
    except,
    mandateFound,
  }: {
    readonly now: Date;
    /** A decision's locks (true), or the simulator's reads (false). */
    readonly decides: boolean;
    readonly monthOf: (zoneIfNew: string) => Promise<string>;
    readonly rules?: (inForce: PoliciesWeighed, mandate: MandateWeighed | null) => PoliciesWeighed;
    /** The request weighed again, whose own reservation and claim aren't counted. */
    readonly except?: string | undefined;
    /** The agent's open mandate's ID as a gather found it (decisionRows). */
    readonly mandateFound?: { readonly id: string | null };
  },
) {
  const { mandate, ...inForce } = await authorityIn(tx, states, orgId, agent.id, 'inForce', mandateFound);
  const policies = rules(inForce, mandate);
  const { source, supplier, order } = await payingIn(tx, states, orgId, asked, decides ? 'change' : 'share');
  // 7: the agent's month, under a mandate: none without one, as nothing is then weighed against it.
  const month = mandate === null ? null : await monthOf(mandate.timeZone);
  // The currency weighed: the mandate's, as its limits are (a request in another is denied by decide).
  const currency = mandate?.perOrderLimit.currency ?? asked.amount.currency;
  // All in one statement, after the supplier's and the month's locks (4D2d P12). The split total only where it is
  // weighed: the mandate's split check on, for a supplier of the organisation's.
  const { spent, split, claims } = await totalsWeighed(tx, {
    month: month === null ? null : { agentId: agent.id, month, currency, except },
    split:
      mandate?.splitCheck === true && supplier !== null
        ? {
            supplierId: supplier.id,
            payeeKey: supplier.payeeKey,
            since: windowStart(now, mandate.splitWindowHours),
            currency,
          }
        : null,
    order: order === null ? null : { ...order, except },
  });
  const input = inputOf({
    asked,
    now,
    agent,
    mandate,
    policies,
    supplier,
    source,
    spent: money(spent, currency),
    split: money(split, currency),
    claims,
  });
  return { input, mandate, supplier, order, month, approvalWait: inForce.approvalWait };
}

/**
 * What the engine weighs, from what was read for it: one builder for a
 * decision (weigh) and a carry's batch (E4c), so the two never weigh apart.
 */
export function inputOf({
  asked,
  now,
  agent,
  mandate,
  policies,
  supplier,
  source,
  spent,
  split,
  claims,
}: {
  readonly asked: SpendWeighed;
  readonly now: Date;
  readonly agent: { readonly id: string; readonly status: string };
  readonly mandate: MandateWeighed | null;
  readonly policies: PoliciesWeighed;
  readonly supplier: { readonly status: string } | null;
  readonly source: Awaited<ReturnType<typeof sourceOf>>;
  readonly spent: Money;
  readonly split: Money;
  readonly claims: { readonly duplicate: boolean; readonly possible: boolean };
}): DecisionInput {
  return {
    request: { amount: asked.amount, supplierId: asked.supplierId, fundingSourceId: asked.fundingSourceId },
    now,
    agent: { id: agent.id, status: agent.status },
    mandate,
    supplierStatus: supplier?.status ?? null,
    sourceMayFund: source.outcome === 'found' && mayFund(source.source, now),
    organizationPolicy: policies.organizationPolicy,
    organizationCapChosen: policies.organizationCapChosen,
    mandatePolicy: policies.mandatePolicy,
    monthSpent: spent,
    splitOpen: split,
    duplicateOrder: claims.duplicate,
    possibleDuplicate: claims.possible,
    consent: source.outcome === 'found' ? consentCeilingOf(consentOf(source.source)) : null,
  };
}

/** Levels 2–3a as a decision reads them, for one gather (4D2d P8): the organisation, the agent, and its key. */
const actingRows = ({ orgId, agentId, keyId }: AgentActing): GatheredRow[] => [
  { table: ORGANIZATIONS, id: { id: orgId }, lock: 'share' },
  { table: AGENTS, id: { id: agentId }, lock: 'share' },
  { table: AGENT_KEYS, id: { id: keyId }, lock: 'share' },
];

/** Where decisionRows puts the rows other rows, and the decision, read by. */
const AT = { mandate: 0, version: 1, mandatePolicy: 2, organizationPolicy: 4, organizationVersion: 5 } as const;

/**
 * Levels 4–6 as a decision reads them, for one gather after actingRows, so
 * the mandate is found once its agent is held, as before: the agent's open
 * mandate (0) and its version in force, the mandate's policy (2) and its
 * version, the organisation's (4) and its version, the source, and the
 * supplier, held for its orders.
 */
const decisionRows = (orgId: string, agentId: string, asked: SpendWeighed): GatheredRow[] => [
  openMandateGathered(agentId),
  { table: MANDATE_VERSIONS, id: { from: AT.mandate, column: 'current_version_id' }, lock: 'share' },
  { table: POLICIES, id: { sameAs: AT.mandate }, lock: 'share' },
  { table: POLICY_VERSIONS, id: { from: AT.mandatePolicy, column: 'current_version_id' }, lock: 'share' },
  { table: POLICIES, id: { id: orgId }, lock: 'share' },
  { table: POLICY_VERSIONS, id: { from: AT.organizationPolicy, column: 'current_version_id' }, lock: 'share' },
  { table: SOURCES, id: { id: asked.fundingSourceId }, lock: 'share' },
  { table: SUPPLIERS, id: { id: asked.supplierId }, lock: 'change' },
];

export function createSpendRequestDecisions({
  database,
  outbox,
  keys,
  ids,
  clock,
  logger,
  turns = createAgentTurns(),
}: {
  readonly database: Database<DecisionTables>;
  /** Where a request waiting for approval is told, in its decision's own transaction (Phase 3 B2). */
  readonly outbox: Outbox;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** Whose decisions may hold a connection now, in this process (agent-turns.ts); the race suites' own, unqueued. */
  readonly turns?: AgentTurns;
}): SpendRequestDecisions {
  // The mandates' refusal: the decision reads mandates, versions and policies through their reads.
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  /** Everything in the lock order, the decision, and what it makes: the request's ID, with its decision. */
  async function decided(
    tx: DecisionTx,
    states: SignedStates,
    acting: AgentActing,
    idempotencyKey: string,
    asked: SpendAskedByAgent,
  ): Promise<{ readonly id: string; readonly answer: SpendRequestRecord } & Pick<NewRequest, 'decision' | 'reasons'>> {
    const { orgId, agentId } = acting;
    // Read before the lock waits below (each at most 5 s), so a request can be weighed seconds past a mandate's
    // `endsAt`; the sealed instant is this one, so the evidence shows it as it was weighed.
    const now = clock.now();
    // Each level's rows in one statement, in the lock order (4D2d P8): the reads below answer from them. The
    // currency's read and the acting rows on one trip (P17); what is refused on them is refused here, before the
    // supplier's lock below is asked for, so a request refused anyway never queues on it.
    const currency = await states.gatherBehind(
      tx,
      orgId,
      allowedCurrencyRead(tx, asked.amount.currency),
      actingRows(acting),
    );
    if (currency.rows.length === 0) throw new MandateRefused(422, 'CURRENCY_NOT_ALLOWED');
    const { agent, keyId } = await actingIn(tx, states, acting, now);
    const found = await states.gather(tx, orgId, decisionRows(orgId, agentId, asked));
    const mandateId = found[AT.mandate] ?? null;
    const versionId = found[AT.version] ?? null;
    const policyVersionId = found[AT.organizationVersion] ?? null;
    // Their histories in one statement too, once their rows are held, as before.
    await states.gatherHistories(tx, orgId, [
      ...(mandateId === null || versionId === null ? [] : overLimitHistories(mandateId, versionId)),
      ...(policyVersionId === null ? [] : [choicesHistory(policyVersionId)]),
    ]);
    // The agent's zone, when this is its first decision: sealed with the request, as the audit head comes last.
    let zoneKept: string | undefined;
    const { input, mandate, supplier, order, month, approvalWait } = await weigh(tx, states, orgId, agent, asked, {
      now,
      decides: true,
      mandateFound: { id: mandateId },
      monthOf: async (zoneIfNew) => {
        const locked = await lockAgentMonth(tx, states, { orgId, agentId, zoneIfNew, at: now });
        if (locked.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
        if (locked.keptNow) zoneKept = zoneIfNew;
        return locked.month;
      },
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
      weighed: decisionFacts(input),
      decision: made.decision,
      reasons: made.reasons,
      // The wait in force now, sealed with it: a later change moves it never (decision 20); 72 until chosen (S119).
      approvalWait: approvalWait ?? LONGEST_APPROVAL_WAIT,
      createdAt: now,
    };

    let held: HeldAs | null = null;
    if (!holdsCapacity(made.decision)) {
      await insertRequestStatement(tx, request).execute();
    } else {
      // Capacity is held only on a mandate in force, by a supplier of the organisation's (decide's checks).
      if (mandate === null || month === null || order === null) throw new Error('capacity held with nothing weighed');
      const claim = { ...order, orgId, id: ids.next(), requestId, claimedAt: now };
      // One trip, in this order: each needs the one before it, and a failure in one fails those behind it.
      const [, , claimAnswer] = await sendTogether(tx, [
        insertRequestStatement(tx, request),
        reserveStatement(tx, {
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
        }),
        claimStatement(tx, claim),
      ]);
      const claimed = await claimAnswered(tx, claim, claimAnswer.rows.length === 1);
      // The supplier held and its payee key its own alone: see the top of this file.
      if (claimed === 'taken') throw new Error(`An order held by its supplier was claimed meanwhile: ${requestId}`);
      held = { month, reservedAt: now, payee: sealPayee(keys, { orgId, requestId, payeeKey: order.payeeKey }) };
    }
    if (zoneKept !== undefined) {
      await sealNewZone(tx, states, {
        orgId,
        agentId,
        zone: zoneKept,
        at: now,
        actor: { type: 'agent', id: agent.id },
      });
    }
    // Every admin and approver is told it waits (partner decision 2, Phase 3); the email reads it as it is sent.
    // Told before it is signed, so the chain head, whose lock comes last, is held one statement less (4D2d P8).
    if (made.decision === 'REQUIRE_APPROVAL') {
      await outbox.add(tx, toldAdminsAndApprovers(orgId, 'spend_request_waiting', requestId));
    }
    const answer = await signRequest(tx, states, request, { type: 'agent', id: agent.id }, held);
    return { id: requestId, answer, decision: made.decision, reasons: made.reasons };
  }

  return {
    async decideAndReserve(agent, idempotent, asked, correlationId) {
      const log = logger.child({ correlationId, orgId: agent.orgId });
      // Each attempt sets it; only the one that committed is returned, so it is that attempt's decision.
      let made: Awaited<ReturnType<typeof decided>> | undefined;
      let fresh: SpendRequestRecord | undefined;
      // The whole decision, its turn's wait, lock waits and retries too, for the Pilot's policy target (PL-38).
      const started = performance.now();
      // Where its time goes (4D2d): logged with it, so a slow one can be read on Azure.
      const times = noStatementTimes();
      let turnWaitMs = 0;
      const attempt = () =>
        work.write(agent, idempotent, correlationId, async (tx, states) => {
          made = await decided(tx, states, agent, idempotent.key, asked);
          fresh = made.answer;
          return { status: 201, resourceId: made.id };
        });
      // In its agent's turn, so a burst from one agent can't hold every connection while it waits on its month.
      let done: Awaited<ReturnType<typeof work.write>>;
      try {
        done = await turns.run(agent.agentId, () => {
          turnWaitMs = performance.now() - started;
          return timingStatements(times, () => retryingTransaction(log, DECIDE_OPERATION, attempt));
        });
      } catch (error) {
        if (!(error instanceof TurnWaitExceeded)) throw error;
        // Nothing of it was made, its key unclaimed: the agent sends it again (partner, S161: busy, never a 500).
        log.warn('spend_request.agent_busy', { agentId: agent.agentId, waitedMs: error.waitedMs });
        return refused(503, 'AGENT_BUSY');
      }
      if (isUnwritten(done)) return done;
      // Once a decision is committed, and once only (never for its key's replay), from the write itself, so a
      // failed read after it can't lose it (E2a review): the denial-surge alert counts these lines per agent
      // (E2). The audit chain is the record; this is the signal.
      if (done.outcome === 'done' && made !== undefined) {
        log.info('spend_request.decided', {
          agentId: agent.agentId,
          decision: made.decision,
          reasons: made.reasons.join(' '),
          durationMs: Math.round(performance.now() - started),
          turnWaitMs: Math.round(turnWaitMs),
          ...statementTimesForLog(times),
        });
      }
      // A fresh decision answers as its own transaction sealed it (4D2d P4 and P8, partner decision 2);
      // a replay of its key reads it in a transaction of its own, as it is now.
      if (done.outcome === 'done' && fresh !== undefined) return { outcome: 'decided' as const, request: fresh };
      return work.answered(agent.orgId, correlationId, async (tx, states) => ({
        outcome: 'decided' as const,
        request: await answerOf(tx, states, agent.orgId, done.result.resourceId),
      }));
    },
  };
}
