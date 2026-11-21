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
// - 1a, 1b, 1c: the organisation's, the agent's and the source's brakes, shared,
//   so any stop or change of them waiting goes first (PL-63 item 3, 4D2e C3;
//   tenant.ts);
// - 2: the organisation FOR SHARE, refused while FROZEN (ORG_FROZEN: nothing
//   made, the key unused, ADR-007 §4);
// - 3, 3a: the agent and the key it came with FOR SHARE, the key live and
//   the agent's (UNAUTHENTICATED: a revocation committed first wins);
// - 4: the agent's open mandate and its version in force, then the mandate's
//   policy and the organisation's, FOR SHARE;
// - 5: the source the agent named FOR SHARE, then the agent's zone, if it has one;
// - 6: the supplier FOR NO KEY UPDATE, alone, after all a request can be refused
//   on, so a request refused anyway never queues on it (4D2e C6), serialising the
//   duplicate check; then the agent's zone added, on its first decision under a
//   mandate, so one stuck on this supplier holds up none of its others (PL-62);
// - 7: the agent's month FOR NO KEY UPDATE, serialising the monthly check
//   (decision 4: the agent's, under all its mandates);
// - then the checks, in one statement of their own after the locks, never the
//   locking one, on the month's lock's trip (4D2d P12, 4D2e C7), with the
//   month's signed total (11a, GM-1a) and the payee's signed split windows
//   (11b, GM-1b: what its reservations across agents hold, hour by hour; the
//   split weighed from them with the mandate's split check on, D5) gathered
//   for change behind them, though new rows no one else holds come before
//   them in the order: the request (8); its reservation and claim (11); then
//   the total's, the windows' and its own signed events, in one step (12).
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
import type { AlongsideChange, AuditTables, SignedStates } from '@agentx/core/modules/audit';
import { mayFund, SOURCES, sourceOf } from '@agentx/core/modules/funding-sources';
import {
  AGENT_ZONES,
  heldAdded,
  hourOf,
  keptFromHour,
  keptZoneOf,
  type LimitReservationsTables,
  MONTH_TOTALS,
  monthTotalId,
  type MonthTotalKey,
  monthTotalOf,
  monthTotalsCutOver,
  monthTotalToSend,
  type Payee,
  type PayeeWindowCheck,
  payeeWindowId,
  payeeWindowKeys,
  payeeWindowsCutOver,
  payeeWindowsOf,
  payeeWindowToSend,
  reserveStatement,
  sealNewZone,
  splitHeldIn,
  windowFromHour,
  zoneInForce,
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
  type DecisionMonthTotal,
  type DecisionWindows,
  monthLockedAndTotalsWeighed,
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
import { supplierOf } from '@agentx/core/modules/suppliers';
import { type Clock, type IdGenerator, type Money, money, periodOf } from '@agentx/core/shared-kernel';
import {
  AGENT_BRAKE,
  brakeShared,
  type Database,
  type DatabaseTransaction,
  type GatheredRow,
  type IdempotentRequest,
  isUnwritten,
  noStatementTimes,
  ORGANISATION_BRAKE,
  retryingTransaction,
  statementTimesForLog,
  timedLock,
  timedSupplierLock,
  timingStatements,
  sendTogether,
  SOURCE_BRAKE,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { TurnWaitExceeded } from './agent-turns.ts';
import { createDecisionEntry, type DecisionEntry, type EntryWaits, SupplierTurnExceeded } from './decision-entry.ts';
import { DecisionGateRefused } from './decision-gate.ts';
import { EVERY_LINE, type LogSample, timersKept } from './log-sample.ts';
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

/**
 * A request as it stands once written, or answered for its key (a decision, an
 * approval, a reject, a cancel): read and verified for its answer,
 * INTEGRITY_FAILED if tampered with. `written` names it in the error for one
 * missing ("A decided spend request").
 */
export async function answerOf(
  tx: DatabaseTransaction<SpendRequestsTables & AuditTables>,
  states: SignedStates,
  { orgId, id }: { readonly orgId: string; readonly id: string },
  written: string,
): Promise<SpendRequestRecord> {
  const found = await requestOf(tx, states, { orgId, id });
  believed(found);
  // Requests are never deleted (0039's grants): one just written, or answered for its key, is there.
  if (found.outcome !== 'found') throw new Error(`${written} is missing: ${id}`);
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

/** Level 5: the source asked for. */
async function sourceIn(tx: DecisionTx, states: SignedStates, orgId: string, asked: SpendWeighed) {
  const source = await sourceOf(tx, states, { orgId, id: asked.fundingSourceId }, 'share');
  believed(source);
  return source;
}

/**
 * Level 6: the supplier, with the order to look for among the claims once the
 * locks are held. A decision or an approval holds it FOR NO KEY UPDATE (`change`), serialising its orders; the
 * simulator FOR SHARE, as all its reads (C4's review): simulations never wait on each other, and a decision
 * waits at most the moment one takes, each person's simulations rate-limited.
 */
async function supplierIn(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  asked: SpendWeighed,
  supplierLock: 'share' | 'change',
) {
  const supplier = await supplierOf(tx, states, { orgId, id: asked.supplierId }, supplierLock);
  believed(supplier);
  if (supplier.outcome !== 'found') return { supplier: null, order: null };
  const found = supplier.supplier;
  // The simulator may weigh a request with no order named: no duplicate is then looked for.
  const order =
    asked.orderReference === null
      ? null
      : { supplierId: found.id, payeeKey: found.payeeKey, reference: asked.orderReference };
  return { supplier: found, order };
}

/** What weigh and a decision read for the engine, once the locks they each take are held. */
interface ReadToWeigh {
  readonly asked: SpendWeighed;
  readonly now: Date;
  readonly agent: { readonly id: string; readonly status: string };
  readonly mandate: MandateWeighed | null;
  readonly policies: PoliciesWeighed;
  readonly source: Awaited<ReturnType<typeof sourceOf>>;
  readonly supplier: Awaited<ReturnType<typeof supplierIn>>['supplier'];
  readonly order: Awaited<ReturnType<typeof supplierIn>>['order'];
  readonly month: string | null;
  readonly except?: string | undefined;
}

/** The currency weighed: the mandate's, as its limits are (a request in another is denied by decide). */
const currencyWeighed = ({ mandate, asked }: ReadToWeigh): string =>
  mandate?.perOrderLimit.currency ?? asked.amount.currency;

/**
 * What to read in one statement after the supplier's and the month's locks (4D2d P12), and the payee's split windows
 * (GM-1b): whose (a supplier of the organisation's, under a mandate, which alone may hold capacity), and from which
 * hour they are weighed, only where the split is weighed (the mandate's split check on), else null.
 */
function totalsToWeigh(read: ReadToWeigh) {
  const { now, agent, mandate, supplier, order, month, except } = read;
  const currency = currencyWeighed(read);
  return {
    month: month === null ? null : { agentId: agent.id, month, currency, except },
    order: order === null ? null : { ...order, except },
    payee:
      supplier === null || month === null ? null : { supplierId: supplier.id, payeeKey: supplier.payeeKey, currency },
    splitFrom: mandate?.splitCheck === true && supplier !== null ? windowFromHour(now, mandate.splitWindowHours) : null,
  };
}

/** The engine's input from what was read and those totals: one way for a decision and for weigh, so the two never weigh apart. */
function inputWith(
  read: ReadToWeigh,
  { spent, split, claims }: Awaited<ReturnType<typeof totalsWeighed>> & { readonly split: bigint },
): DecisionInput {
  const currency = currencyWeighed(read);
  return inputOf({ ...read, spent: money(spent, currency), split: money(split, currency), claims });
}

/**
 * What the payee's window holds from `fromHour` on (null: the split not weighed, nothing), from its signed windows
 * (GM-1b), read as asked in order of ID with `alsoLocked` (an approval's own sealed windows, which its reject gives
 * back to: never locked after these out of order): the simulator's (`share`), an approval's (for change at its
 * confirm), a carry's. A window that can't be believed is INTEGRITY_FAILED; one missing holds nothing once the
 * organisation is cut over, and is ORGANISATION_BUSY before.
 */
export async function splitWeighed(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  { payee, fromHour }: { readonly payee: Payee | null; readonly fromHour: number | null },
  lock: 'share' | 'change',
  alsoLocked: readonly string[] = [],
): Promise<bigint> {
  if (payee === null || fromHour === null) return 0n;
  const rows = await payeeWindowsRead(tx, states, orgId, [payee], lock, alsoLocked);
  return splitHeldIn(known(rows.get(payeeText(payee))), fromHour);
}

/** A payee's key as text, to find its rows by. */
export const payeeText = ({ supplierId, payeeKey, currency }: Payee): string =>
  `${supplierId.toLowerCase()}|${payeeKey ?? ''}|${currency}|${payeeKey === null ? 'none' : 'key'}`;

/**
 * Each payee's windows (payeeWindowKeys' order), with `alsoLocked`, read as asked in one pass in order of ID: by
 * payeeText. INTEGRITY_FAILED for any that can't be believed; one missing holds nothing once the organisation is cut
 * over (one look at its log for all), ORGANISATION_BUSY before.
 */
export async function payeeWindowsRead(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  payees: readonly Payee[],
  lock: 'share' | 'change',
  alsoLocked: readonly string[] = [],
): Promise<ReadonlyMap<string, readonly PayeeWindowCheck[]>> {
  const idsOf = (payee: Payee) => payeeWindowKeys(payee).map((key) => payeeWindowId(orgId, key));
  const read = await payeeWindowsOf(tx, states, orgId, [...payees.flatMap(idsOf), ...alsoLocked], lock);
  const checks = [...read.values()];
  if (checks.some(({ outcome }) => outcome === 'tampered')) throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (checks.some(({ outcome }) => outcome === 'none')) {
    const counted = await payeeWindowsCutOver(tx, states, orgId);
    if (counted === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    if (counted === 'not_yet') throw new MandateRefused(503, 'ORGANISATION_BUSY');
  }
  return new Map(payees.map((payee) => [payeeText(payee), idsOf(payee).map((id) => known(read.get(id)))]));
}

/** A value a read above answers for what it was asked: one missing is something past the app. */
const known = <Value>(value: Value | undefined): Value => {
  if (value === undefined) throw new MandateRefused(503, 'INTEGRITY_FAILED');
  return value;
};

/** The policies in force for the agent's mandate, as the engine weighs them. */
export interface PoliciesWeighed {
  readonly organizationPolicy: PolicyRules | null;
  readonly organizationCapChosen: boolean;
  readonly mandatePolicy: PolicyRules | null;
  /** The organisation's chosen approval wait (E6), or null: not chosen, so 72 hours (partner, S119). */
  readonly approvalWait: ApprovalWaitHours | null;
}

/**
 * Levels 4–7 and what the engine weighs, for the simulator (C4) and an approval
 * (a decision reads its own, on fewer trips, and weighs by the same totalsToWeigh and inputWith): the
 * agent's authority, the source and supplier, the agent's month. An approval
 * locks the supplier and the month (`decides`, `monthOf` locking it); the
 * simulator only reads them, and `rules` lets it put proposed policies in
 * place of those in force. `except`: an approval's own request (Phase 3 B4b),
 * whose claim isn't counted; the split total still counts it, as over the
 * threshold it only asks for an approval. The month's signed total and the
 * payee's signed split windows are the caller's to read and hand to
 * `inputWith` (monthSpentWeighed, GM-1a; splitWeighed with `split`, GM-1b):
 * an approval may read them only once its request is locked.
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
  }: {
    readonly now: Date;
    /** An approval's locks (true), or the simulator's reads (false). */
    readonly decides: boolean;
    readonly monthOf: (zoneIfNew: string) => Promise<string>;
    readonly rules?: (inForce: PoliciesWeighed, mandate: MandateWeighed | null) => PoliciesWeighed;
    /** The request weighed again, whose own reservation and claim aren't counted. */
    readonly except?: string | undefined;
  },
) {
  const { mandate, ...inForce } = await authorityIn(tx, states, orgId, agent.id);
  const policies = rules(inForce, mandate);
  const source = await sourceIn(tx, states, orgId, asked);
  const { supplier, order } = await supplierIn(tx, states, orgId, asked, decides ? 'change' : 'share');
  // 7: the agent's month, under a mandate: none without one, as nothing is then weighed against it.
  const month = mandate === null ? null : await monthOf(mandate.timeZone);
  const read = { asked, now, agent, mandate, policies, source, supplier, order, month, except };
  // The claims now; the month's signed total and the payee's windows by the caller (GM-1a, GM-1b): an approval reads
  // them only once its request is locked (8), as they come after it in the lock order (11a, 11b).
  const toWeigh = totalsToWeigh(read);
  const others = await totalsWeighed(tx, { ...toWeigh, month: null });
  return {
    inputWith: (spent: bigint, split: bigint) => inputWith(read, { ...others, spent, split }),
    totalOf: month === null ? null : { agentId: agent.id, month, currency: currencyWeighed(read) },
    split: { payee: toWeigh.payee, fromHour: toWeigh.splitFrom },
    mandate,
    supplier,
    order,
    month,
    approvalWait: inForce.approvalWait,
  };
}

/**
 * The keys a month's total is made under (0110): its ID, and its agent, month and currency; and a payee window's
 * (0112): its ID, and its supplier, key and currency.
 */
const TOTAL_KEYS: ReadonlySet<unknown> = new Set([
  'month_totals_pkey',
  'one_total_a_month',
  'payee_windows_pkey',
  'one_window_a_payee',
]);

/**
 * A month's total or a payee window made by another while this decision read it empty (its organisation's cutover
 * committing just then, GM-1a review): ORGANISATION_BUSY, so the agent asks again and is weighed against it. Any
 * other error as it was.
 */
export function totalMadeMeanwhile(error: unknown): unknown {
  const pg = error as { readonly code?: unknown; readonly constraint?: unknown } | null;
  return pg?.code === '23505' && TOTAL_KEYS.has(pg.constraint) ? new MandateRefused(503, 'ORGANISATION_BUSY') : error;
}

/**
 * What a decision weighs once its supplier is held: its month's lock and the totals on one trip, each its own
 * statement, so the totals see what its holder committed: the month's the signed total (GM-1a) and the split window
 * the payee's signed windows (GM-1b), each locked for the change a capacity held makes to it. Under no mandate, no
 * month: the claims alone, nothing held.
 */
async function decisionWeighed(tx: DecisionTx, states: SignedStates, orgId: string, read: ReadToWeigh) {
  const toWeigh = totalsToWeigh(read);
  if (toWeigh.month === null) {
    return { totals: { ...(await totalsWeighed(tx, toWeigh)), split: 0n }, monthTotal: null, windows: [] };
  }
  const weighed = await monthLockedAndTotalsWeighed(
    tx,
    states,
    { orgId, at: read.now, payee: toWeigh.payee },
    { ...toWeigh, month: toWeigh.month },
  );
  const monthTotal = monthTotalWeighed(weighed.monthTotal);
  const windows = windowsWeighed(weighed.windows);
  const split =
    toWeigh.splitFrom === null
      ? 0n
      : splitHeldIn(
          windows.map(({ read: row }) => row),
          toWeigh.splitFrom,
        );
  return { totals: { ...weighed, spent: monthTotal.spent, split }, monthTotal, windows };
}

/** A decision's payee windows as read, each with what it is written from (GM-1b). */
type WindowsWeighed = Extract<DecisionWindows, { readonly outcome: 'read' }>['rows'];

/** A decision's payee windows as weighed: refused while any can't be believed, or before its organisation's cutover. */
function windowsWeighed(windows: DecisionWindows): WindowsWeighed {
  if (windows.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (windows.outcome === 'busy') throw new MandateRefused(503, 'ORGANISATION_BUSY');
  return windows.rows;
}

/** A decision's month's total as weighed: refused while it can't be believed, or before its organisation's cutover. */
function monthTotalWeighed(
  total: DecisionMonthTotal,
): Extract<DecisionMonthTotal, { readonly outcome: 'held' | 'none' }> {
  if (total.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (total.outcome === 'busy') throw new MandateRefused(503, 'ORGANISATION_BUSY');
  return total;
}

/**
 * What the agent's month holds, from its signed total (GM-1a), for weigh's
 * callers, locked as asked: the simulator's (`share`), an approval's (for
 * change at its confirm, which may reject it), a carry's. `own`: what the
 * requests weighed again hold there, already in the total, left out (the
 * engine adds each one's amount itself). A total that can't be believed, or
 * holding less than they do, is INTEGRITY_FAILED (the latter alarmed); one
 * missing holds nothing once the organisation is cut over (then, with `own`,
 * a total gone without a trace: alarmed), and is ORGANISATION_BUSY before.
 */
export async function monthSpentWeighed(
  tx: DecisionTx,
  states: SignedStates,
  orgId: string,
  key: MonthTotalKey,
  lock: 'share' | 'change',
  own = 0n,
): Promise<bigint> {
  const total = await monthTotalOf(tx, states, orgId, key, lock);
  if (total.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  const short = () => {
    states.mismatch(MONTH_TOTALS.subject, { orgId, id: monthTotalId(orgId, key) });
    return new MandateRefused(503, 'INTEGRITY_FAILED');
  };
  if (total.outcome === 'held') {
    if (total.held < own) throw short();
    return total.held - own;
  }
  const cutOver = await monthTotalsCutOver(tx, states, orgId);
  if (cutOver === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  if (cutOver === 'not_yet') throw new MandateRefused(503, 'ORGANISATION_BUSY');
  if (own > 0n) throw short();
  return 0n;
}

/**
 * What the engine weighs, from what was read for it: one builder for a
 * decision, weigh and a carry's batch (E4c), so they never weigh apart.
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
 * Levels 4–5 as a decision reads them, for one gather after actingRows, so
 * the mandate is found once its agent is held, as before: the agent's open
 * mandate (0) and its version in force, the mandate's policy (2) and its
 * version, the organisation's (4) and its version, the source, and the agent's
 * zone. Never the supplier: what is refused on these is refused before its queue.
 */
const decisionRows = (orgId: string, agentId: string, asked: SpendWeighed): GatheredRow[] => [
  openMandateGathered(agentId),
  { table: MANDATE_VERSIONS, id: { from: AT.mandate, column: 'current_version_id' }, lock: 'share' },
  { table: POLICIES, id: { sameAs: AT.mandate }, lock: 'share' },
  { table: POLICY_VERSIONS, id: { from: AT.mandatePolicy, column: 'current_version_id' }, lock: 'share' },
  { table: POLICIES, id: { id: orgId }, lock: 'share' },
  { table: POLICY_VERSIONS, id: { from: AT.organizationPolicy, column: 'current_version_id' }, lock: 'share' },
  { table: SOURCES, id: { id: asked.fundingSourceId }, lock: 'share' },
  { table: AGENT_ZONES, id: { id: agentId }, lock: 'share' },
];

/**
 * Each level's rows up to the supplier's in one statement, in the lock order (4D2d P8), for the reads after it to answer
 * from, and their histories. The brakes, the currency's read and the acting rows on one trip (P17), each its own
 * statement: a brake waited for behind a freeze or a kill switch comes before the acting rows' snapshot, so they read
 * what it did (S157). All before the supplier's lock, so a request refused on any of it never queues there.
 */
async function rowsBeforeTheSupplier(
  tx: DecisionTx,
  states: SignedStates,
  acting: AgentActing,
  asked: SpendWeighed,
  now: Date,
) {
  const { orgId, agentId } = acting;
  const {
    ahead: [, , , currency],
  } = await states.gatherBehind(
    tx,
    orgId,
    [
      brakeShared(ORGANISATION_BRAKE, orgId),
      brakeShared(AGENT_BRAKE, orgId, agentId),
      brakeShared(SOURCE_BRAKE, orgId, asked.fundingSourceId),
      allowedCurrencyRead(tx, asked.amount.currency),
    ],
    actingRows(acting),
  );
  if (currency.rows.length === 0) throw new MandateRefused(422, 'CURRENCY_NOT_ALLOWED');
  const { agent, keyId } = await actingIn(tx, states, acting, now);
  const found = await timedLock('decisionRowsMs', () => states.gather(tx, orgId, decisionRows(orgId, agentId, asked)));
  const mandateId = found[AT.mandate] ?? null;
  const versionId = found[AT.version] ?? null;
  const policyVersionId = found[AT.organizationVersion] ?? null;
  await states.gatherHistories(tx, orgId, [
    ...(mandateId === null || versionId === null ? [] : overLimitHistories(mandateId, versionId)),
    ...(policyVersionId === null ? [] : [choicesHistory(policyVersionId)]),
  ]);
  return { agent, keyId, mandateId };
}

export function createSpendRequestDecisions({
  database,
  outbox,
  keys,
  ids,
  clock,
  logger,
  entry = createDecisionEntry(),
  logSample = EVERY_LINE,
}: {
  readonly database: Database<DecisionTables>;
  /** Where a request waiting for approval is told, in its decision's own transaction (Phase 3 B2). */
  readonly outbox: Outbox;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** Which decisions may hold a connection now, in this process (decision-entry.ts); the race suites' own, unqueued. */
  readonly entry?: DecisionEntry;
  /** Which decisions' lines say where their time went (log-sample.ts); the line itself is always written. All when not given. */
  readonly logSample?: LogSample;
}): SpendRequestDecisions {
  // The mandates' refusal: the decision reads mandates, versions and policies through their reads.
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  /**
   * The request inserted with its reservation, order claim and month's total (its amount added, GM-1a), all on one
   * trip, in this order: each needs the one before it, and a failure in one fails those behind it. What its decision
   * seals of them, and the total's change to sign with it.
   */
  async function capacityHeld(
    tx: DecisionTx,
    states: SignedStates,
    request: NewRequest,
    {
      mandateId,
      month,
      order,
      monthTotal,
      windows: payeeRows,
    }: {
      readonly mandateId: string;
      readonly month: string;
      readonly order: NonNullable<ReadToWeigh['order']>;
      readonly monthTotal: Extract<DecisionMonthTotal, { readonly outcome: 'held' | 'none' }>;
      readonly windows: WindowsWeighed;
    },
  ): Promise<{ readonly held: HeldAs; readonly alongside: readonly AlongsideChange[] }> {
    const { orgId, id: requestId, amount, createdAt: now } = request;
    // In the cap's currency alone, as decide denies any other (CURRENCY_NOT_ALLOWED).
    if (monthTotal.key.currency !== amount.currency) throw new Error('capacity held in another currency');
    const claim = { ...order, orgId, id: ids.next(), requestId, claimedAt: now };
    const total = monthTotalToSend(
      tx,
      states,
      orgId,
      monthTotal.key,
      monthTotal.total,
      monthTotal.spent + amount.minor,
      now,
    );
    // Its amount added at its own hour to each of its payee's windows (GM-1b), the hours no window counts let go.
    const hour = hourOf(now);
    const keptFrom = keptFromHour(now);
    const windows = payeeRows.map(({ key, read }) =>
      payeeWindowToSend(
        tx,
        states,
        orgId,
        key,
        read,
        heldAdded(read.outcome === 'held' ? read.held : new Map(), hour, amount.minor, keptFrom),
        now,
      ),
    );
    const changes = [total, ...windows];
    const [, , claimAnswer, ...changeAnswers] = await sendTogether(tx, [
      insertRequestStatement(tx, request),
      reserveStatement(tx, {
        orgId,
        id: ids.next(),
        requestId,
        agentId: request.agentId,
        mandateId,
        month,
        supplierId: order.supplierId,
        payeeKey: order.payeeKey,
        amountMinor: amount.minor,
        currency: amount.currency,
        reservedAt: now,
      }),
      claimStatement(tx, claim),
      ...changes.flatMap(({ statements }) => statements),
    ]);
    const claimed = await claimAnswered(tx, claim, claimAnswer.rows.length === 1);
    // The supplier held and its payee key its own alone: see the top of this file.
    if (claimed === 'taken') throw new Error(`An order held by its supplier was claimed meanwhile: ${requestId}`);
    // Each change's write is the last of its statements: its answer is the row it left.
    let at = 0;
    const alongside = changes.map(({ statements, sent }, index): AlongsideChange => {
      at += statements.length;
      return {
        sent,
        rows: (changeAnswers[at - 1]?.rows ?? []) as readonly Readonly<Record<string, unknown>>[],
        change: {
          actor: { type: 'agent', id: request.agentId },
          action: index === 0 ? 'month_total.held' : 'payee_window.held',
          details: { requestId: requestId.toLowerCase(), amountMinor: amount.minor.toString() },
        },
      };
    });
    return {
      held: {
        month,
        reservedAt: now,
        payee: sealPayee(keys, { orgId, requestId, payeeKey: order.payeeKey }),
        windows: payeeRows.map(({ key }) => payeeWindowId(orgId, key)),
      },
      alongside,
    };
  }

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
    const { agent, keyId, mandateId } = await rowsBeforeTheSupplier(tx, states, acting, asked, now);
    const { mandate, ...policies } = await authorityIn(tx, states, orgId, agentId, 'inForce', { id: mandateId });
    const source = await sourceIn(tx, states, orgId, asked);
    // Under a mandate: none without one, as no month is then weighed.
    const zoneRead = mandate === null ? null : await keptZoneOf(tx, states, { orgId, agentId });
    if (zoneRead?.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    const { supplier, order } = await timedSupplierLock(() => supplierIn(tx, states, orgId, asked, 'change'));
    const zone =
      mandate === null || zoneRead === null
        ? null
        : await zoneInForce(tx, states, zoneRead, { orgId, agentId, zoneIfNew: mandate.timeZone, at: now });
    if (zone?.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
    // The month named at the instant asked, however long the locks take.
    const month = zone === null ? null : periodOf(now, zone.zone).month;
    const read = { asked, now, agent, mandate, policies, source, supplier, order, month };
    const { totals, monthTotal, windows } = await decisionWeighed(tx, states, orgId, read);
    const input = inputWith(read, totals);
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
      approvalWait: policies.approvalWait ?? LONGEST_APPROVAL_WAIT,
      createdAt: now,
    };

    let held: HeldAs | null = null;
    let alongside: readonly AlongsideChange[] = [];
    if (holdsCapacity(made.decision)) {
      // Capacity is held only on a mandate in force, by a supplier of the organisation's (decide's checks).
      if (mandate === null || month === null || order === null || monthTotal === null || windows.length === 0) {
        throw new Error('capacity held with nothing weighed');
      }
      ({ held, alongside } = await capacityHeld(tx, states, request, {
        mandateId: mandate.id,
        month,
        order,
        monthTotal,
        windows,
      }).catch((error: unknown) => {
        throw totalMadeMeanwhile(error);
      }));
    } else {
      await insertRequestStatement(tx, request).execute();
    }
    // The agent's zone, when this is its first decision: sealed with the request, as the audit head comes last.
    if (zone?.keptNow === true) {
      await sealNewZone(tx, states, {
        orgId,
        agentId,
        zone: zone.zone,
        at: now,
        actor: { type: 'agent', id: agent.id },
      });
    }
    const answer = await signRequest(tx, states, request, { type: 'agent', id: agent.id }, held, alongside);
    // Every admin and approver is told it waits (partner decision 2, Phase 3); the email reads it as it is sent.
    // Told after it is signed: the notice's record takes the chain head's lock too, which comes last (S206 V4, ADR-006 §6).
    if (made.decision === 'REQUIRE_APPROVAL') {
      await outbox.add(tx, toldAdminsAndApprovers(orgId, 'spend_request_waiting', requestId));
    }
    return { id: requestId, answer, decision: made.decision, reasons: made.reasons };
  }

  /** A decision its entry turned away, logged: nothing of it was made, its key unclaimed, so the agent sends it again (partner, S161: busy, never a 500). */
  function turnedAway(log: Logger, { agentId, orgId }: AgentActing, error: unknown): Refused {
    // A turn's wait run out behind decisions a full platform is holding: the platform's doing, not its organisation's.
    if (
      (error instanceof TurnWaitExceeded || error instanceof SupplierTurnExceeded) &&
      entry.heldByThePlatform(orgId)
    ) {
      log.warn('spend_request.platform_full', { agentId, waitedMs: error.waitedMs });
      return refused(503, 'PLATFORM_BUSY');
    }
    if (error instanceof TurnWaitExceeded) {
      log.warn('spend_request.agent_busy', { agentId, waitedMs: error.waitedMs });
      return refused(503, 'AGENT_BUSY');
    }
    if (error instanceof SupplierTurnExceeded) {
      log.warn('spend_request.supplier_busy', { agentId, waitedMs: error.waitedMs });
      return refused(503, 'ORGANISATION_BUSY');
    }
    if (error instanceof DecisionGateRefused) {
      // The whole platform full is its own line, alerted, and its own answer: this organisation hit no limit of its own.
      if (error.reason === 'platform') {
        log.warn('spend_request.platform_full', { agentId, waitedMs: error.waitedMs });
        return refused(503, 'PLATFORM_BUSY');
      }
      log.warn('spend_request.organisation_busy', { agentId, waitedMs: error.waitedMs });
      return refused(503, 'ORGANISATION_BUSY');
    }
    throw error;
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
      let waits: EntryWaits | undefined;
      const attempt = () =>
        work.write(agent, idempotent, correlationId, async (tx, states) => {
          made = await decided(tx, states, agent, idempotent.key, asked);
          fresh = made.answer;
          return { status: 201, resourceId: made.id };
        });
      // Through its entry, so decisions waiting on one agent's month or one supplier's lock can't hold every connection.
      let done: Awaited<ReturnType<typeof work.write>>;
      try {
        done = await entry.run(
          { agentId: agent.agentId, orgId: agent.orgId, supplierId: asked.supplierId },
          (waited) => {
            waits = waited;
            return timingStatements(times, () => retryingTransaction(log, DECIDE_OPERATION, attempt));
          },
        );
      } catch (error) {
        return turnedAway(log, agent, error);
      }
      if (isUnwritten(done)) return done;
      // Once a decision is committed, and once only (never for its key's replay), from the write itself, so a
      // failed read after it can't lose it (E2a review): the denial-surge alert counts these lines per agent
      // (E2). The audit chain is the record; this is the signal.
      if (done.outcome === 'done' && made !== undefined) {
        const durationMs = Math.round(performance.now() - started);
        log.info('spend_request.decided', {
          agentId: agent.agentId,
          decision: made.decision,
          reasons: made.reasons.join(' '),
          durationMs,
          ...timersKept(logSample, correlationId, durationMs, () => ({
            turnWaitMs: Math.round(waits?.turnWaitMs ?? 0),
            supplierTurnWaitMs: Math.round(waits?.supplierTurnWaitMs ?? 0),
            gateWaitMs: Math.round(waits?.gateWaitMs ?? 0),
            ...statementTimesForLog(times),
          })),
        });
      }
      // A fresh decision answers as its own transaction sealed it (4D2d P4 and P8, partner decision 2);
      // a replay of its key has given its turns and slot back, and reads it in a transaction of its own, as it is
      // now, outside the gate: it can be answered busy, safely, and sent again (PL-63 item 5).
      if (done.outcome === 'done' && fresh !== undefined) return { outcome: 'decided' as const, request: fresh };
      return work.answered(agent.orgId, correlationId, async (tx, states) => ({
        outcome: 'decided' as const,
        request: await answerOf(
          tx,
          states,
          { orgId: agent.orgId, id: done.result.resourceId },
          'A decided spend request',
        ),
      }));
    },
  };
}
