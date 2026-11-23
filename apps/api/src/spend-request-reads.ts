// Reading the organisation's spend requests, for its members (Phase 3 B3;
// SEC-AG-08, -10): every request newest first, those waiting for approval
// oldest first (the soonest to expire at the top), and one in full. Each is
// read through its signed state, and so are the agent and supplier it names,
// so nothing is shown that can't be believed: one tampered with refuses the
// answer, 503 INTEGRITY_FAILED, and holds the organisation. One that can't
// be checked right now (a backlog of events), a request or the agent or
// supplier it names, leaves only that request out of a list, named in
// `unchecked`: the list shows the rest (A1b, partner decision 5; B3b). A
// waiting one carried to its supplier's new details by changes chosen to
// pause is marked `needsRecheck` (decision 18; E5c), its approver re-checking
// it before approving (E5a): each such supplier's moves read once, and one
// whose history can't be believed leaves its requests out, named.
//
// ADR-006's lock order (agent 3, supplier 6, request 8) is kept, so a read
// never waits on a brake that waits on it (C2's cascades lock the agent, then
// its requests): a list reads its page of requests in one transaction and the
// agents and suppliers they name in a second (their names, read a moment
// later); one request is read in one transaction, its agent and supplier
// first, found by their IDs alone (requestInOrder). A rejected one in full
// carries its reject, from the signed event: who, when and why (B4a,
// decision 6); a voided one its void: when, and the causes (C2b).
//
// S206 V8: an agent's ask naming a supplier its organisation doesn't have
// (none at all, or another organisation's) is DENIED, as every ask is
// decided, and sealed naming no version of the supplier's details (0039).
// Such a request is shown with no supplier name (null), never another
// organisation's, and never fails the read: one sealed naming a version whose
// supplier is gone is still one that can't be believed.
//
// The agent reads its own requests (B4c, partner S106), one by its ID: its
// own alone (another agent's is NOT_FOUND, as none), as it stands now, so it
// learns that one waiting was approved, rejected, cancelled, expired or
// voided. Who rejected it and why are the team's alone: the agent learns only
// that a person rejected it (APPROVAL_REJECTED). A void it learns with its
// causes (REQUEST_VOIDED, then each cause), so it knows what to wait for
// before asking again.
//
// One handed off is shown with its payment (S212 G2): its ID and status, as
// the request's own story ends at HANDED_OFF and the payment carries how it
// came out. Read in the same transaction, after the request (ADR-006: payment
// 10), and only for one handed off: the instruction and its transaction are
// made with that move, in one transaction (hand-off's Tx A).
import { agentOf, agentsNamed, type AgentShown, type AgentsTables, agentsShown } from '@agentx/core/modules/agents';
import type { PageAsked, SignedStates, VerifiedState } from '@agentx/core/modules/audit';
import {
  type Decided,
  decidedAgainst,
  decisionOf,
  decisionsOf,
  denialOf,
  expiresAtOf,
  type RejectionShown,
  requestOf,
  requestsPage,
  type SpendRequestListed,
  type SpendRequestRecord,
  type SpendRequestsTables,
  type VoidingShown,
} from '@agentx/core/modules/spend-requests';
import { supplierOf, suppliersNamed, type SuppliersTables, versionOf } from '@agentx/core/modules/suppliers';
import { paymentsOfRequests, type PaymentsTables, type TransactionStatus } from '@agentx/core/modules/transactions';
import type { IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type Refused, refused } from './refused.ts';
import { isCarried, movedPast, pausedFromOf } from './suspensions.ts';
import { createUseCaseWork, pointedTo, UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

export type RequestReadTables = UseCaseTables & AgentsTables & SuppliersTables & SpendRequestsTables;
type ReadTx = DatabaseTransaction<RequestReadTables>;

/** A request as people see it: its signed state, when that was signed, and who it names, by name. */
export interface RequestShown {
  readonly request: SpendRequestRecord;
  /** When its latest move was signed. */
  readonly changedAt: Date;
  /** When a waiting one expires: its sealed wait from its decision's sealed time (D7, E6), never a later event's (E4b); else null. */
  readonly expiresAt: Date | null;
  readonly agentName: string;
  /** Null for a supplier not the organisation's: the request was denied for it, naming no version (S206 V8). */
  readonly supplierName: string | null;
  /** Waiting, carried to its supplier's new details: its approver re-checks it before approving (E5a). */
  readonly needsRecheck: boolean;
}

/**
 * When a request expires, from its decision (`decisionsOf`): null for one not
 * waiting; undefined for one waiting with no decision to believe, which is
 * then not shown.
 */
const expiresOf = (request: SpendRequestRecord, decided: Decided | null | undefined): Date | null | undefined => {
  if (request.status !== 'APPROVAL_REQUIRED') return null;
  return decided ? expiresAtOf(decided) : undefined;
};

export type RequestsListed =
  | {
      readonly outcome: 'listed';
      readonly requests: readonly RequestShown[];
      readonly next: string | null;
      readonly unchecked: readonly string[];
    }
  | Refused;

/** Why a DENIED request ended after its decision: a person's reject or a void; both null otherwise. */
interface Denial {
  readonly rejection: RejectionShown | null;
  readonly voiding: VoidingShown | null;
}

/** A handed-off request's payment, as the team follows it: its ID (the payments page's) and its status. */
interface RequestPayment {
  readonly id: string;
  readonly status: TransactionStatus;
}

export type RequestFound =
  | ({
      readonly outcome: 'found';
      readonly shown: RequestShown;
      /** Null for one not handed off: no payment yet. */
      readonly payment: RequestPayment | null;
    } & Denial)
  | Refused;

export type OwnRequestFound =
  | {
      readonly outcome: 'found';
      readonly request: SpendRequestRecord;
      /** The reasons that replace its decision's once a person or a brake ended it; null while they still explain it. */
      readonly endedBecause: readonly ReasonCode[] | null;
    }
  | Refused;

export interface SpendRequestReads {
  /** Every request, newest first; or those waiting for approval, oldest first. */
  list(orgId: string, page: PageAsked, which: 'all' | 'waiting', correlationId: string): Promise<RequestsListed>;
  show(orgId: string, requestId: string, correlationId: string): Promise<RequestFound>;
  /** One of the agent's own requests, as it stands, and why it ended if a person or a brake ended it. */
  ofAgent(orgId: string, agentId: string, requestId: string, correlationId: string): Promise<OwnRequestFound>;
}

/** Refused inside a request's read, so its transaction ends there. */
class RequestReadRefused extends UseCaseRefused {}

/** A record that can't be believed (its alarm raised): 503 INTEGRITY_FAILED. */
const integrityFailed = () => new RequestReadRefused(503, 'INTEGRITY_FAILED');

/**
 * One request with its agent and supplier, in ADR-006's lock order, each
 * verified and locked `share`, in the caller's transaction, which must be
 * withSignedStates' for the organisation: `none` for no request of the
 * organisation's; `unbelieved` when a record fails its seal (its alarm
 * raised) or the request names others than the IDs first found by. With the
 * request's verified state, for its evidence (C2).
 */
export async function requestInOrder(
  tx: ReadTx,
  states: SignedStates,
  orgId: string,
  requestId: string,
): Promise<
  | { readonly outcome: 'found'; readonly shown: RequestShown; readonly state: VerifiedState }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'unbelieved' }
> {
  const named = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state below
    .selectFrom('spend_requests.requests')
    .select(['agent_id', 'supplier_id'])
    .where('org_id', '=', orgId)
    .where('id', '=', requestId)
    .executeTakeFirst();
  if (named === undefined) return { outcome: 'none' };
  const agent = await agentOf(tx, states, { orgId, id: named.agent_id }, 'share');
  const supplier = await supplierOf(tx, states, { orgId, id: named.supplier_id }, 'share');
  if (agent.outcome !== 'found') return { outcome: 'unbelieved' };
  if (supplier.outcome === 'missing') return unknownSupplierRequest(tx, states, orgId, requestId, agent.agent);
  if (supplier.outcome !== 'found') return { outcome: 'unbelieved' };
  const version = await versionOf(tx, states, { orgId, id: supplier.supplier.currentVersionId }, supplier.supplier.id);
  const read = await requestOf(tx, states, { orgId, id: requestId });
  if (version.outcome !== 'found' || read.outcome !== 'found') return { outcome: 'unbelieved' };
  const { request } = read;
  // The sealed request names its agent and supplier: the IDs found first must be those.
  if (request.agentId !== agent.agent.id || request.supplierId !== supplier.supplier.id) {
    return { outcome: 'unbelieved' };
  }
  const waiting = request.status === 'APPROVAL_REQUIRED';
  const expiresAt = expiresOf(request, waiting ? await decisionOf(tx, states, { orgId, id: request.id }) : null);
  if (expiresAt === undefined) return { outcome: 'unbelieved' };
  const decidedUnder = decidedAgainst(read.state).supplierVersionId;
  let carried: readonly string[] = [];
  if (waiting && movedPast(decidedUnder, supplier.supplier.currentVersionId)) {
    try {
      carried = await pausedFromOf(tx, states, orgId, supplier.supplier, integrityFailed);
    } catch (error) {
      if (error instanceof RequestReadRefused) return { outcome: 'unbelieved' };
      throw error;
    }
  }
  // One named agent asked, one shown (agentsShown throws for a missing row).
  const [shown] = (await agentsShown(tx, orgId, [agent.agent])) as [AgentShown];
  return {
    outcome: 'found',
    state: read.state,
    shown: {
      request,
      changedAt: read.state.recordedAt,
      expiresAt,
      agentName: shown.name,
      supplierName: version.version.displayName,
      needsRecheck: isCarried(decidedUnder, supplier.supplier.currentVersionId, carried),
    },
  };
}

/**
 * A request whose supplier isn't the organisation's (S206 V8), read on from requestInOrder in its transaction: shown,
 * its supplier unnamed, only when its sealed state names no version of the supplier's details, as a decision seals
 * one denied for a supplier not the organisation's (0039); one naming a version, its supplier gone, is `unbelieved`.
 */
async function unknownSupplierRequest(
  tx: ReadTx,
  states: SignedStates,
  orgId: string,
  requestId: string,
  agent: Parameters<typeof agentsShown>[2][number],
): Promise<
  | { readonly outcome: 'found'; readonly shown: RequestShown; readonly state: VerifiedState }
  | { readonly outcome: 'unbelieved' }
> {
  const read = await requestOf(tx, states, { orgId, id: requestId });
  if (read.outcome !== 'found' || decidedAgainst(read.state).supplierVersionId !== null)
    return { outcome: 'unbelieved' };
  // Its row is the one named, its seal holding the agent read first; denied, it never waits: no expiry, no re-check.
  const { request } = read;
  const [shown] = (await agentsShown(tx, orgId, [agent])) as [AgentShown];
  return {
    outcome: 'found',
    state: read.state,
    shown: {
      request,
      changedAt: read.state.recordedAt,
      expiresAt: null,
      agentName: shown.name,
      supplierName: null,
      needsRecheck: false,
    },
  };
}

/**
 * The reject or void of a request read as DENIED, from its signed event, in
 * the caller's transaction; both null for any other status, or one its
 * decision denied.
 */
async function denialIn(tx: ReadTx, states: SignedStates, orgId: string, request: SpendRequestRecord): Promise<Denial> {
  if (request.status !== 'DENIED') return { rejection: null, voiding: null };
  const denial = await denialOf(tx, states, { orgId, id: request.id });
  if (denial.outcome === 'tampered') throw integrityFailed();
  return {
    rejection: denial.outcome === 'rejected' ? denial.rejection : null,
    voiding: denial.outcome === 'voided' ? denial.voiding : null,
  };
}

/**
 * The payment of a request read as HANDED_OFF, through its instruction's and
 * transaction's signed states, in the caller's transaction; null for any
 * other status. One changed past the app refuses the read (its alarm raised).
 */
async function paymentIn(
  tx: DatabaseTransaction<RequestReadTables & PaymentsTables>,
  states: SignedStates,
  orgId: string,
  request: SpendRequestRecord,
): Promise<RequestPayment | null> {
  if (request.status !== 'HANDED_OFF') return null;
  const payment = (await paymentsOfRequests(tx, states, orgId, [request.id])).get(request.id.toLowerCase());
  // None at all (rows gone under a HANDED_OFF request): shown as none here, a display read; the holdings sweep
  // and the evidence read, which judge a request's payment whole, raise it.
  if (payment === undefined) return null;
  if (payment.outcome === 'tampered') throw integrityFailed();
  return { id: payment.transactionId, status: payment.status };
}

/** What the agent is told of a denial: a reject alone, never why; a void with its causes. */
const toldToAgent = ({ rejection, voiding }: Denial): readonly ReasonCode[] | null => {
  if (rejection !== null) return ['APPROVAL_REJECTED'];
  if (voiding !== null) return ['REQUEST_VOIDED', ...voiding.causes];
  return null;
};

/**
 * For each supplier a waiting request of the page names that has moved past
 * the details it was decided under, the versions changes chosen to pause
 * moved it on from (pausedFromOf), read once a supplier. A history that
 * can't be believed is a broken chain, a tamper: the list is refused, 503
 * INTEGRITY_FAILED, as for any record it names (its alarm raised).
 */
/** Whether a listed request was sealed naming its supplier's details: all but one denied for a supplier not the organisation's. */
const namesVersion = (item: SpendRequestListed): boolean => item.supplierVersionId !== null;

async function carriedFrom(
  tx: ReadTx,
  states: SignedStates,
  orgId: string,
  items: readonly SpendRequestListed[],
  suppliers: ReadonlyMap<string, { readonly id: string; readonly currentVersionId: string }>,
): Promise<ReadonlyMap<string, readonly string[]>> {
  const moved = new Map<string, { readonly id: string; readonly currentVersionId: string }>();
  for (const item of items) {
    const supplier = suppliers.get(item.request.supplierId);
    const waiting = item.request.status === 'APPROVAL_REQUIRED';
    if (waiting && supplier && movedPast(item.supplierVersionId, supplier.currentVersionId))
      moved.set(supplier.id, supplier);
  }
  const carried = new Map<string, readonly string[]>();
  for (const supplier of moved.values()) {
    carried.set(supplier.id, await pausedFromOf(tx, states, orgId, supplier, integrityFailed));
  }
  return carried;
}

export function createSpendRequestReads({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<RequestReadTables & PaymentsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): SpendRequestReads {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: RequestReadRefused });

  return {
    async list(orgId, page, which, correlationId) {
      const read = await work.inOrganisation(orgId, correlationId, async (tx, states) => {
        const found = await requestsPage(tx, states, orgId, page, which);
        if (found.outcome === 'tampered') return { listed: found, decisions: new Map<string, Decided>() };
        // The waiting ones' decisions, in one statement, for when each expires.
        const waiting = found.items.filter(({ request }) => request.status === 'APPROVAL_REQUIRED');
        const decisions = await decisionsOf(
          tx,
          states,
          orgId,
          waiting.map(({ request }) => request.id),
        );
        return { listed: found, decisions };
      });
      const { listed, decisions } = read;
      if (listed.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      const named = await work.answered(orgId, correlationId, async (tx, states) => {
        const agents = await agentsNamed(tx, states, orgId, [
          ...new Set(listed.items.map(({ request }) => request.agentId)),
        ]);
        if (agents.outcome === 'tampered') return agents;
        // Only those sealed naming a version: one naming none was denied for a supplier not the organisation's.
        const suppliers = await suppliersNamed(tx, states, orgId, [
          ...new Set(listed.items.filter(namesVersion).map(({ request }) => request.supplierId)),
        ]);
        if (suppliers.outcome === 'tampered') return suppliers;
        const carried = await carriedFrom(tx, states, orgId, listed.items, suppliers.suppliers);
        return { outcome: 'named' as const, agents, suppliers, carried };
      });
      if (named.outcome === 'refused') return named;
      if (named.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      const { agents, suppliers, carried } = named;
      const needsRecheck = (item: SpendRequestListed) => {
        if (!namesVersion(item)) return false;
        const supplier = pointedTo(suppliers.suppliers, item.request.supplierId);
        return (
          item.request.status === 'APPROVAL_REQUIRED' &&
          isCarried(item.supplierVersionId, supplier.currentVersionId, carried.get(supplier.id) ?? [])
        );
      };
      const expiresAt = ({ request }: { readonly request: SpendRequestRecord }) =>
        expiresOf(request, decisions.get(request.id.toLowerCase()));
      // A waiting one with no decision to believe is left out and named, as one that can't be checked (A1b).
      const stuck = (item: SpendRequestListed) =>
        agents.stuck.has(item.request.agentId) ||
        suppliers.stuck.has(item.request.supplierId) ||
        // Sealed naming a version (only those are asked for), its supplier gone: not believed, so left out and named.
        suppliers.missing.has(item.request.supplierId) ||
        expiresAt(item) === undefined;
      return {
        outcome: 'listed',
        requests: listed.items
          .filter((item) => !stuck(item))
          .map((item) => ({
            request: item.request,
            changedAt: item.changedAt,
            expiresAt: expiresAt(item) ?? null,
            agentName: pointedTo(agents.agents, item.request.agentId).name,
            supplierName: namesVersion(item)
              ? pointedTo(suppliers.suppliers, item.request.supplierId).displayName
              : null,
            needsRecheck: needsRecheck(item),
          })),
        next: listed.next,
        unchecked: [...listed.unchecked, ...listed.items.filter(stuck).map(({ request }) => request.id)],
      };
    },

    show: (orgId, requestId, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const read = await requestInOrder(tx, states, orgId, requestId);
        if (read.outcome === 'none') throw new RequestReadRefused(404, 'NOT_FOUND');
        if (read.outcome === 'unbelieved') throw integrityFailed();
        const { request } = read.shown;
        const denial = await denialIn(tx, states, orgId, request);
        return {
          outcome: read.outcome,
          shown: read.shown,
          payment: await paymentIn(tx, states, orgId, request),
          ...denial,
        };
      }),

    ofAgent: (orgId, agentId, requestId, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const read = await requestOf(tx, states, { orgId, id: requestId });
        if (read.outcome === 'tampered') throw integrityFailed();
        // Another agent's is answered as none: an agent can't learn another's requests exist.
        if (read.outcome === 'missing' || read.request.agentId !== agentId) {
          throw new RequestReadRefused(404, 'NOT_FOUND');
        }
        const denial = await denialIn(tx, states, orgId, read.request);
        return { outcome: 'found' as const, request: read.request, endedBecause: toldToAgent(denial) };
      }),
  };
}
