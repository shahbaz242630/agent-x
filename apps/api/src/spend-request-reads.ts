// Reading the organisation's spend requests, for its members (Phase 3 B3;
// SEC-AG-08, -10): every request newest first, those waiting for approval
// oldest first (the soonest to expire at the top), and one in full. Each is
// read through its signed state, and so are the agent and supplier it names,
// so nothing is shown that can't be believed: one tampered with refuses the
// answer, 503 INTEGRITY_FAILED, and holds the organisation. One that can't
// be checked right now (a backlog of events), a request or the agent or
// supplier it names, leaves only that request out of a list, named in
// `unchecked`: the list shows the rest (A1b, partner decision 5; B3b).
//
// ADR-006's lock order (agent 3, supplier 6, request 8) is kept, so a read
// never waits on a brake that waits on it (C2's cascades lock the agent, then
// its requests): a list reads its page of requests in one transaction and the
// agents and suppliers they name in a second (their names, read a moment
// later); one request is read in one transaction, its agent and supplier
// first, found by their IDs alone (requestInOrder).
import { agentOf, agentsNamed, type AgentShown, type AgentsTables, agentsShown } from '@agentx/core/modules/agents';
import type { PageAsked, SignedStates } from '@agentx/core/modules/audit';
import {
  requestOf,
  requestsPage,
  type SpendRequestRecord,
  type SpendRequestsTables,
} from '@agentx/core/modules/spend-requests';
import { supplierOf, suppliersNamed, type SuppliersTables, versionOf } from '@agentx/core/modules/suppliers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type Refused, refused } from './refused.ts';
import { createUseCaseWork, UseCaseRefused, type UseCaseTables } from './use-case-work.ts';

export type RequestReadTables = UseCaseTables & AgentsTables & SuppliersTables & SpendRequestsTables;
type ReadTx = DatabaseTransaction<RequestReadTables>;

/** A request as people see it: its signed state, when that was signed, and who it names, by name. */
export interface RequestShown {
  readonly request: SpendRequestRecord;
  /** When its latest move was signed: a waiting request's decision, which its 72 hours run from (D7). */
  readonly changedAt: Date;
  readonly agentName: string;
  readonly supplierName: string;
}

export type RequestsListed =
  | {
      readonly outcome: 'listed';
      readonly requests: readonly RequestShown[];
      readonly next: string | null;
      readonly unchecked: readonly string[];
    }
  | Refused;

export type RequestFound = { readonly outcome: 'found'; readonly shown: RequestShown } | Refused;

export interface SpendRequestReads {
  /** Every request, newest first; or those waiting for approval, oldest first. */
  list(orgId: string, page: PageAsked, which: 'all' | 'waiting', correlationId: string): Promise<RequestsListed>;
  show(orgId: string, requestId: string, correlationId: string): Promise<RequestFound>;
}

/** Refused inside a request's read, so its transaction ends there. */
class RequestReadRefused extends UseCaseRefused {}

/**
 * One request with its agent and supplier, in ADR-006's lock order, each
 * verified and locked `share`, in the caller's transaction, which must be
 * withSignedStates' for the organisation: `none` for no request of the
 * organisation's; `unbelieved` when a record fails its seal (its alarm
 * raised) or the request names others than the IDs first found by.
 */
export async function requestInOrder(
  tx: ReadTx,
  states: SignedStates,
  orgId: string,
  requestId: string,
): Promise<
  | { readonly outcome: 'found'; readonly shown: RequestShown }
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
  if (agent.outcome !== 'found' || supplier.outcome !== 'found') return { outcome: 'unbelieved' };
  const version = await versionOf(tx, states, { orgId, id: supplier.supplier.currentVersionId }, supplier.supplier.id);
  const read = await requestOf(tx, states, { orgId, id: requestId });
  if (version.outcome !== 'found' || read.outcome !== 'found') return { outcome: 'unbelieved' };
  const { request } = read;
  // The sealed request names its agent and supplier: the IDs found first must be those.
  if (request.agentId !== agent.agent.id || request.supplierId !== supplier.supplier.id) {
    return { outcome: 'unbelieved' };
  }
  // One named agent asked, one shown (agentsShown throws for a missing row).
  const [shown] = (await agentsShown(tx, orgId, [agent.agent])) as [AgentShown];
  return {
    outcome: 'found',
    shown: {
      request,
      changedAt: read.state.recordedAt,
      agentName: shown.name,
      supplierName: version.version.displayName,
    },
  };
}

/** The entry a verified list's own rows point to; one missing is a bug. */
function pointedTo<T>(named: ReadonlyMap<string, T>, id: string): T {
  const entry = named.get(id);
  if (entry === undefined) throw new Error(`A verified request names one not read: ${id}`);
  return entry;
}

export function createSpendRequestReads({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<RequestReadTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): SpendRequestReads {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: RequestReadRefused });

  return {
    async list(orgId, page, which, correlationId) {
      const listed = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        requestsPage(tx, states, orgId, page, which),
      );
      if (listed.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      const named = await work.inOrganisation(orgId, correlationId, async (tx, states) => {
        const agents = await agentsNamed(tx, states, orgId, [
          ...new Set(listed.items.map(({ request }) => request.agentId)),
        ]);
        if (agents.outcome === 'tampered') return agents;
        const suppliers = await suppliersNamed(tx, states, orgId, [
          ...new Set(listed.items.map(({ request }) => request.supplierId)),
        ]);
        if (suppliers.outcome === 'tampered') return suppliers;
        return { outcome: 'named' as const, agents, suppliers };
      });
      if (named.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      const { agents, suppliers } = named;
      const stuck = ({ request }: { readonly request: SpendRequestRecord }) =>
        agents.stuck.has(request.agentId) || suppliers.stuck.has(request.supplierId);
      return {
        outcome: 'listed',
        requests: listed.items
          .filter((item) => !stuck(item))
          .map(({ request, changedAt }) => ({
            request,
            changedAt,
            agentName: pointedTo(agents.agents, request.agentId).name,
            supplierName: pointedTo(suppliers.suppliers, request.supplierId).displayName,
          })),
        next: listed.next,
        unchecked: [...listed.unchecked, ...listed.items.filter(stuck).map(({ request }) => request.id)],
      };
    },

    show: (orgId, requestId, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const read = await requestInOrder(tx, states, orgId, requestId);
        if (read.outcome === 'none') throw new RequestReadRefused(404, 'NOT_FOUND');
        if (read.outcome === 'unbelieved') throw new RequestReadRefused(503, 'INTEGRITY_FAILED');
        return read;
      }),
  };
}
