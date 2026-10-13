// A spend request waiting for approval, as its email shows it (Phase 3 B2;
// partner decision 2, S104): read when the email is sent, never when the
// notice was written, so a request decided, expired or cancelled since sends
// nothing. Every fact is read from its verified record: the agent, its
// supplier and that supplier's version in force (the name it goes by), and the
// request itself, in ADR-006's lock order (agent 3, supplier 6, request 8), so
// the request's agent and supplier are found by their IDs alone first. A record
// that can't be believed raises its alarm through its read and sends nothing.
// The agent's own words (its purpose) never go in an email.
import { agentOf, type AgentShown, type AgentsTables, agentsShown } from '@agentx/core/modules/agents';
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import type { WaitingRequest, WaitingRequests } from '@agentx/core/modules/notifications';
import { requestOf, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { supplierOf, type SuppliersTables, versionOf } from '@agentx/core/modules/suppliers';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

type WaitingTables = AgentsTables & DirectoryTables & AuditTables & SpendRequestsTables & SuppliersTables;

export function createWaitingRequests({
  database,
  keys,
  ids,
  logger,
  publicOrigin,
}: {
  readonly database: Database<WaitingTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** Agent X's address: the email's link until Phase 6's console shows the request itself. */
  readonly publicOrigin: string;
}): WaitingRequests {
  return {
    waitingOf: (orgId, requestId) =>
      withSignedStates(
        database,
        orgId,
        { keys, ids, logger },
        async (tx, states): Promise<WaitingRequest | undefined> => {
          const named = await tx
            // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state below
            .selectFrom('spend_requests.requests')
            .select(['agent_id', 'supplier_id'])
            .where('org_id', '=', orgId)
            .where('id', '=', requestId)
            .executeTakeFirst();
          if (named === undefined) return undefined;
          const agent = await agentOf(tx, states, { orgId, id: named.agent_id }, 'share');
          const supplier = await supplierOf(tx, states, { orgId, id: named.supplier_id }, 'share');
          if (agent.outcome !== 'found' || supplier.outcome !== 'found') return undefined;
          const version = await versionOf(
            tx,
            states,
            { orgId, id: supplier.supplier.currentVersionId },
            supplier.supplier.id,
          );
          const read = await requestOf(tx, states, { orgId, id: requestId });
          if (version.outcome !== 'found' || read.outcome !== 'found') return undefined;
          const { request } = read;
          // The sealed request names its agent and supplier: the IDs found first must be those.
          if (
            request.status !== 'APPROVAL_REQUIRED' ||
            request.agentId !== agent.agent.id ||
            request.supplierId !== supplier.supplier.id
          ) {
            return undefined;
          }
          // One named agent asked, one shown (agentsShown throws for a missing row).
          const [shown] = (await agentsShown(tx, orgId, [agent.agent])) as [AgentShown];
          return {
            amountMinor: request.amount.minor,
            currency: request.amount.currency,
            supplierName: version.version.displayName,
            agentName: shown.name,
            agentId: agent.agent.id,
            consoleUrl: publicOrigin,
          };
        },
      ),
  };
}
