// A spend request waiting for approval, as its email shows it (Phase 3 B2;
// partner decision 2, S104): read when the email is sent, never when the
// notice was written, so a request decided, expired or cancelled since sends
// nothing. Every fact is read from its verified record, in ADR-006's lock
// order (requestInOrder, as the team's own read of it, B3). A record that
// can't be believed raises its alarm through its read and sends nothing.
// The agent's own words (its purpose) never go in an email.
import { withSignedStates } from '@agentx/core/modules/audit';
import type { WaitingRequest, WaitingRequests } from '@agentx/core/modules/notifications';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type RequestReadTables, requestInOrder } from './spend-request-reads.ts';

export function createWaitingRequests({
  database,
  keys,
  ids,
  logger,
  publicOrigin,
}: {
  readonly database: Database<RequestReadTables>;
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
          const read = await requestInOrder(tx, states, orgId, requestId);
          if (read.outcome !== 'found' || read.shown.request.status !== 'APPROVAL_REQUIRED') return undefined;
          const { request, agentName, supplierName, expiresAt } = read.shown;
          // Waiting, so its expiry was read from its decision (requestInOrder).
          if (expiresAt === null) return undefined;
          return {
            amountMinor: request.amount.minor,
            currency: request.amount.currency,
            supplierName,
            agentName,
            agentId: request.agentId,
            consoleUrl: publicOrigin,
            expiresAt,
          };
        },
      ),
  };
}
