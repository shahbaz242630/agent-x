// A spend request waiting for approval, as its email shows it (Phase 3 B2;
// partner decision 2, S104): read when the email is sent, never when the
// notice was written, so a request decided, expired or cancelled since sends
// nothing. Every fact is read from its verified record, in ADR-006's lock
// order (requestInOrder, as the team's own read of it, B3). A record that
// can't be believed raises its alarm through its read and sends nothing.
// The agent's own words (its purpose) never go in an email. Its link opens
// the request's own page in the console, in its organisation (6B1, PL-51):
// IDs only, nothing that decides; the console signs the person in first.
import { withSignedStates } from '@agentx/core/modules/audit';
import type { WaitingRequest, WaitingRequests } from '@agentx/core/modules/notifications';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type RequestReadTables, requestInOrder } from './spend-request-reads.ts';

/** The console's page of one request, in its organisation: `/approvals/<id>?org=<organisation>`. */
const requestPage = (origin: string, orgId: string, requestId: string): string =>
  `${origin}/approvals/${encodeURIComponent(requestId)}?${new URLSearchParams({ org: orgId }).toString()}`;

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
  /** Agent X's address, which the request's page is under. */
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
          // Only a request still waiting has an expiry (requestInOrder: read from its decision).
          if (read.outcome !== 'found' || read.shown.expiresAt === null) return undefined;
          const { request, agentName, supplierName, expiresAt } = read.shown;
          return {
            amountMinor: request.amount.minor,
            currency: request.amount.currency,
            supplierName,
            agentName,
            agentId: request.agentId,
            consoleUrl: requestPage(publicOrigin, orgId, requestId),
            expiresAt,
          };
        },
      ),
  };
}
