// Cancelling a spend request before hand-off (PRD §4.2, §7.2; ADR-006 §10–§11;
// ADR-014 §8; BR-09, BR-11; partner decision 10; Phase 2 D8): one click and
// no step-up, an instant brake, as suspending an agent is. Its reservation and
// order claim are released in the same transaction (core `cancelRequest`).
//
// - `byMember` (`spend-requests.cancel`): an admin or finance approver, read
//   again for this decision; any of the organisation's requests.
// - `byAgent` (`spend-requests.agent-cancel`): the agent that made the
//   request, its own alone (another agent's is NOT_FOUND, as none). The
//   access hook has checked its key; a cancel only gives capacity back, so it
//   isn't refused for a key revoked meanwhile, nor while the organisation is
//   frozen (a freeze stops new requests, never a brake).
//
// The key claimed first; then the request read for change (8), its holdings
// locked (11), the move signed (12), both released. A request cancelled
// already is answered as it stands (a brake pressed twice is not an error);
// one denied, expired or handed off is REQUEST_NOT_CANCELLABLE (409). No one
// is emailed yet (decision 10).
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import {
  cancelRequest,
  type Ended,
  requestOf,
  type SpendRequestRecord,
  type SpendRequestsTables,
} from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { MandateRefused } from './mandate-reads.ts';
import type { AgentActing } from './spend-request-decisions.ts';
import type { Refused } from './refused.ts';
import { createUseCaseWork, type Member, type UseCaseTables } from './use-case-work.ts';

export const CANCEL_OPERATION = 'spend-requests.cancel';
export const AGENT_CANCEL_OPERATION = 'spend-requests.agent-cancel';

/** Who in the team may cancel a request (partner decision 10). */
export const CANCELLING_ROLES = ['admin', 'approver'] as const;

type CancelTables = UseCaseTables & SpendRequestsTables & LimitReservationsTables;

/** A cancel's answer: the request as it now stands, the key's own answers, or a refusal. */
export type Cancelled =
  | { readonly outcome: 'cancelled'; readonly request: SpendRequestRecord }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface SpendRequestCancels {
  byMember(member: Member, idempotent: IdempotentRequest, requestId: string, correlationId: string): Promise<Cancelled>;
  byAgent(
    agent: AgentActing,
    idempotent: IdempotentRequest,
    requestId: string,
    correlationId: string,
  ): Promise<Cancelled>;
}

/** The write's answer for what came of the cancel: the request's ID, or the refusal. */
function settled(ended: Ended): { status: number; resourceId: string } {
  if (ended.outcome === 'ended') return { status: 200, resourceId: ended.request.id };
  if (ended.outcome === 'missing') throw new MandateRefused(404, 'NOT_FOUND');
  if (ended.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
  // Never `not_due`: only expiry waits. Cancelled already: answered as it stands.
  if (ended.outcome === 'not_open' && ended.request.status === 'CANCELLED') {
    return { status: 200, resourceId: ended.request.id };
  }
  throw new MandateRefused(409, 'REQUEST_NOT_CANCELLABLE');
}

export function createSpendRequestCancels({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Database<CancelTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): SpendRequestCancels {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  /** The request as it stands once the write is done (or answered for its key). */
  const shown = async (orgId: string, correlationId: string, done: Awaited<ReturnType<typeof work.write>>) => {
    if (isUnwritten(done)) return done;
    return work.answered(orgId, correlationId, async (tx, states) => {
      const found = await requestOf(tx, states, { orgId, id: done.result.resourceId });
      if (found.outcome === 'tampered') throw new MandateRefused(503, 'INTEGRITY_FAILED');
      // Requests are never deleted (0039's grants): one just cancelled, or answered for its key, is there.
      if (found.outcome !== 'found') throw new Error(`A cancelled spend request is missing: ${done.result.resourceId}`);
      return { outcome: 'cancelled' as const, request: found.request };
    });
  };

  return {
    async byMember(member, idempotent, requestId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, CANCELLING_ROLES);
        const by = { kind: 'user', userId: member.userId } as const;
        return settled(await cancelRequest(tx, states, { orgId: member.orgId, id: requestId }, by, clock.now()));
      });
      return shown(member.orgId, correlationId, done);
    },

    async byAgent(agent, idempotent, requestId, correlationId) {
      const done = await work.write(agent, idempotent, correlationId, async (tx, states) => {
        const by = { kind: 'agent', agentId: agent.agentId } as const;
        return settled(await cancelRequest(tx, states, { orgId: agent.orgId, id: requestId }, by, clock.now()));
      });
      return shown(agent.orgId, correlationId, done);
    },
  };
}
