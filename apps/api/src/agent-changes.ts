// Suspending and reactivating an AI agent (ADR-012 §5, ADR-014 §8, ADR-003
// §8, BR-03; Phase 1 C1-3). Composed in the API, as registering is
// (agent-writes.ts): the step-up is the identity module's, the agent the
// agents module's.
//
// - `suspend` (`agents.suspend`): the kill switch, one click and no step-up
//   (ADR-014 §8: the instant brakes are never behind step-up). The key
//   claimed first; the member read again, active and an admin or developer;
//   the agent read for change; then ACTIVE > SUSPENDED, recorded as the
//   member's. An agent suspended already is left as it is, and answered: a
//   brake pressed twice is not an error. None of its keys works while it is
//   suspended (C2 reads the agent's status on every request). Phase 3 adds
//   the cascade in the same transaction: its pending requests denied, their
//   approvals cancelled, their reservations released (ADR-012 §5).
// - `reactivate` (`agents.reactivate`): gives the agent its authority back,
//   so an admin's, with step-up (a passkey, SEC-HA-12). The ask: the key
//   claimed first; the admin read again; the agent, SUSPENDED
//   (AGENT_NOT_SUSPENDED otherwise); a challenge bound to the organisation,
//   the agent and the event that suspended it, so it reactivates exactly
//   that suspension and not a later one. The confirm, with the challenge:
//   the same reads, the agent for change; the challenge consumed; then
//   SUSPENDED > ACTIVE, with the step-up's evidence on its event.
//
// Lock order (ADR-006 §6): the idempotency key, the member's membership (2a),
// the agent (3), the step-up challenge, the chain head last.
import { AGENTS, agentOf } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  type AgentMember,
  AgentRefused,
  type AgentTables,
  type AgentTx,
  type AgentWithKeys,
  createAgentWork,
  type Refused,
} from './agent-writes.ts';

/** Suspending an agent: the kill switch. */
export const SUSPEND_OPERATION = 'agents.suspend';
/** Asking to reactivate one: its operation, which the step-up challenge names as its action too. */
export const REACTIVATE_OPERATION = 'agents.reactivate';
/** Reactivating it, once stepped up. */
export const REACTIVATE_CONFIRM_OPERATION = 'agents.reactivate.confirm';

/** Who may press the kill switch: anyone who may register an agent (ADR-012 §5). */
export const SUSPENDING_ROLES = ['admin', 'developer'] as const;
/** Who may give an agent its authority back: an admin (ADR-003 §8). */
export const REACTIVATING_ROLES = ['admin'] as const;

/** What a change's write answers. */
export type AgentChangeWrite =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'changed'; readonly agent: AgentWithKeys }
  | { readonly outcome: 'conflict' | 'busy' }
  | Refused;

export interface AgentChanges {
  suspend(
    member: AgentMember,
    idempotent: IdempotentRequest,
    agentId: string,
    correlationId: string,
  ): Promise<AgentChangeWrite>;
  reactivate(
    member: AgentMember,
    idempotent: IdempotentRequest,
    agentId: string,
    correlationId: string,
  ): Promise<AgentChangeWrite>;
  reactivateConfirm(
    member: AgentMember,
    idempotent: IdempotentRequest,
    agentId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<AgentChangeWrite>;
}

/** The pending change's SHA-256: the organisation, the agent and the event that suspended it, IDs in lower case. */
const reactivationHash = (orgId: string, agentId: string, suspendedBy: string): Buffer =>
  changeHashOf([REACTIVATE_OPERATION, orgId.toLowerCase(), agentId.toLowerCase(), suspendedBy.toLowerCase()]);

export function createAgentChanges({
  database,
  keys,
  ids,
  challenges,
  logger,
}: {
  readonly database: Database<AgentTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): AgentChanges {
  const work = createAgentWork({ database, keys, ids, logger });

  /** The agent, read for change and verified: NOT_FOUND, or INTEGRITY_FAILED, otherwise. */
  const agentToChange = async (tx: AgentTx, states: SignedStates, orgId: string, agentId: string) => {
    const read = await agentOf(tx, states, { orgId, id: agentId }, 'change');
    if (read.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new AgentRefused(404, 'NOT_FOUND');
    return read;
  };

  /** A suspended agent, and the event that suspended it: AGENT_NOT_SUSPENDED for an active one. */
  const suspendedAgent = async (tx: AgentTx, states: SignedStates, orgId: string, agentId: string) => {
    const read = await agentToChange(tx, states, orgId, agentId);
    if (read.agent.status !== 'SUSPENDED') throw new AgentRefused(409, 'AGENT_NOT_SUSPENDED');
    return { id: read.agent.id, suspendedBy: read.state.eventId };
  };

  /** Answers the write: the agent as it now stands, on a retry too. */
  const answer = async (
    member: AgentMember,
    correlationId: string,
    done: Awaited<ReturnType<typeof work.write>>,
  ): Promise<AgentChangeWrite> => {
    if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
    const agent = await work.answered(member.orgId, correlationId, (tx, states) =>
      work.withKeys(tx, states, member.orgId, done.result.resourceId),
    );
    if ('outcome' in agent) return agent;
    return { outcome: 'changed', agent };
  };

  return {
    async suspend(member, idempotent, agentId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, SUSPENDING_ROLES);
        const read = await agentToChange(tx, states, member.orgId, agentId);
        // Pressed twice: already stopped, and answered as it is.
        if (read.agent.status === 'ACTIVE') {
          const moved = await states.changeStatus(tx, AGENTS, { orgId: member.orgId, id: read.agent.id }, 'suspend', {
            actor: { type: 'user', id: member.userId },
            action: 'agent.suspended',
            details: {},
          });
          if (moved.outcome !== 'changed') throw new Error(`an agent read as ACTIVE didn't suspend: ${moved.outcome}`);
        }
        return { status: 200, resourceId: read.agent.id };
      });
      return answer(member, correlationId, done);
    },

    async reactivate(member, idempotent, agentId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const agent = await suspendedAgent(tx, states, member.orgId, agentId);
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: REACTIVATE_OPERATION,
          changeHash: reactivationHash(member.orgId, agent.id, agent.suspendedBy),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new AgentRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async reactivateConfirm(member, idempotent, agentId, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REACTIVATING_ROLES);
        const agent = await suspendedAgent(tx, states, member.orgId, agentId);
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: REACTIVATE_OPERATION,
            changeHash: reactivationHash(member.orgId, agent.id, agent.suspendedBy),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new AgentRefused(403, 'STEP_UP_FAILED');
        const moved = await states.changeStatus(tx, AGENTS, { orgId: member.orgId, id: agent.id }, 'reactivate', {
          actor: { type: 'user', id: member.userId },
          action: 'agent.reactivated',
          details: stepUpDetails(consumed),
        });
        if (moved.outcome !== 'changed')
          throw new Error(`an agent read as SUSPENDED didn't reactivate: ${moved.outcome}`);
        return { status: 200, resourceId: agent.id };
      });
      return answer(member, correlationId, done);
    },
  };
}
