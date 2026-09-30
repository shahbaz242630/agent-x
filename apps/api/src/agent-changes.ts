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
//   (AGENT_NOT_SUSPENDED otherwise); a challenge bound to the organisation
//   and the event that suspended the agent, so it reactivates exactly
//   that suspension and not a later one. The confirm, with the challenge:
//   the same reads, the agent for change; the challenge consumed; then
//   SUSPENDED > ACTIVE, with the step-up's evidence on its event.
// - `handOver` (`agents.owner`): an admin gives the agent to another member
//   (the S68 audit's question A: a removed member's agents keep running, so
//   an admin must be able to give them to someone who is still there), with
//   step-up (a passkey), as the new owner may then rotate its keys. The ask:
//   the key claimed first; the admin's membership and the new owner's, in
//   order of ID; the agent, ACTIVE or SUSPENDED, read for change; the new
//   owner an active admin or developer (AGENT_OWNER_NOT_ELIGIBLE otherwise,
//   one answer whether the membership is missing, another organisation's,
//   removed or of another role), and not its owner already
//   (AGENT_OWNER_UNCHANGED); a challenge bound to the organisation, the
//   agent's latest event and the new owner, so it hands over exactly this
//   agent, as it stood, to exactly that member. The confirm, with the
//   challenge: the same reads; the challenge consumed; then the owner
//   changed, its event naming both owners and the step-up's evidence. Its
//   status, scopes and keys stay as they are.
//
// Lock order (ADR-006 §6): the idempotency key, the members' memberships (2a,
// in order of ID), the agent (3), the step-up challenge, the chain head last.
import { AGENTS, agentOf, handAgentOver } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { listedMembership } from '@agentx/core/modules/directory';
import { changeHashOf, memberOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { REGISTERING_ROLES } from './agent-registering.ts';
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

/** Asking to hand an agent to another owner: its operation, which the step-up challenge names as its action too. */
export const HAND_OVER_OPERATION = 'agents.owner';
/** Handing it over, once stepped up. */
export const HAND_OVER_CONFIRM_OPERATION = 'agents.owner.confirm';

/** Who may press the kill switch: anyone who may register an agent (ADR-012 §5). */
export const SUSPENDING_ROLES = ['admin', 'developer'] as const;
/** Who may give an agent its authority back: an admin (ADR-003 §8). */
export const REACTIVATING_ROLES = ['admin'] as const;
/** Who may hand an agent to another owner: an admin, as for giving its authority back. */
export const HANDING_OVER_ROLES = ['admin'] as const;
/** Who may own an agent: anyone who may register one. */
const OWNING_ROLES: readonly string[] = REGISTERING_ROLES;

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
  handOver(
    member: AgentMember,
    idempotent: IdempotentRequest,
    agentId: string,
    owner: string,
    correlationId: string,
  ): Promise<AgentChangeWrite>;
  handOverConfirm(
    member: AgentMember,
    idempotent: IdempotentRequest,
    agentId: string,
    owner: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<AgentChangeWrite>;
}

/**
 * The pending handover's SHA-256: the organisation, the agent's latest event
 * and the new owner's membership, IDs in lower case. That event is the
 * agent's own, read from its signed state, so it names the agent as it stood
 * when asked: any change to it since (another handover, a suspension) makes
 * the step-up another change's.
 */
const handOverHash = (orgId: string, agentEvent: string, owner: string): Buffer =>
  changeHashOf([HAND_OVER_OPERATION, orgId.toLowerCase(), agentEvent.toLowerCase(), owner.toLowerCase()]);

/**
 * The pending change's SHA-256: the organisation and the event that suspended
 * the agent, IDs in lower case. That event is the agent's own, read from its
 * signed state, so it names the agent and exactly this suspension.
 */
const reactivationHash = (orgId: string, suspendedBy: string): Buffer =>
  changeHashOf([REACTIVATE_OPERATION, orgId.toLowerCase(), suspendedBy.toLowerCase()]);

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

  /**
   * The admin's membership and the new owner's, each read (`share`) once, in
   * order of membership ID (ADR-006 §6 level 2a), then the agent for change
   * (3): the admin an active admin (FORBIDDEN otherwise), the new owner an
   * active admin or developer of the organisation (AGENT_OWNER_NOT_ELIGIBLE
   * otherwise) and not the agent's owner already (AGENT_OWNER_UNCHANGED).
   */
  const handOverRead = async (
    tx: AgentTx,
    states: SignedStates,
    member: AgentMember,
    agentId: string,
    owner: string,
  ) => {
    const adminId = await listedMembership(tx, member.orgId, member.userId);
    if (adminId === undefined) throw new AgentRefused(403, 'FORBIDDEN');
    const ownerId = owner.toLowerCase();
    const ordered = [...new Set([adminId, ownerId])].sort();
    const reads = new Map<string, Awaited<ReturnType<typeof memberOf>>>();
    for (const id of ordered) reads.set(id, await memberOf(tx, states, { orgId: member.orgId, id }, 'share'));
    const admin = reads.get(adminId);
    const next = reads.get(ownerId);
    if (admin?.outcome === 'tampered' || next?.outcome === 'tampered') {
      throw new AgentRefused(503, 'INTEGRITY_FAILED');
    }
    if (
      admin?.outcome !== 'found' ||
      admin.member.userId !== member.userId.toLowerCase() ||
      admin.member.status !== 'ACTIVE' ||
      !(HANDING_OVER_ROLES as readonly string[]).includes(admin.member.role)
    ) {
      throw new AgentRefused(403, 'FORBIDDEN');
    }
    const read = await agentToChange(tx, states, member.orgId, agentId);
    if (next?.outcome !== 'found' || next.member.status !== 'ACTIVE' || !OWNING_ROLES.includes(next.member.role)) {
      throw new AgentRefused(409, 'AGENT_OWNER_NOT_ELIGIBLE');
    }
    if (read.agent.owner === next.member.id) throw new AgentRefused(409, 'AGENT_OWNER_UNCHANGED');
    return { ...read, owner: next.member.id };
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
          changeHash: reactivationHash(member.orgId, agent.suspendedBy),
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
            changeHash: reactivationHash(member.orgId, agent.suspendedBy),
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

    async handOver(member, idempotent, agentId, owner, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const read = await handOverRead(tx, states, member, agentId, owner);
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: HAND_OVER_OPERATION,
          changeHash: handOverHash(member.orgId, read.state.eventId, read.owner),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new AgentRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async handOverConfirm(member, idempotent, agentId, owner, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const read = await handOverRead(tx, states, member, agentId, owner);
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: HAND_OVER_OPERATION,
            changeHash: handOverHash(member.orgId, read.state.eventId, read.owner),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new AgentRefused(403, 'STEP_UP_FAILED');
        await handAgentOver(tx, states, {
          orgId: member.orgId,
          agent: read.agent,
          state: read.state,
          owner: read.owner,
          actor: { type: 'user', id: member.userId },
          details: stepUpDetails(consumed),
        });
        return { status: 200, resourceId: read.agent.id };
      });
      return answer(member, correlationId, done);
    },
  };
}
