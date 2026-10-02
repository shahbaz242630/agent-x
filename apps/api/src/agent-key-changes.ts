// Rotating and revoking an AI agent's key (ADR-011 §1, ADR-012 §5, ADR-014
// §8, ADR-003 §8, BR-03; Phase 1 C1-4b). Composed in the API, as registering
// is (agent-writes.ts): the step-up is the identity module's, the agent and
// its keys the agents module's. Both are admins' and developers' (as
// registering is), each with step-up, with a passkey for an admin (SEC-HA-12).
//
// - `rotate` (`agents.keys.rotate`), then its confirm: a new key for the
//   agent, and the old one kept working to the end of the overlap
//   (KEY_OVERLAP_HOURS), so the agent can switch without a gap. A developer
//   rotates only the agents they own; an admin, any (the S68 audit: a new
//   key is a working credential for the agent, so another member's agent
//   isn't a developer's to take). The ask: the
//   key claimed first; the member read again; the agent and the key, read
//   for change; the key the agent's, and live (AGENT_KEY_NOT_LIVE for one
//   revoked or expired); fewer than MOST_LIVE_KEYS of the agent's keys live
//   (AGENT_KEYS_FULL: a rotation already in its overlap is waited out, or a
//   key revoked); a challenge bound to the organisation and the key's latest
//   event, so it rotates exactly that key as it stood. The confirm: the
//   organisation's lock for issuing keys; the member; the day's budget
//   (AGENT_KEYS_SPENT); the same reads and checks; the challenge consumed;
//   then the new key, with the scopes both the old key and the agent hold,
//   expiring in KEY_DAYS, shown this once; and the old key's expiry brought
//   forward to the end of the overlap (never later than it was). A suspended
//   agent's key may be rotated: after a leak, suspend first, rotate, then
//   reactivate.
// - `revoke` (`agents.keys.revoke`), then its confirm: the key stops at once,
//   with no overlap (ADR-012 §5). The same reads; AGENT_KEY_REVOKED for one
//   revoked already; the challenge bound the same way; then ACTIVE > REVOKED
//   with the step-up's evidence on its event. An expired key may be revoked.
//   For a key being used against the organisation now, the instant brake is
//   suspending its agent (no step-up), then revoking the key (ADR-014 §8).
//
// Lock order (ADR-006 §6): the idempotency key, the issue lock (rotation's
// confirm), the member's membership (2a), the agent (3), the key (3a) and
// then the agent's other keys (3a, by ID), the step-up challenge, the chain
// head last.
import {
  agentKeyOf,
  agentKeysOf,
  agentOf,
  AGENT_KEYS,
  bringKeyExpiryForward,
  isLiveKey,
  MOST_LIVE_KEYS,
  oneKeyIssueAtATime,
  rotatedKeyExpiresAt,
} from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
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
} from './agent-writes.ts';
import type { Refused } from './refused.ts';

/** Asking to rotate a key: its operation, which the step-up challenge names as its action too. */
export const ROTATE_OPERATION = 'agents.keys.rotate';
/** Rotating it, once stepped up. */
export const ROTATE_CONFIRM_OPERATION = 'agents.keys.rotate.confirm';
/** Asking to revoke a key: its operation, which the step-up challenge names as its action too. */
export const REVOKE_OPERATION = 'agents.keys.revoke';
/** Revoking it, once stepped up. */
export const REVOKE_CONFIRM_OPERATION = 'agents.keys.revoke.confirm';

/** Who may rotate or revoke an agent's key: anyone who may register an agent. */
export const KEY_CHANGING_ROLES = ['admin', 'developer'] as const;

/** The key a change is for: its agent and its own ID. */
export interface KeyNamed {
  readonly agentId: string;
  readonly keyId: string;
}

/** What a key change's write answers. */
export type AgentKeyChangeWrite =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | {
      readonly outcome: 'rotated';
      readonly agent: AgentWithKeys;
      /** The new key, answered this once; null on a retry of the same write. */
      readonly key: string | null;
    }
  | { readonly outcome: 'revoked'; readonly agent: AgentWithKeys }
  | { readonly outcome: 'conflict' | 'busy' }
  | Refused;

export interface AgentKeyChanges {
  rotate(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: KeyNamed,
    correlationId: string,
  ): Promise<AgentKeyChangeWrite>;
  rotateConfirm(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: KeyNamed,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<AgentKeyChangeWrite>;
  revoke(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: KeyNamed,
    correlationId: string,
  ): Promise<AgentKeyChangeWrite>;
  revokeConfirm(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: KeyNamed,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<AgentKeyChangeWrite>;
}

/**
 * The pending change's SHA-256: the organisation and the key's latest
 * event, IDs in lower case. That event is the key's own, read from its
 * signed state, so it names the key and exactly the state it was asked in: a
 * key rotated or revoked since can't be changed by it. Which change it is,
 * a rotation or a revocation, is the challenge's own action.
 */
const keyChangeHash = (orgId: string, keyEventId: string): Buffer =>
  changeHashOf([orgId.toLowerCase(), keyEventId.toLowerCase()]);

export function createAgentKeyChanges({
  database,
  keys,
  ids,
  clock,
  challenges,
  logger,
}: {
  readonly database: Database<AgentTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): AgentKeyChanges {
  const work = createAgentWork({ database, keys, ids, logger });

  /**
   * The agent and its key, each read for change and verified: NOT_FOUND for
   * either missing, or a key of another agent; INTEGRITY_FAILED for either
   * tampered with.
   */
  const keyToChange = async (tx: AgentTx, states: SignedStates, orgId: string, { agentId, keyId }: KeyNamed) => {
    const agentRead = await agentOf(tx, states, { orgId, id: agentId }, 'change');
    if (agentRead.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (agentRead.outcome === 'missing') throw new AgentRefused(404, 'NOT_FOUND');
    const keyRead = await agentKeyOf(tx, states, { orgId, id: keyId }, 'change');
    if (keyRead.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (keyRead.outcome === 'missing' || keyRead.key.agentId !== agentRead.agent.id) {
      throw new AgentRefused(404, 'NOT_FOUND');
    }
    return { agent: agentRead.agent, key: keyRead.key, state: keyRead.state };
  };

  /** A key that may be rotated now: live, and its agent with room for one more live key. */
  const keyToRotate = async (tx: AgentTx, states: SignedStates, orgId: string, named: KeyNamed, now: Date) => {
    const read = await keyToChange(tx, states, orgId, named);
    if (!isLiveKey(read.key, now)) throw new AgentRefused(409, 'AGENT_KEY_NOT_LIVE');
    const listed = await agentKeysOf(tx, states, orgId, read.agent.id);
    if (listed.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (listed.keys.filter((key) => isLiveKey(key, now)).length >= MOST_LIVE_KEYS) {
      throw new AgentRefused(409, 'AGENT_KEYS_FULL');
    }
    return read;
  };

  /**
   * Refuses a developer's rotation of an agent they don't own (FORBIDDEN, as
   * any other role check): the new key would be theirs to use as the agent.
   * Revoking isn't held to the owner: it only stops a key, as the brake does.
   */
  const mayRotate = (role: string, membershipId: string, owner: string): void => {
    if (role !== 'admin' && owner !== membershipId) throw new AgentRefused(403, 'FORBIDDEN');
  };

  /** A key that may be revoked: not revoked already. */
  const keyToRevoke = async (tx: AgentTx, states: SignedStates, orgId: string, named: KeyNamed) => {
    const read = await keyToChange(tx, states, orgId, named);
    if (read.key.status === 'REVOKED') throw new AgentRefused(409, 'AGENT_KEY_REVOKED');
    return read;
  };

  /** Opens the step-up for the change: the challenge is the write's resource, so a retry answers the same one. */
  const ask = async (
    tx: AgentTx,
    member: AgentMember,
    operation: string,
    keyEventId: string,
  ): Promise<{ status: number; resourceId: string }> => {
    const challenge = await challenges.open(tx, {
      sessionId: member.sessionId,
      action: operation,
      changeHash: keyChangeHash(member.orgId, keyEventId),
    });
    // The session ended since the access hook found it.
    if (challenge === undefined) throw new AgentRefused(401, 'UNAUTHENTICATED');
    return { status: 202, resourceId: challenge.challengeId };
  };

  /** Consumes the step-up for the change, with a passkey for an admin (SEC-HA-12): STEP_UP_FAILED otherwise. */
  const steppedUp = async (
    tx: AgentTx,
    member: AgentMember,
    role: string,
    operation: string,
    keyEventId: string,
    stepUpChallengeId: string,
  ) => {
    const consumed = await challenges.consume(
      tx,
      stepUpChallengeId,
      {
        sessionId: member.sessionId,
        action: operation,
        changeHash: keyChangeHash(member.orgId, keyEventId),
      },
      { passkeyRequired: role === 'admin' },
    );
    if (consumed === undefined) throw new AgentRefused(403, 'STEP_UP_FAILED');
    return consumed;
  };

  /** The agent and its keys as they now stand, answering the write, on a retry too. */
  const reread = (member: AgentMember, correlationId: string, agentId: string) =>
    work.answered(member.orgId, correlationId, (tx, states) => work.withKeys(tx, states, member.orgId, agentId));

  const asked = (done: Awaited<ReturnType<typeof work.write>>): AgentKeyChangeWrite => {
    if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
    return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
  };

  return {
    async rotate(member, idempotent, named, correlationId) {
      return asked(
        await work.write(member, idempotent, correlationId, async (tx, states) => {
          const { role, membershipId } = await work.memberIn(tx, states, member, KEY_CHANGING_ROLES);
          const { state, agent } = await keyToRotate(tx, states, member.orgId, named, clock.now());
          mayRotate(role, membershipId, agent.owner);
          return ask(tx, member, ROTATE_OPERATION, state.eventId);
        }),
      );
    },

    async rotateConfirm(member, idempotent, named, stepUpChallengeId, correlationId) {
      let key: string | null = null;
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await oneKeyIssueAtATime(tx, member.orgId);
        const { role, membershipId } = await work.memberIn(tx, states, member, KEY_CHANGING_ROLES);
        const now = clock.now();
        await work.keyBudgetLeft(tx, member.orgId, now);
        const old = await keyToRotate(tx, states, member.orgId, named, now);
        mayRotate(role, membershipId, old.agent.owner);
        const consumed = await steppedUp(tx, member, role, ROTATE_OPERATION, old.state.eventId, stepUpChallengeId);
        const actor = { type: 'user' as const, id: member.userId };
        const issued = await work.issueKey(tx, states, {
          orgId: member.orgId,
          agentId: old.agent.id,
          scopes: old.key.scopes.filter((scope) => old.agent.scopes.includes(scope)),
          now,
          actor,
          details: { ...stepUpDetails(consumed), rotates: old.key.id },
        });
        await bringKeyExpiryForward(tx, states, {
          orgId: member.orgId,
          key: old.key,
          state: old.state,
          expiresAt: rotatedKeyExpiresAt(old.key.expiresAt, now),
          actor,
          action: 'agent_key.rotated',
          details: { rotatedTo: issued.id },
        });
        key = issued.text;
        return { status: 201, resourceId: old.agent.id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      // The key is set only by a write done now: a retry answers it as null, as it was shown once.
      const agent = await reread(member, correlationId, done.result.resourceId);
      if ('outcome' in agent) return agent;
      return { outcome: 'rotated', agent, key };
    },

    async revoke(member, idempotent, named, correlationId) {
      return asked(
        await work.write(member, idempotent, correlationId, async (tx, states) => {
          await work.memberIn(tx, states, member, KEY_CHANGING_ROLES);
          const { state } = await keyToRevoke(tx, states, member.orgId, named);
          return ask(tx, member, REVOKE_OPERATION, state.eventId);
        }),
      );
    },

    async revokeConfirm(member, idempotent, named, stepUpChallengeId, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        const { role } = await work.memberIn(tx, states, member, KEY_CHANGING_ROLES);
        const read = await keyToRevoke(tx, states, member.orgId, named);
        const consumed = await steppedUp(tx, member, role, REVOKE_OPERATION, read.state.eventId, stepUpChallengeId);
        const moved = await states.changeStatus(tx, AGENT_KEYS, { orgId: member.orgId, id: read.key.id }, 'revoke', {
          actor: { type: 'user', id: member.userId },
          action: 'agent_key.revoked',
          details: stepUpDetails(consumed),
        });
        if (moved.outcome !== 'changed') throw new Error(`a key read as ACTIVE didn't revoke: ${moved.outcome}`);
        return { status: 200, resourceId: read.agent.id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      const agent = await reread(member, correlationId, done.result.resourceId);
      if ('outcome' in agent) return agent;
      return { outcome: 'revoked', agent };
    },
  };
}
