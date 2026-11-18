// An agent's MCP connections, listed and revoked (6E3b, ADR-016; plan
// decision 6; SEC-OAUTH-07, -10). Composed in the API as a key's revocation
// is (agent-key-changes.ts): the step-up is the identity module's, the agent,
// its keys and its connections the agents module's.
//
// - `list`: the agent's connections, newest first, each as its own signed
//   state and its key's say (connectionsListed): every live one, and those
//   ended in the last 30 days (inside their tokens' retention, so when each
//   last connected is still known). Any member. NOT_FOUND for an agent the
//   organisation doesn't have; INTEGRITY_FAILED for anything tampered with.
// - `revoke` (`connections.revoke`), then its confirm: the connection stops at
//   once, its key revoked (revokeKey), so every token it was given is refused
//   at its next use. Admins and developers, a developer only for an agent they
//   own (as for making one: whoever made it may hold its tokens), each with
//   step-up, a passkey for an admin (SEC-HA-12). The ask: the key claimed
//   first; the member read again; the agent and the connection's key read for
//   change, and the connection; NOT_FOUND for a key that is no connection of
//   the agent's (an agent's own key is revoked as a key); CONNECTION_REVOKED
//   for one revoked already (an expired one may be); a challenge bound to the
//   organisation and the key's latest event, so it revokes exactly that
//   connection as it stood. The confirm: the same reads, the challenge
//   consumed, ACTIVE > REVOKED with the step-up's evidence on its event, and
//   the agent's connections as they now stand. Suspending the agent stays the
//   instant brake, with no step-up (decision 6).
// - Removing a member revokes the connections they made (decision 7):
//   connectionsOfLeaving, the identity module's MemberLeaving, as it can't
//   read the agents module. A hand-over revokes every connection of the agent
//   (agent-changes.ts).
//
// Lock order (ADR-006 §6): the idempotency key, the agent's brake, the
// member's membership (2a), the agent (3), the key (3a), the connection (3b),
// the step-up challenge, the chain head last.
import {
  agentKeyOf,
  agentOf,
  agentsOfLiveConnectionsMadeBy,
  type AgentsTables,
  type ConnectionListed,
  connectionOf,
  connectionsListed,
  type ConnectionVia,
  liveConnectionsMadeBy,
  revokeKey,
  type Scope,
} from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import {
  changeHashOf,
  type HeldChallenges,
  type MemberLeaving,
  type StepUpChallenges,
  stepUpDetails,
} from '@agentx/core/modules/identity';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import {
  AGENT_BRAKE,
  type Database,
  holdBrake,
  holdBrakesWithin,
  type IdempotentRequest,
  isUnwritten,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { KEY_CHANGING_ROLES, type KeyNamed } from './agent-key-changes.ts';
import { type AgentMember, AgentRefused, type AgentTables, type AgentTx, createAgentWork } from './agent-writes.ts';
import type { Refused, StepUpAsked } from './refused.ts';
import { createStepUps, type Written } from './use-case-work.ts';

/** Asking to revoke a connection: its operation, which the step-up challenge names as its action too. */
export const CONNECTION_REVOKE_OPERATION = 'connections.revoke';
/** Revoking it, once stepped up. */
export const CONNECTION_REVOKE_CONFIRM_OPERATION = 'connections.revoke.confirm';

/** Who may revoke a connection: anyone who may make one (a developer, for an agent they own). */
export const CONNECTION_REVOKING_ROLES = KEY_CHANGING_ROLES;

/** What a connection's status is: its key's, or EXPIRED once its key's expiry has passed. */
type ConnectionStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED';

/** A connection as an answer shows it: never a token, nor its key's MAC. */
export interface ConnectionShown {
  readonly keyId: string;
  readonly clientId: string;
  readonly clientName: string;
  /** The host (and port) its browser was sent back to; null for a device's connection. */
  readonly redirectHost: string | null;
  readonly via: ConnectionVia;
  readonly scopes: readonly Scope[];
  /** The membership of the person who made it. */
  readonly madeBy: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly lastConnectedAt: Date | null;
  readonly status: ConnectionStatus;
}

/** The agent's connections, newest first. */
interface ConnectionsShown {
  readonly connections: readonly ConnectionShown[];
}

/** What a connection's revocation answers. */
export type ConnectionChangeWrite =
  | StepUpAsked
  | { readonly outcome: 'revoked'; readonly connections: readonly ConnectionShown[] }
  | { readonly outcome: 'conflict' | 'busy' }
  | Refused;

export interface ConnectionChanges {
  list(orgId: string, agentId: string, correlationId: string): Promise<ConnectionsShown | Refused>;
  revoke(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: KeyNamed,
    correlationId: string,
  ): Promise<ConnectionChangeWrite>;
  revokeConfirm(
    member: AgentMember,
    idempotent: IdempotentRequest,
    named: KeyNamed,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<ConnectionChangeWrite>;
}

/** The connection as its list shows it at `now`: its status is its key's, EXPIRED past its key's expiry. */
function connectionShown({ connection, key, ...made }: ConnectionListed, now: Date): ConnectionShown {
  const ended = key.expiresAt.getTime() <= now.getTime() ? 'EXPIRED' : 'ACTIVE';
  return {
    keyId: key.id,
    clientId: connection.clientId,
    clientName: made.clientName,
    redirectHost: connection.redirectUri === null ? null : new URL(connection.redirectUri).host,
    via: made.via,
    scopes: key.scopes,
    madeBy: made.madeBy,
    createdAt: made.createdAt,
    expiresAt: key.expiresAt,
    lastConnectedAt: made.lastConnectedAt,
    status: key.status === 'REVOKED' ? 'REVOKED' : ended,
  };
}

/**
 * The pending revocation's SHA-256: the organisation and the connection's key's latest event, IDs in lower case, so a
 * key revoked since can't be revoked by it. That it is a connection's revocation is the challenge's own action.
 */
const revocationHash = (orgId: string, keyEventId: string): Buffer =>
  changeHashOf([orgId.toLowerCase(), keyEventId.toLowerCase()]);

/**
 * What removing a member ends of the agents module's (decision 7): the live connections they made. First, the brakes of
 * their agents (1b), found by one unlocked statement and taken one by one in order of agent ID, before any session or
 * row (ADR-006 §6: the one change that may hold more than one brake), so a stream of decisions and key checks can't
 * starve the revocations, their waits together bounded to one brake's (AG4). Then the keys read for change, and revoked by the admin removing them, each event naming
 * the membership removed. A connection made for another agent between the two (its consent committed before the
 * membership was locked) is revoked too, without its brake: correct, only not starvation-proof, and as rare as that.
 */
export const connectionsOfLeaving = (clock: Clock): MemberLeaving<AgentsTables> => ({
  async brakes(tx, { orgId, membershipId }) {
    const agents = await agentsOfLiveConnectionsMadeBy(tx, orgId, membershipId, clock.now());
    await holdBrakesWithin(
      tx,
      AGENT_BRAKE,
      agents.map((agentId) => [orgId, agentId]),
    );
    return agents.length > 0;
  },
  async read(tx, states, { orgId, membershipId }) {
    const listed = await liveConnectionsMadeBy(tx, states, orgId, membershipId, clock.now());
    if (listed.outcome === 'tampered') return { outcome: 'tampered' };
    return {
      outcome: 'read',
      end: async (actor) => {
        for (const key of listed.keys) {
          await revokeKey(
            tx,
            states,
            { orgId, keyId: key.id, actor, details: { reason: 'member_removed', membershipId } },
            "a connection's key read as ACTIVE didn't revoke",
          );
        }
      },
    };
  },
});

export function createConnectionChanges({
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
}): ConnectionChanges {
  const work = createAgentWork({ database, keys, ids, logger });
  const stepUps = createStepUps({ challenges, Refusal: AgentRefused });

  /** The agent's brake, before any row: revoking its key waits behind a kill switch, as a key's revocation does. */
  const brakeOf =
    (member: AgentMember, { agentId }: KeyNamed) =>
    (tx: AgentTx) =>
      holdBrake(tx, AGENT_BRAKE, member.orgId, agentId);

  /** The agent's connections, read (`share`) and verified: NOT_FOUND, or INTEGRITY_FAILED, otherwise. */
  const listOf = async (tx: AgentTx, states: SignedStates, orgId: string, agentId: string) => {
    const agentRead = await agentOf(tx, states, { orgId, id: agentId }, 'share');
    if (agentRead.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (agentRead.outcome === 'missing') throw new AgentRefused(404, 'NOT_FOUND');
    const now = clock.now();
    const listed = await connectionsListed(tx, states, orgId, agentRead.agent.id, now);
    if (listed.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    return { connections: listed.connections.map((each) => connectionShown(each, now)) };
  };

  /**
   * The connection to revoke, by its key, with its agent: the agent and the key read for change, then the connection;
   * NOT_FOUND for any of them missing, a key of another agent's, or a key that is no connection (an agent's own key is
   * revoked as a key); INTEGRITY_FAILED for any tampered with; FORBIDDEN for a developer's of an agent they don't own;
   * CONNECTION_REVOKED for one revoked already.
   */
  const connectionToRevoke = async (
    tx: AgentTx,
    states: SignedStates,
    member: AgentMember,
    { agentId, keyId }: KeyNamed,
  ) => {
    const { role, membershipId } = await work.memberIn(tx, states, member, CONNECTION_REVOKING_ROLES);
    const agentRead = await agentOf(tx, states, { orgId: member.orgId, id: agentId }, 'change');
    if (agentRead.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (agentRead.outcome === 'missing') throw new AgentRefused(404, 'NOT_FOUND');
    const keyRead = await agentKeyOf(tx, states, { orgId: member.orgId, id: keyId }, 'change');
    if (keyRead.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (keyRead.outcome === 'missing' || keyRead.key.agentId !== agentRead.agent.id) {
      throw new AgentRefused(404, 'NOT_FOUND');
    }
    const connectionRead = await connectionOf(tx, states, { orgId: member.orgId, id: keyId });
    if (connectionRead.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
    if (connectionRead.outcome === 'missing' || connectionRead.connection.agentId !== agentRead.agent.id) {
      throw new AgentRefused(404, 'NOT_FOUND');
    }
    // SEC-OAUTH-10: whoever made a connection may hold its tokens, so another member's agent isn't a developer's.
    if (role !== 'admin' && agentRead.agent.owner !== membershipId) throw new AgentRefused(403, 'FORBIDDEN');
    if (keyRead.key.status === 'REVOKED') throw new AgentRefused(409, 'CONNECTION_REVOKED');
    return { role, agent: agentRead.agent, key: keyRead.key, state: keyRead.state };
  };

  /** Consumes the step-up for the revocation, with a passkey for an admin (SEC-HA-12): STEP_UP_FAILED otherwise. */
  const steppedUp = (
    tx: AgentTx,
    member: AgentMember,
    role: string,
    keyEventId: string,
    held: HeldChallenges,
    stepUpChallengeId: string,
  ) =>
    stepUps.consumed(
      tx,
      member,
      held,
      stepUpChallengeId,
      { action: CONNECTION_REVOKE_OPERATION, changeHash: revocationHash(member.orgId, keyEventId) },
      { passkeyRequired: role === 'admin' },
    );

  const asked = (done: Written): ConnectionChangeWrite => {
    if (isUnwritten(done)) return done;
    return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
  };

  return {
    list(orgId, agentId, correlationId) {
      return work.answered(orgId, correlationId, (tx, states) => listOf(tx, states, orgId, agentId));
    },

    async revoke(member, idempotent, named, correlationId) {
      return asked(
        await work.brakeWrite(member, idempotent, correlationId, brakeOf(member, named), async (tx, states) => {
          const { state } = await connectionToRevoke(tx, states, member, named);
          return stepUps.ask(tx, member, {
            action: CONNECTION_REVOKE_OPERATION,
            changeHash: revocationHash(member.orgId, state.eventId),
          });
        }),
      );
    },

    async revokeConfirm(member, idempotent, named, stepUpChallengeId, correlationId) {
      const done = await work.brakeWrite(
        member,
        idempotent,
        correlationId,
        brakeOf(member, named),
        async (tx, states) => {
          const held = await challenges.hold(tx, member.sessionId);
          const read = await connectionToRevoke(tx, states, member, named);
          const consumed = await steppedUp(tx, member, read.role, read.state.eventId, held, stepUpChallengeId);
          await revokeKey(
            tx,
            states,
            {
              orgId: member.orgId,
              keyId: read.key.id,
              actor: { type: 'user', id: member.userId },
              details: { ...stepUpDetails(consumed), reason: 'connection_revoked' },
            },
            "a connection's key read as ACTIVE didn't revoke",
          );
          return { status: 200, resourceId: read.agent.id };
        },
      );
      if (isUnwritten(done)) return done;
      // Read after the commit, on a retry too: the list as it now stands.
      const listed = await work.answered(member.orgId, correlationId, (tx, states) =>
        listOf(tx, states, member.orgId, done.result.resourceId),
      );
      if ('outcome' in listed) return listed;
      return { outcome: 'revoked', connections: listed.connections };
    },
  };
}
