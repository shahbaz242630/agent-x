// Registering an AI agent with its first key (ADR-011 §1, ADR-003 §8, BR-03;
// Phase 1 C1-2). Composed here, in the API, as ADR-004 §7 has it: the step-up
// is the identity module's, the agent and its key the agents module's, and
// the agents module never depends on identity. One transaction, the
// organisation's, holds both (agent-writes.ts).
//
// 1. `ask` (`agents.register`): the key claimed first; the member read again,
//    active and an admin or developer; then a step-up challenge for their own
//    session, bound to the organisation, the name and the scopes. The
//    challenge is the write's resource, so a retry answers the same one.
// 2. `confirm` (`agents.register.confirm`), the same name and scopes and the
//    step-up's ID: the key claimed first; the organisation's lock for adding
//    agents; the member read again; the day's budget (AGENT_ADDS_SPENT); the
//    challenge consumed only for this session, action and change, with a
//    passkey for an admin (SEC-HA-12); then the agent, ACTIVE, owned by the
//    member, and its first key, with the agent's scopes, expiring in
//    KEY_DAYS. The key, `axk_<keyId>_<secret>`, is answered once: only its
//    secret's MAC with the agent-key pepper is kept, and a retry of the same
//    write answers the agent and the key's ID without it.
//
// Lock order (ADR-006 §6): the idempotency key, the add lock, the member's
// membership (2a), the step-up challenge, the agent (3), its key (3a), the
// chain head last.
import {
  addAgent,
  agentsAddedSince,
  type AgentShown,
  agentsPage,
  MOST_AGENTS_ADDED_A_DAY,
  oneAgentAddAtATime,
  type Scope,
  scopesText,
} from '@agentx/core/modules/agents';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from '@agentx/core/modules/identity';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  type AgentMember,
  AgentRefused,
  type AgentTables,
  type AgentWithKeys,
  createAgentWork,
  type Refused,
} from './agent-writes.ts';

/** Asking to register an agent: its operation, which the step-up challenge names as its action too. */
export const REGISTER_OPERATION = 'agents.register';
/** Registering it, once stepped up. */
export const REGISTER_CONFIRM_OPERATION = 'agents.register.confirm';

/** The roles that may register an agent (BRD §4: the developer registers it; the admin holds authority). */
export const REGISTERING_ROLES = ['admin', 'developer'] as const;

/** Who is registering: a signed-in member, in the organisation the access hook verified, and their session. */
export type RegisteringMember = AgentMember;

/** The agent asked for: its name and scopes, the same on the ask and the confirm. */
export interface AgentAsked {
  readonly name: string;
  readonly scopes: readonly Scope[];
}

/** What a registration's write answers. */
export type RegistrationWrite =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | {
      readonly outcome: 'registered';
      readonly agent: AgentWithKeys;
      /** The key, answered this once; null on a retry of the same write. */
      readonly key: string | null;
    }
  | { readonly outcome: 'conflict' | 'busy' }
  | Refused;

/** A page of agents, or a refusal. */
export type AgentsListed =
  { readonly outcome: 'listed'; readonly agents: readonly AgentShown[]; readonly next: string | null } | Refused;

/** One agent with its keys, or a refusal. */
export type AgentFound = ({ readonly outcome: 'found' } & AgentWithKeys) | Refused;

export interface AgentRegistrations {
  ask(
    member: RegisteringMember,
    idempotent: IdempotentRequest,
    asked: AgentAsked,
    correlationId: string,
  ): Promise<RegistrationWrite>;
  confirm(
    member: RegisteringMember,
    idempotent: IdempotentRequest,
    asked: AgentAsked,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<RegistrationWrite>;
  /** A page of the organisation's agents, after `after`, at most `limit`. */
  list(orgId: string, page: { after: string | null; limit: number }, correlationId: string): Promise<AgentsListed>;
  /** The agent, with its keys: NOT_FOUND for one the organisation doesn't have. */
  show(orgId: string, agentId: string, correlationId: string): Promise<AgentFound>;
}

const DAY_MS = 86_400_000;

/**
 * The pending change's SHA-256: the organisation, the name as it will be kept
 * (composed, NFC, so the same name typed either way binds the same change) and
 * the scopes as they will be sealed. Who owns it needs no place here: the
 * challenge is bound to the member's own session, and a person has one
 * membership in an organisation, read again at the confirm.
 */
const registrationHash = (orgId: string, { name, scopes }: AgentAsked): Buffer =>
  changeHashOf([REGISTER_OPERATION, orgId.toLowerCase(), name.normalize('NFC'), scopesText(scopes)]);

export function createAgentRegistrations({
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
}): AgentRegistrations {
  const work = createAgentWork({ database, keys, ids, logger });

  return {
    async ask(member, idempotent, asked, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REGISTERING_ROLES);
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: REGISTER_OPERATION,
          changeHash: registrationHash(member.orgId, asked),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new AgentRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, asked, stepUpChallengeId, correlationId) {
      let key: string | null = null;
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await oneAgentAddAtATime(tx, member.orgId);
        const { membershipId, role } = await work.memberIn(tx, states, member, REGISTERING_ROLES);
        const now = clock.now();
        if ((await agentsAddedSince(tx, member.orgId, new Date(now.getTime() - DAY_MS))) >= MOST_AGENTS_ADDED_A_DAY) {
          throw new AgentRefused(409, 'AGENT_ADDS_SPENT');
        }
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: REGISTER_OPERATION,
            changeHash: registrationHash(member.orgId, asked),
          },
          // An admin's change is proved with a passkey (SEC-HA-12); a developer's with their second factor.
          { passkeyRequired: role === 'admin' },
        );
        if (consumed === undefined) throw new AgentRefused(403, 'STEP_UP_FAILED');
        const actor = { type: 'user' as const, id: member.userId };
        const agentId = ids.next();
        await addAgent(tx, states, {
          orgId: member.orgId,
          id: agentId,
          name: asked.name,
          owner: membershipId,
          scopes: asked.scopes,
          createdAt: now,
          actor,
          details: stepUpDetails(consumed),
        });
        key = (await work.issueKey(tx, states, { orgId: member.orgId, agentId, scopes: asked.scopes, now, actor }))
          .text;
        return { status: 201, resourceId: agentId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      // Answered from the agent as it now stands. The key is set only by a write done now: a retry answers it as null, as it was shown once.
      const agent = await work.answered(member.orgId, correlationId, (tx, states) =>
        work.withKeys(tx, states, member.orgId, done.result.resourceId),
      );
      if ('outcome' in agent) return agent;
      return { outcome: 'registered', agent, key };
    },

    async list(orgId, page, correlationId) {
      const listed = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        agentsPage(tx, states, orgId, page),
      );
      if (listed.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
      return listed;
    },

    show(orgId, agentId, correlationId) {
      return work.answered(orgId, correlationId, async (tx, states) => ({
        outcome: 'found' as const,
        ...(await work.withKeys(tx, states, orgId, agentId)),
      }));
    },
  };
}
