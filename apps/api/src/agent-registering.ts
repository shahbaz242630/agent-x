// Registering an AI agent with its first key (ADR-011 §1, ADR-003 §8, BR-03;
// Phase 1 C1-2). Composed here, in the API, as ADR-004 §7 has it: the step-up
// is the identity module's, the agent and its key the agents module's, and
// the agents module never depends on identity. One transaction, the
// organisation's, holds both.
//
// 1. `ask` (`agents.register`): the key claimed first; the member read again,
//    active and an admin or developer; then a step-up challenge for their own
//    session, bound to the organisation, the member, the name and the scopes.
//    The challenge is the write's resource, so a retry answers the same one.
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
// A refusal throws inside the write, so the claim and everything written roll
// back and the same key may be sent again. Each statement is limited to 10
// seconds. Lock order (ADR-006 §6): the idempotency key, the add lock, the
// member's membership (2a), the step-up challenge, the agent (3), its key
// (3a), the chain head last.
import { randomBytes } from 'node:crypto';

import {
  addAgent,
  addAgentKey,
  agentKeysOf,
  type AgentKeyRecord,
  agentOf,
  agentsAddedSince,
  type AgentShown,
  agentsPage,
  agentsShown,
  type AgentsTables,
  agentKeyText,
  KEY_SECRET_BYTES,
  keyExpiresAt,
  keySecretMessage,
  MOST_AGENTS_ADDED_A_DAY,
  oneAgentAddAtATime,
  type Scope,
  scopesText,
} from '@agentx/core/modules/agents';
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  changeHashOf,
  type IdentityTables,
  membershipOf,
  type StepUpChallenges,
  stepUpDetails,
} from '@agentx/core/modules/identity';
import type { Clock, IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
import {
  createIdempotentWrites,
  type Database,
  type DatabaseTransaction,
  type IdempotentRequest,
  limitStatements,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** Asking to register an agent: its operation, which the step-up challenge names as its action too. */
export const REGISTER_OPERATION = 'agents.register';
/** Registering it, once stepped up. */
export const REGISTER_CONFIRM_OPERATION = 'agents.register.confirm';

/** The roles that may register an agent (BRD §4: the developer registers it; the admin holds authority). */
export const REGISTERING_ROLES = ['admin', 'developer'] as const;

/** Who is registering: a signed-in member, in the organisation the access hook verified, and their session. */
export interface RegisteringMember {
  readonly orgId: string;
  readonly userId: string;
  /** The session the step-up binds to (ADR-003 §7). */
  readonly sessionId: string;
}

/** The agent asked for: its name and scopes, the same on the ask and the confirm. */
export interface AgentAsked {
  readonly name: string;
  readonly scopes: readonly Scope[];
}

interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}

/** An agent with its keys, as an answer shows it. */
export interface AgentWithKeys {
  readonly agent: AgentShown;
  readonly keys: readonly AgentKeyRecord[];
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

class RegistrationRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`an agent's registration refused: ${code}`);
    this.name = 'RegistrationRefused';
    this.status = status;
    this.code = code;
  }
}

type Tables = IdentityTables & AgentsTables & DirectoryTables & AuditTables;
/** The organisation's transaction, on the tables of both modules it holds. */
type Tx = DatabaseTransaction<Tables>;

const DAY_MS = 86_400_000;

/**
 * The pending change's SHA-256: the organisation, the member's membership,
 * the name as it will be kept and the scopes as they will be sealed. The name
 * is composed (NFC) by the caller's check, so the same name typed either way
 * binds the same change.
 */
const registrationHash = (orgId: string, membershipId: string, { name, scopes }: AgentAsked): Buffer =>
  changeHashOf([
    REGISTER_OPERATION,
    orgId.toLowerCase(),
    membershipId.toLowerCase(),
    name.normalize('NFC'),
    scopesText(scopes),
  ]);

export function createAgentRegistrations({
  database,
  keys,
  ids,
  clock,
  challenges,
  logger,
}: {
  readonly database: Database<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): AgentRegistrations {
  /** The member's membership, read again for this decision: active, and one who may register, or a refusal. */
  const registrantOf = async (
    tx: Tx,
    states: SignedStates,
    member: RegisteringMember,
  ): Promise<{ membershipId: string; isAdmin: boolean }> => {
    const membership = await membershipOf(tx, states, member.orgId, member.userId);
    if (membership.outcome === 'tampered') throw new RegistrationRefused(503, 'INTEGRITY_FAILED');
    if (membership.outcome !== 'active' || !REGISTERING_ROLES.some((role) => role === membership.role)) {
      throw new RegistrationRefused(403, 'FORBIDDEN');
    }
    return { membershipId: membership.id, isAdmin: membership.role === 'admin' };
  };

  /** Runs the work in the organisation's transaction, each statement limited to 10 seconds. */
  const inOrganisation = <T>(
    orgId: string,
    correlationId: string,
    work: (tx: Tx, states: SignedStates) => Promise<T>,
  ): Promise<T> =>
    withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }) }, async (tx, states) => {
      await limitStatements(tx);
      return work(tx, states);
    });

  /** Runs the write with its key claimed first; a refusal is answered, with everything it did rolled back. */
  const write = async (
    member: RegisteringMember,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: Tx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
    try {
      return await inOrganisation(member.orgId, correlationId, (tx, states) =>
        idempotency.run(tx, idempotent, () => work(tx, states)),
      );
    } catch (error) {
      if (error instanceof RegistrationRefused) {
        return { outcome: 'refused' as const, status: error.status, code: error.code };
      }
      throw error;
    }
  };

  /** The agent and its keys, read and verified; a refusal for one missing or tampered with. */
  const withKeys = async (tx: Tx, states: SignedStates, orgId: string, agentId: string): Promise<AgentWithKeys> => {
    const read = await agentOf(tx, states, { orgId, id: agentId }, 'share');
    if (read.outcome === 'tampered') throw new RegistrationRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new RegistrationRefused(404, 'NOT_FOUND');
    const listed = await agentKeysOf(tx, states, orgId, agentId);
    if (listed.outcome === 'tampered') throw new RegistrationRefused(503, 'INTEGRITY_FAILED');
    const [agent] = await agentsShown(tx, orgId, [read.agent]);
    if (agent === undefined) throw new Error('an agent read has nothing to show');
    return { agent, keys: listed.keys };
  };

  /** Answers a read, a refusal inside it included. */
  const answered = async <T extends object>(
    orgId: string,
    correlationId: string,
    work: (tx: Tx, states: SignedStates) => Promise<T>,
  ): Promise<T | Refused> => {
    try {
      return await inOrganisation(orgId, correlationId, work);
    } catch (error) {
      if (error instanceof RegistrationRefused) return { outcome: 'refused', status: error.status, code: error.code };
      throw error;
    }
  };

  return {
    async ask(member, idempotent, asked, correlationId) {
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        const { membershipId } = await registrantOf(tx, states, member);
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: REGISTER_OPERATION,
          changeHash: registrationHash(member.orgId, membershipId, asked),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new RegistrationRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(member, idempotent, asked, stepUpChallengeId, correlationId) {
      let key: string | null = null;
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        await oneAgentAddAtATime(tx, member.orgId);
        const { membershipId, isAdmin } = await registrantOf(tx, states, member);
        const now = clock.now();
        if ((await agentsAddedSince(tx, member.orgId, new Date(now.getTime() - DAY_MS))) >= MOST_AGENTS_ADDED_A_DAY) {
          throw new RegistrationRefused(409, 'AGENT_ADDS_SPENT');
        }
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          {
            sessionId: member.sessionId,
            action: REGISTER_OPERATION,
            changeHash: registrationHash(member.orgId, membershipId, asked),
          },
          // An admin's change is proved with a passkey (SEC-HA-12); a developer's with their second factor.
          { passkeyRequired: isAdmin },
        );
        if (consumed === undefined) throw new RegistrationRefused(403, 'STEP_UP_FAILED');
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
        const keyId = ids.next();
        const secret = randomBytes(KEY_SECRET_BYTES);
        const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(keyId, secret));
        await addAgentKey(tx, states, {
          orgId: member.orgId,
          id: keyId,
          agentId,
          scopes: asked.scopes,
          secretMac: mac,
          secretKeyVersion: keyVersion,
          expiresAt: keyExpiresAt(now),
          createdAt: now,
          actor,
        });
        key = agentKeyText(keyId, secret);
        return { status: 201, resourceId: agentId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      // Answered from the agent as it now stands; on a retry, without the key, which was shown once.
      const agent = await answered(member.orgId, correlationId, (tx, states) =>
        withKeys(tx, states, member.orgId, done.result.resourceId),
      );
      if ('outcome' in agent) return agent;
      return { outcome: 'registered', agent, key: done.outcome === 'done' ? key : null };
    },

    async list(orgId, page, correlationId) {
      const listed = await inOrganisation(orgId, correlationId, (tx, states) => agentsPage(tx, states, orgId, page));
      if (listed.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
      return listed;
    },

    async show(orgId, agentId, correlationId) {
      const found = await answered(orgId, correlationId, async (tx, states) => ({
        outcome: 'found' as const,
        ...(await withKeys(tx, states, orgId, agentId)),
      }));
      return found;
    },
  };
}
