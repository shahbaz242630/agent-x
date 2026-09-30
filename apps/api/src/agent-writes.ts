// What the agents' use cases share (C1-2, C1-3): the organisation's
// transaction, each statement limited to 10 seconds; a write with its
// idempotency key claimed first; the caller's membership read again; and an
// agent read with its keys; a key issued, and the day's budget for issuing
// them. A refusal is thrown inside the work as
// AgentRefused, so everything the write did rolls back and the same key may
// be sent again, and answered as a plain outcome.
import { randomBytes } from 'node:crypto';

import {
  addAgentKey,
  agentKeysOf,
  type AgentKeyRecord,
  agentKeyText,
  agentOf,
  type AgentShown,
  agentsShown,
  type AgentsTables,
  KEY_SECRET_BYTES,
  keyExpiresAt,
  keySecretMessage,
  keysIssuedSince,
  MOST_KEYS_ISSUED_A_DAY,
  type Scope,
} from '@agentx/core/modules/agents';
import {
  type AuditActor,
  type AuditDetails,
  type AuditTables,
  type SignedStates,
  withSignedStates,
} from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type IdentityTables, membershipOf, type Role } from '@agentx/core/modules/identity';
import type { IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
import {
  createIdempotentWrites,
  type Database,
  type DatabaseTransaction,
  type IdempotentRequest,
  type IdempotentWrite,
  limitStatements,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** The tables the agents' use cases work on: both modules', with the directory and the audit trail. */
export type AgentTables = IdentityTables & AgentsTables & DirectoryTables & AuditTables;
/** The organisation's transaction, on those tables. */
export type AgentTx = DatabaseTransaction<AgentTables>;

/** Who is acting: a signed-in member, in the organisation the access hook verified, and their session. */
export interface AgentMember {
  readonly orgId: string;
  readonly userId: string;
  /** The session a step-up binds to (ADR-003 §7). */
  readonly sessionId: string;
}

/** A refusal, as a use case answers it. */
export interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}

/** An agent with its keys, as an answer shows it. */
export interface AgentWithKeys {
  readonly agent: AgentShown;
  readonly keys: readonly AgentKeyRecord[];
}

/** A new key for an agent, as issueKey takes it. */
interface KeyToIssue {
  readonly orgId: string;
  readonly agentId: string;
  readonly scopes: readonly Scope[];
  /** When it is issued: it expires KEY_DAYS after. */
  readonly now: Date;
  readonly actor: AuditActor;
  /** More facts for its event, such as the step-up it was confirmed with. */
  readonly details?: AuditDetails;
}

const DAY_MS = 86_400_000;

/** A refusal thrown inside a write or a read, answered as `Refused`. */
export class AgentRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`an agent's write or read refused: ${code}`);
    this.name = 'AgentRefused';
    this.status = status;
    this.code = code;
  }
}

const refusedOf = (error: AgentRefused): Refused => ({ outcome: 'refused', status: error.status, code: error.code });

export interface AgentWork {
  /** Runs the work in the organisation's transaction, each statement limited to 10 seconds. */
  inOrganisation<T>(
    orgId: string,
    correlationId: string,
    work: (tx: AgentTx, states: SignedStates) => Promise<T>,
  ): Promise<T>;
  /** Runs the write with its key claimed first; a refusal is answered, with everything it did rolled back. */
  write(
    member: AgentMember,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: AgentTx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ): Promise<IdempotentWrite | Refused>;
  /** Runs a read in the organisation's transaction, a refusal inside it answered. */
  answered<T extends object>(
    orgId: string,
    correlationId: string,
    work: (tx: AgentTx, states: SignedStates) => Promise<T>,
  ): Promise<T | Refused>;
  /**
   * The member's membership, read again for this decision: active with one of
   * `roles`, or FORBIDDEN (INTEGRITY_FAILED if it was tampered with).
   */
  memberIn(
    tx: AgentTx,
    states: SignedStates,
    member: AgentMember,
    roles: readonly Role[],
  ): Promise<{ readonly membershipId: string; readonly role: Role }>;
  /** The agent and its keys, read (`share`) and verified: NOT_FOUND, or INTEGRITY_FAILED, otherwise. */
  withKeys(tx: AgentTx, states: SignedStates, orgId: string, agentId: string): Promise<AgentWithKeys>;
  /**
   * Refuses a key past the organisation's budget for the day
   * (MOST_KEYS_ISSUED_A_DAY, first keys included): AGENT_KEYS_SPENT. Counted
   * under oneKeyIssueAtATime in a write that issues one; an ask's early
   * check may count without it.
   */
  keyBudgetLeft(tx: AgentTx, orgId: string, now: Date): Promise<void>;
  /**
   * Issues a new key for the agent, ACTIVE, expiring KEY_DAYS from `now`: its
   * secret random, only its MAC kept (with the pepper's version). Answers its
   * ID, and the key itself, `axk_<keyId>_<secret>`, for the write to show
   * this once.
   */
  issueKey(tx: AgentTx, states: SignedStates, key: KeyToIssue): Promise<{ readonly id: string; readonly text: string }>;
}

export function createAgentWork({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<AgentTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): AgentWork {
  const inOrganisation: AgentWork['inOrganisation'] = (orgId, correlationId, work) =>
    withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }) }, async (tx, states) => {
      await limitStatements(tx);
      return work(tx, states);
    });

  return {
    inOrganisation,

    async write(member, idempotent, correlationId, work) {
      const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
      try {
        return await inOrganisation(member.orgId, correlationId, (tx, states) =>
          idempotency.run(tx, idempotent, () => work(tx, states)),
        );
      } catch (error) {
        if (error instanceof AgentRefused) return refusedOf(error);
        throw error;
      }
    },

    async answered(orgId, correlationId, work) {
      try {
        return await inOrganisation(orgId, correlationId, work);
      } catch (error) {
        if (error instanceof AgentRefused) return refusedOf(error);
        throw error;
      }
    },

    async memberIn(tx, states, member, roles) {
      const membership = await membershipOf(tx, states, member.orgId, member.userId);
      if (membership.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
      if (membership.outcome !== 'active' || !roles.includes(membership.role)) {
        throw new AgentRefused(403, 'FORBIDDEN');
      }
      return { membershipId: membership.id, role: membership.role };
    },

    async withKeys(tx, states, orgId, agentId) {
      const read = await agentOf(tx, states, { orgId, id: agentId }, 'share');
      if (read.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
      if (read.outcome === 'missing') throw new AgentRefused(404, 'NOT_FOUND');
      const listed = await agentKeysOf(tx, states, orgId, agentId);
      if (listed.outcome === 'tampered') throw new AgentRefused(503, 'INTEGRITY_FAILED');
      const [agent] = await agentsShown(tx, orgId, [read.agent]);
      if (agent === undefined) throw new Error('an agent read has nothing to show');
      return { agent, keys: listed.keys };
    },

    async keyBudgetLeft(tx, orgId, now) {
      if ((await keysIssuedSince(tx, orgId, new Date(now.getTime() - DAY_MS))) >= MOST_KEYS_ISSUED_A_DAY) {
        throw new AgentRefused(409, 'AGENT_KEYS_SPENT');
      }
    },

    async issueKey(tx, states, { orgId, agentId, scopes, now, actor, details }) {
      const keyId = ids.next();
      const secret = randomBytes(KEY_SECRET_BYTES);
      const { mac, keyVersion } = keys.mac('agent-key-pepper', keySecretMessage(keyId, secret));
      await addAgentKey(tx, states, {
        orgId,
        id: keyId,
        agentId,
        scopes,
        secretMac: mac,
        secretKeyVersion: keyVersion,
        expiresAt: keyExpiresAt(now),
        createdAt: now,
        actor,
        ...(details !== undefined && { details }),
      });
      return { id: keyId, text: agentKeyText(keyId, secret) };
    },
  };
}
