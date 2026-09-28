// What the agents' use cases share (C1-2, C1-3): the organisation's
// transaction, each statement limited to 10 seconds; a write with its
// idempotency key claimed first; the caller's membership read again; and an
// agent read with its keys. A refusal is thrown inside the work as
// AgentRefused, so everything the write did rolls back and the same key may
// be sent again, and answered as a plain outcome.
import {
  agentKeysOf,
  type AgentKeyRecord,
  agentOf,
  type AgentShown,
  agentsShown,
  type AgentsTables,
} from '@agentx/core/modules/agents';
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
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
  };
}
