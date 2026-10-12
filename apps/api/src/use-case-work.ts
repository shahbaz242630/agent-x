// What the agents', funding sources' and suppliers' use cases share (S79,
// one copy where agent-writes.ts, funding-source-work.ts and supplier-work.ts
// each had their own): the organisation's transaction with its signed
// states; a write with its idempotency key claimed first; a read; and the
// member read again for the decision. A refusal is thrown inside the work as
// the area's own UseCaseRefused subclass, so everything the write did rolls
// back and the same key may be sent again, and only that area's refusals are
// answered as a plain outcome.
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  type ConsumedStepUp,
  type HeldChallenges,
  type IdentityTables,
  membershipOf,
  type MembershipsTransaction,
  type Role,
  type StepUpBinding,
  type StepUpChallenges,
} from '@agentx/core/modules/identity';
import type { IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
import {
  createIdempotentWrites,
  type Database,
  type DatabaseTransaction,
  type IdempotentRequest,
  type IdempotentWrite,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Refused, refused } from './refused.ts';

/** A refusal thrown inside a write or a read, so everything it did rolls back; each area keeps its own subclass. */
export class UseCaseRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`refused: ${code}`);
    this.name = new.target.name;
    this.status = status;
    this.code = code;
  }
}

/** The tables every use case's transaction has; each area adds its own. */
export type UseCaseTables = IdentityTables & DirectoryTables & AuditTables;

/** Who is acting: a signed-in member, in the organisation the access hook verified. */
export interface Member {
  readonly orgId: string;
  readonly userId: string;
}

/** A member acting in a session of theirs. */
export interface SessionMember extends Member {
  /** The session a step-up binds to (ADR-003 §7). */
  readonly sessionId: string;
}

/** A write's answer: its key's outcome, or the area's refusal. */
export type Written = IdempotentWrite | Refused;

// A status move the work's own read said it may make (the shared kernel's, also core's: D7).
export { movedAsRead } from '@agentx/core/shared-kernel';

export function createUseCaseWork<Tables extends UseCaseTables>({
  database,
  keys,
  ids,
  logger,
  Refusal,
}: {
  /** Both: the work's transaction has every table the area's has, withSignedStates's the shared ones. */
  readonly database: Database<Tables> & Database<UseCaseTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  /** The area's own refusal: the only one its writes and reads answer. */
  readonly Refusal: new (status: number, code: ReasonCode) => UseCaseRefused;
}) {
  type Tx = DatabaseTransaction<Tables>;

  /** Runs the work in the organisation's transaction, each statement limited to 10 seconds. */
  const inOrganisation = <T>(
    orgId: string,
    correlationId: string,
    work: (tx: Tx, states: SignedStates) => Promise<T>,
  ): Promise<T> => withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }) }, work);

  /** The work's answer, or its area's refusal as a plain outcome. */
  const orRefused = async <T>(run: () => Promise<T>): Promise<T | Refused> => {
    try {
      return await run();
    } catch (error) {
      if (error instanceof Refusal) return refused(error.status, error.code);
      throw error;
    }
  };

  return {
    inOrganisation,

    /**
     * The write with its key claimed first; a refusal is answered, with
     * everything it did rolled back. A member's or an agent's: only its
     * organisation is read.
     */
    write: (
      member: Pick<Member, 'orgId'>,
      idempotent: IdempotentRequest,
      correlationId: string,
      work: (tx: Tx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
    ): Promise<Written> => {
      const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
      return orRefused(() =>
        inOrganisation(member.orgId, correlationId, (tx, states) =>
          idempotency.run(tx, idempotent, () => work(tx, states)),
        ),
      );
    },

    /** A read in the organisation's transaction, a refusal inside it answered. */
    answered: <T extends object>(
      orgId: string,
      correlationId: string,
      work: (tx: Tx, states: SignedStates) => Promise<T>,
    ): Promise<T | Refused> => orRefused(() => inOrganisation(orgId, correlationId, work)),

    /** The member's membership, read again for this decision: active in one of `roles`, or FORBIDDEN (INTEGRITY_FAILED if tampered with). */
    memberIn: async (tx: MembershipsTransaction, states: SignedStates, member: Member, roles: readonly Role[]) => {
      const membership = await membershipOf(tx, states, member.orgId, member.userId);
      if (membership.outcome === 'tampered') throw new Refusal(503, 'INTEGRITY_FAILED');
      if (membership.outcome !== 'active' || !roles.includes(membership.role)) throw new Refusal(403, 'FORBIDDEN');
      return membership;
    },
  };
}

type ChallengeHandle = Parameters<StepUpChallenges['open']>[0];

/**
 * A change's step-up (ADR-003 §7), one copy for every use case asking one
 * (S101, eleven had their own): the ask opens the challenge, the confirm
 * uses it in the change's own transaction. Both bind the member's session:
 * `consume` refuses a hold of any other, so a confirm holding the wrong one throws.
 */
export function createStepUps({
  challenges,
  Refusal,
}: {
  readonly challenges: StepUpChallenges;
  readonly Refusal: new (status: number, code: ReasonCode) => UseCaseRefused;
}) {
  return {
    /** Opens the challenge, the write's resource, so a retry answers the same one. */
    ask: async (
      tx: ChallengeHandle,
      member: SessionMember,
      change: Omit<StepUpBinding, 'sessionId'>,
    ): Promise<{ status: number; resourceId: string }> => {
      const challenge = await challenges.open(tx, { sessionId: member.sessionId, ...change });
      // The session ended since the access hook found it.
      if (challenge === undefined) throw new Refusal(401, 'UNAUTHENTICATED');
      return { status: 202, resourceId: challenge.challengeId };
    },

    /** Uses the challenge for exactly this change, or STEP_UP_FAILED. An admin's change needs a passkey (SEC-HA-12). */
    consumed: async (
      tx: ChallengeHandle,
      member: SessionMember,
      held: HeldChallenges,
      stepUpChallengeId: string,
      change: Omit<StepUpBinding, 'sessionId'>,
      need: { readonly passkeyRequired: boolean },
    ): Promise<ConsumedStepUp> => {
      const consumed = await challenges.consume(
        tx,
        held,
        stepUpChallengeId,
        { sessionId: member.sessionId, ...change },
        need,
      );
      if (consumed === undefined) throw new Refusal(403, 'STEP_UP_FAILED');
      return consumed;
    },
  };
}
