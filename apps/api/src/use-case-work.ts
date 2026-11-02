// What the agents', funding sources' and suppliers' use cases share (S79,
// one copy where agent-writes.ts, funding-source-work.ts and supplier-work.ts
// each had their own): the organisation's transaction with its signed
// states; a write with its idempotency key claimed first; a read; and the
// member read again for the decision. A refusal is thrown inside the work as
// the area's own UseCaseRefused subclass, so everything the write did rolls
// back and the same key may be sent again, and only that area's refusals are
// answered as a plain outcome.
import { type AuditTables, type SignedStates, TooManyEventsToRead, withSignedStates } from '@agentx/core/modules/audit';
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
  holdRoutineBrakeNamed,
  isLockWaitRunOut,
  isRetryable,
  isStatementLimit,
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

/** A stop that couldn't take hold: agents can still act, so the alarm. */
const stopNotApplied = (log: Logger, fields: { readonly waitedMs: number }): void => {
  log.error('brake.not_applied', fields);
};

/** A routine change that couldn't take hold: the old rules still apply, so nothing to raise an alarm for. */
const routineChangeBusy = (log: Logger, fields: { readonly waitedMs: number }): void => {
  log.warn('brake.routine_change_busy', fields);
};

/**
 * A brake's write (an organisation's freeze, an agent's kill switch; PL-63 item 3): its wait for a lock run out, a
 * statement past its limit, or a deadlock lost, rolled it all back, so nothing is stopped: answered busy, its key free
 * to send again, and the alarm raised, as an admin's brake failing is never routine. A 57014 is taken as a wait: a
 * brake's statements read and write a few rows, and row locks can restart their wait past the statement's limit.
 */
export async function braked(
  logger: Logger,
  orgId: string,
  correlationId: string,
  write: () => Promise<Written>,
  gaveUp = stopNotApplied,
): Promise<Written> {
  const started = performance.now();
  try {
    return await write();
  } catch (error) {
    if (!isLockWaitRunOut(error) && !isStatementLimit(error) && !isRetryable(error)) throw error;
    gaveUp(logger.child({ correlationId, orgId }), { waitedMs: Math.round(performance.now() - started) });
    return refused(503, 'ORGANISATION_BUSY');
  }
}

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
  ): Promise<T> =>
    withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }), correlationId }, work);

  /** The work's answer, or its area's refusal as a plain outcome. */
  const orRefused = async <T>(run: () => Promise<T>): Promise<T | Refused> => {
    try {
      return await run();
    } catch (error) {
      if (error instanceof Refusal) return refused(error.status, error.code);
      throw error;
    }
  };

  /**
   * The write with its key claimed first; a refusal is answered, with
   * everything it did rolled back. A member's or an agent's: only its
   * organisation is read.
   */
  const write = (
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
  };

  /**
   * write, with `hold` taking a brake first, before any row: braked's answer if it can't.
   */
  const brakeWrite = (
    member: Pick<Member, 'orgId'>,
    idempotent: IdempotentRequest,
    correlationId: string,
    hold: (tx: Tx) => Promise<void>,
    work: (tx: Tx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ): Promise<Written> =>
    braked(logger, member.orgId, correlationId, () =>
      write(member, idempotent, correlationId, async (tx, states) => {
        await hold(tx);
        return work(tx, states);
      }),
    );

  /**
   * brakeWrite for a routine change (a policy, a draft, a consent choice): the brake `name` names, with a routine
   * change's shorter wait and its quieter line. The one way to either, so they can't part.
   */
  const routineBrakeWrite = (
    member: Pick<Member, 'orgId'>,
    idempotent: IdempotentRequest,
    correlationId: string,
    name: Parameters<typeof holdRoutineBrakeNamed>[1],
    work: (tx: Tx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ): Promise<Written> =>
    braked(
      logger,
      member.orgId,
      correlationId,
      () =>
        write(member, idempotent, correlationId, async (tx, states) => {
          await holdRoutineBrakeNamed(tx, name);
          return work(tx, states);
        }),
      routineChangeBusy,
    );

  return {
    inOrganisation,
    write,
    brakeWrite,
    routineBrakeWrite,

    /** The write, a history past its read's cap (the two-person rule's, a supplier's versions) answered HISTORY_TOO_LONG. */
    historyBounded: async (...args: Parameters<typeof write>): Promise<Written> => {
      try {
        return await write(...args);
      } catch (error) {
        if (!(error instanceof TooManyEventsToRead)) throw error;
        return refused(409, 'HISTORY_TOO_LONG');
      }
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
