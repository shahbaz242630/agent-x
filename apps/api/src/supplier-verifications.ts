// A supplier verified by a second person (ADR-012 §1, ADR-014 §3, ADR-003 §9;
// SEC-PAY-03, SEC-PAY-04, SEC-PAY-07; Phase 1 E3-2a): what makes a supplier
// payable.
//
// - `verify` (`suppliers.verify`), an admin or a finance approver, with the
//   call-back they made: the key claimed; everything below checked as the
//   confirm will; a challenge bound to the supplier's current version and the
//   note, so the passkey confirms exactly that.
// - `verifyConfirm` (`suppliers.verify.confirm`), with the challenge and the
//   same note: the same checks with the supplier read for change, the
//   challenge consumed with a passkey (SEC-HA-12), then the supplier VERIFIED
//   on its current version (the suppliers module's verifySupplier), the
//   step-up's evidence, the rule's path and the call-back on its event, and
//   `supplier_verified` written for every active member and the registered
//   contacts that count, in the same transaction.
//
// The checks, in the order a member would fix them: the verifier's own role;
// the supplier UNVERIFIED with no change waiting and a payee, cooled off, its
// name check not "no match" (a note for anything short of a match) and the
// call-back's phone the supplier's own (verificationProblem); then the
// two-person rule (E3-1) against everyone who entered its details since it
// was last verified (versionsToVerify), each in turn: one refusal refuses.
//
// Lock order (ADR-006 §6): the idempotency key, the memberships (2a: the
// verifier's, then every member's for the rule, all `share`), the supplier
// (6), its versions and the registration of its payee (never locked for
// change, so waiting on nothing), the step-up challenge, the chain head with
// the first event recorded, then the notices, new rows that wait on nothing.
import { type SignedStates, TooManyEventsToRead } from '@agentx/core/modules/audit';
import {
  changeHashOf,
  type StepUpChallenges,
  stepUpDetails,
  twoPersonFactsOf,
  type VerifierRefusal,
  type VerifierVerdict,
  verifierVerdict,
} from '@agentx/core/modules/identity';
import type { Notice, Outbox } from '@agentx/core/modules/notifications';
import {
  type VerificationProblem,
  verificationProblem,
  verifySupplier,
  versionsToVerify,
} from '@agentx/core/modules/suppliers';
import type { Clock, IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  createSupplierWork,
  type SessionMember,
  type SupplierChangeWrite,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
} from './supplier-work.ts';

/** Asking to verify a supplier: its operation, which the step-up challenge names as its action too. */
export const VERIFY_OPERATION = 'suppliers.verify';
/** Verifying it, once stepped up. */
export const VERIFY_CONFIRM_OPERATION = 'suppliers.verify.confirm';

/** Who may verify a supplier (partner, S69): the admins and the finance approvers. */
export const VERIFYING_ROLES = ['admin', 'approver'] as const;

/** The verifier's call-back: the tick, always (partner, S74), and their written note, or null. */
interface CallBack {
  readonly note: string | null;
}

export interface SupplierVerifications {
  verify(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    callBack: CallBack,
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
  verifyConfirm(
    member: SessionMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    confirm: CallBack & { readonly stepUpChallengeId: string },
    correlationId: string,
  ): Promise<SupplierChangeWrite>;
}

/** Each refusal of the supplier's state, as answered: all a conflict with the supplier as it stands. */
const PROBLEMS: Readonly<Record<VerificationProblem, ReasonCode>> = {
  SUPPLIER_NOT_UNVERIFIED: 'SUPPLIER_NOT_UNVERIFIED',
  SUPPLIER_CHANGE_WAITING: 'SUPPLIER_CHANGE_WAITING',
  SUPPLIER_NO_PAYEE: 'SUPPLIER_NO_PAYEE',
  SUPPLIER_COOLING_OFF: 'SUPPLIER_COOLING_OFF',
  SUPPLIER_NAME_MISMATCH: 'SUPPLIER_NAME_MISMATCH',
  SUPPLIER_CALL_NOTE_NEEDED: 'SUPPLIER_CALL_NOTE_NEEDED',
  SUPPLIER_PHONE_TOO_NEW: 'SUPPLIER_PHONE_TOO_NEW',
};

/** Each refusal of the verifier, as answered: the verifier may not, so forbidden. */
const REFUSALS: Readonly<Record<VerifierRefusal, ReasonCode>> = {
  NOT_A_VERIFIER: 'FORBIDDEN',
  SAME_PERSON: 'VERIFIER_ENTERED_DETAILS',
  VERIFIER_GRANTED_BY_ENTERER: 'VERIFIER_GRANTED_BY_ENTERER',
  VERIFIER_TOO_NEW: 'VERIFIER_TOO_NEW',
  SOLO_PATH_LOCKED: 'SOLO_PATH_LOCKED',
};

/**
 * The verification's SHA-256: the supplier's current version, its ID in lower
 * case, and the note (none: empty). That version is the supplier's own, read
 * from its signed state inside the organisation's walls, so it names the
 * organisation, the supplier and exactly the details verified.
 */
const verificationHash = (versionId: string, note: string | null): Buffer =>
  changeHashOf([VERIFY_OPERATION, versionId.toLowerCase(), note ?? '']);

/** The notice of a verification, for every active member and for the contacts that count, as the sender finds them. */
const toldOfVerification = (orgId: string, supplierId: string): Notice[] => {
  const about = { orgId, kind: 'supplier_verified' as const, membershipId: null, role: null, aboutId: supplierId };
  return [
    { ...about, recipientUserId: null },
    { ...about, recipientUserId: null, toContacts: true },
  ];
};

/** The rule's verdicts against every enterer, as one: the first refusal; else alone if any is; else two people. */
function combined(verdicts: readonly VerifierVerdict[]): VerifierVerdict {
  const refused = verdicts.find(({ outcome }) => outcome === 'refused');
  if (refused !== undefined) return refused;
  return verdicts.some(({ outcome }) => outcome === 'single_user')
    ? { outcome: 'single_user' }
    : { outcome: 'two_person' };
}

export function createSupplierVerifications({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Database<SupplierTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): SupplierVerifications {
  const work = createSupplierWork({ database, keys, ids, logger });

  /**
   * Whether this member may verify the supplier now, with this call-back,
   * read in the write's transaction (the supplier `lock`ed as asked): the
   * supplier, its current version and the rule's path; or a refusal thrown.
   */
  const verifiable = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SessionMember,
    supplierId: string,
    { note }: CallBack,
    lock: 'share' | 'change',
  ) => {
    const { orgId } = member;
    const verifier = await work.memberIn(tx, states, member, VERIFYING_ROLES);
    const facts = await twoPersonFactsOf(tx, states, orgId);
    if (facts.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    const found = await work.supplierIn(tx, states, { orgId, id: supplierId }, lock);
    const current = await work.versionIn(tx, states, orgId, found.supplier.id, found.supplier.currentVersionId);
    const registration = await work.registrationFor(tx, states, orgId, current);
    const versions = await versionsToVerify(tx, states, orgId, found.supplier, current);
    if (versions.outcome === 'tampered' || versions.outcome === 'incomplete') {
      throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    }
    if (versions.outcome === 'too_many') throw new SupplierRefused(409, 'HISTORY_TOO_LONG');
    const now = clock.now();
    const problem = verificationProblem(
      {
        supplier: found.supplier,
        current,
        nameCheck: registration?.nameCheck ?? null,
        firstEnteredAt: versions.first.enteredAt,
        note,
      },
      now,
    );
    if (problem !== undefined) throw new SupplierRefused(409, PROBLEMS[problem]);
    const enterers = [...new Set(versions.since.map(({ enteredBy }) => enteredBy))];
    const verdict = combined(
      enterers.map((enteredById) => verifierVerdict(facts, { enteredById, verifierId: verifier.id }, now)),
    );
    if (verdict.outcome === 'refused') throw new SupplierRefused(403, REFUSALS[verdict.reason]);
    return { verifier, found, current, registration, path: verdict.outcome };
  };

  /** The write, a history past its cap answered as a refusal like any other. */
  const write = async (...args: Parameters<typeof work.write>) => {
    try {
      return await work.write(...args);
    } catch (error) {
      if (!(error instanceof TooManyEventsToRead)) throw error;
      return { outcome: 'refused' as const, status: 409, code: 'HISTORY_TOO_LONG' as const };
    }
  };

  return {
    async verify(member, idempotent, supplierId, callBack, correlationId) {
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        const { current } = await verifiable(tx, states, member, supplierId, callBack, 'share');
        const challenge = await challenges.open(tx, {
          sessionId: member.sessionId,
          action: VERIFY_OPERATION,
          changeHash: verificationHash(current.id, callBack.note),
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new SupplierRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      return work.askedAfter(done);
    },

    async verifyConfirm(member, idempotent, supplierId, { stepUpChallengeId, note }, correlationId) {
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        const { orgId } = member;
        const { verifier, found, current, registration, path } = await verifiable(
          tx,
          states,
          member,
          supplierId,
          { note },
          'change',
        );
        const consumed = await challenges.consume(
          tx,
          stepUpChallengeId,
          { sessionId: member.sessionId, action: VERIFY_OPERATION, changeHash: verificationHash(current.id, note) },
          // A change that makes a supplier payable: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new SupplierRefused(403, 'STEP_UP_FAILED');
        await verifySupplier(tx, states, { orgId, id: found.supplier.id }, found, {
          verifiedBy: verifier.id,
          actor: { type: 'user', id: member.userId },
          details: {
            ...stepUpDetails(consumed),
            path,
            calledBack: true,
            nameCheck: registration?.nameCheck ?? 'none',
            ...(note === null ? {} : { callBackNote: note }),
          },
        });
        await outbox.add(tx, toldOfVerification(orgId, found.supplier.id));
        return { status: 200, resourceId: found.supplier.id };
      });
      return work.changedAfter(member.orgId, correlationId, done);
    },
  };
}
