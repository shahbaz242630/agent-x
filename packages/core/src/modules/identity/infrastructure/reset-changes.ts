// Asking for a reset of a member's lost second factor, sending it to the
// registered contacts, and cancelling it (ADR-003 §4, ADR-012 §8;
// SEC-OPS-04; B6-3b): an admin's change to another member, with a step-up
// (ADR-003 §8) to send it on, told to the person, the organisation's admins
// and, once sent, its contacts. A contact confirms it by its link (the public
// route, B6-3b-3), and the factor is removed after the cooling-off (B6-3c).
//
// 1. `ask` (`resets.ask`): any lapsed reset of the person's moved to EXPIRED
//    first, each in a transaction of its own (a reset read to check for open
//    ones can't be changed in the same transaction); then the key claimed;
//    the person's resets one ask at a time (a transaction advisory lock for
//    the organisation and person, so two asks can't both find none open);
//    the admin and the person read in order of membership ID (ADR-006 §6
//    level 2a): the admin active and still an admin, the organisation within
//    its budget of asks (RESET_ASKS_SPENT, B8-2), the person someone else
//    (OWN_RESET), listed as the directory says, active (MEMBER_DEACTIVATED)
//    and in no other organisation (MEMBER_ELSEWHERE: their login signs in to
//    each, and one organisation can't reset it for the others: the runbook);
//    the organisation's contacts (2b), one of them counting now
//    (NO_COUNTING_CONTACTS); the person's resets (2c), none open (RESET_OPEN);
//    then the pending change's SHA-256 bound into a step-up challenge for the
//    admin's own session, and the reset kept as a DRAFT naming it. 202.
// 2. `confirm` (`resets.ask.confirm`): the key claimed first; the person the
//    reset's row names, to read the memberships before the reset; the same
//    checks of the admin and the person; the contacts that count now; the
//    reset read for the change (2c), a DRAFT (RESET_CLOSED) not lapsed
//    (RESET_CLOSED), naming the same person, and its hash worked out again
//    from the verified row; the challenge it names consumed only for this
//    session, action and hash, with a passkey (SEC-HA-12); a secret written
//    for each contact that counts and the reset moved to AWAITING_CONTACT,
//    with the step-up's evidence; each of those contacts sent its link, and
//    the person and the admins told, in the same transaction.
// 3. `cancel` (`resets.cancel`): the key claimed first; the admin, active and
//    still an admin, and the person, read as in 2 (whatever their status: a
//    reset is always stoppable, by any admin, the person among them, and with
//    no step-up: stopping is never gated); the reset read for the change,
//    still open (RESET_CLOSED); CANCELLED; the person, the admins and, once
//    it was sent, the contacts told.
//
// A refusal throws inside the write, so the claim and everything written roll
// back and the same key may be sent again. Each statement is limited to 10
// seconds.
import { createIdempotentWrites, type IdempotentRequest, limitStatements } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { Clock, IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, type SignedStatesServices, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedElsewhere, listedMember, listedMembership } from '../../directory/index.ts';
import type { Notice, NoticeKind, NotificationsTables, Outbox } from '../../notifications/index.ts';
import {
  confirmableAt,
  hasLapsed,
  isOpenReset,
  MOST_RESETS_ASKED_A_DAY,
  resetExpiresAt,
} from '../domain/factor-reset.ts';
import { countsNow } from '../domain/registered-contact.ts';
import {
  askContacts,
  draftReset,
  listedPersonOf,
  MOST_RESET_RECORDS,
  moveReset,
  openResetsFor,
  resetChange,
  resetForChange,
  type ResetRecord,
  resetRecord,
  resetRecordsCount,
  resetsOf,
  TooManyResets,
} from './factor-resets.ts';
import type { InvitingAdmin } from './inviting.ts';
import { memberOf, type MemberRecord, type MembershipsTransaction } from './memberships.ts';
import { contactsOf, TooManyContacts } from './registered-contacts.ts';
import { type StepUpChallenges, stepUpDetails } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

const DAY_MS = 86_400_000;

/** Asking for a reset: its operation, which the step-up challenge names as its action too. */
export const RESET_ASK_OPERATION = 'resets.ask';
/** Sending it to the contacts, once stepped up. */
export const RESET_ASK_CONFIRM_OPERATION = 'resets.ask.confirm';
/** Cancelling it. */
export const RESET_CANCEL_OPERATION = 'resets.cancel';

/** What a reset's write answers. */
export type ResetChangeWrite =
  | {
      readonly outcome: 'written';
      readonly status: number;
      readonly reset: ResetRecord;
      /** The step-up to sign in again for, while the reset is a DRAFT. */
      readonly stepUpChallengeId?: string;
    }
  | { readonly outcome: 'conflict' | 'busy' }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

/** The organisation's resets, as the list reads them. */
export type ResetsList =
  | { readonly outcome: 'listed'; readonly resets: readonly ResetRecord[] }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

export interface ResetChanges {
  ask(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    membershipId: string,
    correlationId: string,
  ): Promise<ResetChangeWrite>;
  confirm(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    resetId: string,
    correlationId: string,
  ): Promise<ResetChangeWrite>;
  cancel(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    resetId: string,
    correlationId: string,
  ): Promise<ResetChangeWrite>;
  list(orgId: string, correlationId: string): Promise<ResetsList>;
}

class ResetRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`a reset's change refused: ${code}`);
    this.name = 'ResetRefused';
    this.status = status;
    this.code = code;
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables;

/** The admin's membership and the person's, as a reset's write reads them. */
interface People {
  readonly adminId: string;
  readonly person: MemberRecord;
}

/**
 * The notices about a reset of the person's second factor: to them, as
 * themselves, and to the organisation's admins but them, found as they are
 * sent; and to its ACTIVE contacts once it was sent to them.
 */
export const toldOfReset = (orgId: string, kind: NoticeKind, personUserId: string, toContacts: boolean): Notice[] => {
  const about = { orgId, kind, membershipId: null, role: null, aboutId: personUserId } as const;
  return [
    { ...about, recipientUserId: personUserId },
    { ...about, recipientUserId: null },
    ...(toContacts ? [{ ...about, recipientUserId: null, toContacts: true }] : []),
  ];
};

/** Each contact's own link to confirm the reset, read at send time (0026). */
const linksTo = (orgId: string, resetId: string, contactIds: readonly string[]): Notice[] =>
  contactIds.map((contactId) => ({
    orgId,
    kind: 'factor_reset_link',
    membershipId: null,
    role: null,
    aboutId: resetId,
    recipientUserId: null,
    recipientContactId: contactId,
  }));

/** Whether a reset in this status was sent to the contacts, who are then told how it ends. */
const sentToContacts = (reset: ResetRecord): boolean =>
  reset.status === 'AWAITING_CONTACT' || reset.status === 'COOLING_OFF';

export function createResetChanges({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  /** Where the notices of each change are written (0026). */
  readonly outbox: Outbox;
  readonly logger: Logger;
}): ResetChanges {
  const servicesFor = (correlationId: string): SignedStatesServices => ({
    keys,
    ids,
    logger: logger.child({ correlationId }),
  });

  /**
   * The admin's membership and the person's, each read for a decision
   * (`share`) in order of membership ID (level 2a): the admin active and
   * still an admin, and the person found, listed as the directory says,
   * whatever their status (the caller judges it).
   */
  const peopleOf = async (
    tx: MembershipsTransaction,
    states: SignedStates,
    admin: InvitingAdmin,
    personId: string,
  ): Promise<People> => {
    const adminId = await listedMembership(tx, admin.orgId, admin.userId);
    if (adminId === undefined) throw new ResetRefused(403, 'FORBIDDEN');
    const readAdmin = () => memberOf(tx, states, { orgId: admin.orgId, id: adminId }, 'share');
    const readPerson = () => memberOf(tx, states, { orgId: admin.orgId, id: personId }, 'share');
    const adminFirst = adminId < personId.toLowerCase();
    const first = await (adminFirst ? readAdmin() : readPerson());
    const second = adminId === personId.toLowerCase() ? first : await (adminFirst ? readPerson() : readAdmin());
    const [adminRead, personRead] = adminFirst ? [first, second] : [second, first];

    if (adminRead.outcome === 'tampered' || personRead.outcome === 'tampered') {
      throw new ResetRefused(503, 'INTEGRITY_FAILED');
    }
    if (
      adminRead.outcome !== 'found' ||
      adminRead.member.userId !== admin.userId.toLowerCase() ||
      adminRead.member.status !== 'ACTIVE' ||
      adminRead.member.role !== 'admin'
    ) {
      throw new ResetRefused(403, 'FORBIDDEN');
    }
    if (personRead.outcome !== 'found') throw new ResetRefused(404, 'NOT_FOUND');
    const { member: person } = personRead;
    // The directory's entry named someone else's membership: not this one's.
    if ((await listedMember(tx, admin.orgId, person.id)) !== person.userId) throw new ResetRefused(404, 'NOT_FOUND');
    return { adminId, person };
  };

  /** Refuses a person whose second factor this admin can't have reset in this organisation. */
  const mustBeResettable = async (tx: MembershipsTransaction, orgId: string, { adminId, person }: People) => {
    if (person.id === adminId) throw new ResetRefused(409, 'OWN_RESET');
    if (person.status !== 'ACTIVE') throw new ResetRefused(409, 'MEMBER_DEACTIVATED');
    if (await listedElsewhere(tx, orgId, person.userId)) throw new ResetRefused(409, 'MEMBER_ELSEWHERE');
  };

  /** The IDs of the organisation's contacts that count now (level 2b), each verified. */
  const countingContacts = async (tx: Transaction<Tables>, states: SignedStates, orgId: string) => {
    const listed = await contactsOf(tx, states, keys, orgId);
    if (listed.outcome === 'tampered') throw new ResetRefused(503, 'INTEGRITY_FAILED');
    const now = clock.now();
    return listed.contacts.filter((contact) => countsNow(contact, now)).map((contact) => contact.id);
  };

  /** Refuses an organisation none of whose contacts counts now: no one could confirm. */
  const someoneToConfirm = (contactIds: readonly string[]): void => {
    if (contactIds.length === 0) throw new ResetRefused(409, 'NO_COUNTING_CONTACTS');
  };

  /**
   * The reset, read for the change (level 2c) and verified, naming the person
   * its row named a moment ago. Gone since, or naming another, is the row
   * changed past the app (the app never deletes one, and its person is
   * sealed): refused as the tampering it is.
   */
  const resetOfPerson = async (
    tx: Transaction<Tables>,
    states: SignedStates,
    orgId: string,
    id: string,
    personId: string,
  ) => {
    const read = await resetForChange(tx, states, { orgId, id });
    if (read.outcome === 'tampered') throw new ResetRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing' || read.reset.person !== personId.toLowerCase()) {
      throw new ResetRefused(503, 'INTEGRITY_FAILED');
    }
    return read;
  };

  /**
   * Refuses an ask past the organisation's budget of MOST_RESETS_ASKED_A_DAY
   * (RESET_ASKS_SPENT, B8-2), and warns once its records pass half of what a
   * check reads, long before resets can't be asked. Counted under the
   * person's lock only, so asks for different people at once may pass it by
   * the few running together: a budget, not a boundary; the check's own
   * bound behind it is exact.
   */
  const withinBudget = async (tx: Transaction<Tables>, orgId: string, log: Logger): Promise<void> => {
    const count = await resetRecordsCount(tx, orgId, new Date(clock.now().getTime() - DAY_MS));
    if (count.held * 2 >= MOST_RESET_RECORDS)
      log.warn('identity.records_filling', { records: 'factor_resets', held: count.held, most: MOST_RESET_RECORDS });
    if (count.asked >= MOST_RESETS_ASKED_A_DAY) throw new ResetRefused(409, 'RESET_ASKS_SPENT');
  };

  /** Serialises the person's resets, so a check for an open one holds until the ask commits. */
  const oneAtATime = async (tx: Transaction<Tables>, orgId: string, personId: string): Promise<void> => {
    const key = `agentx.factor-resets:${orgId.toLowerCase()}:${personId.toLowerCase()}`;
    await sql`select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(${key}, 0))`.execute(tx);
  };

  /** Runs the work in the organisation's transaction, each statement limited to 10 seconds. */
  const inOrganization = <T>(
    orgId: string,
    services: SignedStatesServices,
    work: (tx: Transaction<Tables>, states: SignedStates) => Promise<T>,
  ): Promise<T> =>
    withSignedStates(database, orgId, services, async (tx, states) => {
      await limitStatements(tx);
      return work(tx, states);
    });

  /** Runs the write in the organisation's transaction, its key claimed first; a refusal becomes an answer. */
  const write = async (
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    services: SignedStatesServices,
    work: (tx: Transaction<Tables>, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const idempotency = createIdempotentWrites({ keys, logger: services.logger });
    try {
      return await inOrganization(admin.orgId, services, (tx, states) =>
        idempotency.run(tx, idempotent, () => work(tx, states)),
      );
    } catch (error) {
      if (error instanceof ResetRefused) return { outcome: 'refused' as const, status: error.status, code: error.code };
      if (error instanceof TooManyResets)
        return { outcome: 'refused' as const, status: 409, code: 'TOO_MANY_RESETS' as const };
      if (error instanceof TooManyContacts)
        return { outcome: 'refused' as const, status: 409, code: 'TOO_MANY_CONTACTS' as const };
      throw error;
    }
  };

  /** Answers from the reset as it now stands, re-read by its ID, on a replay too. */
  const answer = async (
    admin: InvitingAdmin,
    services: SignedStatesServices,
    status: number,
    resetId: string,
  ): Promise<ResetChangeWrite> => {
    const read = await inOrganization(admin.orgId, services, (tx, states) =>
      resetRecord(tx, states, admin.orgId, resetId),
    );
    if (read.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    if (read.outcome === 'missing') throw new Error('a reset written, or written before, is not there');
    const { reset } = read;
    return {
      outcome: 'written',
      status,
      reset,
      ...(reset.status === 'DRAFT' && { stepUpChallengeId: reset.stepUpChallengeId }),
    };
  };

  /**
   * Moves each of the person's resets that lapsed, no contact having
   * confirmed it in time, to EXPIRED, each in a transaction of its own, and
   * tells of it. No lock of the person's is needed: each reset is read for
   * the change and judged again, so two at once expire it once, and an ask
   * reading it meanwhile waits for, or is waited on by, that row lock
   * (mutation pass, S58). One that can't be believed, or more than a check
   * reads, is left to the ask, which refuses it.
   */
  const expireLapsed = async (orgId: string, personId: string, services: SignedStatesServices): Promise<void> => {
    let open: Awaited<ReturnType<typeof openResetsFor>>;
    try {
      open = await inOrganization(orgId, services, (tx, states) => openResetsFor(tx, states, orgId, personId));
    } catch (error) {
      // The ask reads them again, and refuses.
      if (error instanceof TooManyResets) return;
      throw error;
    }
    if (open.outcome === 'tampered') return;
    const lapsed = open.resets.filter((reset) => hasLapsed(reset, clock.now()));
    for (const { id } of lapsed) {
      await inOrganization(orgId, services, async (tx, states) => {
        const person = await memberOf(tx, states, { orgId, id: personId }, 'share');
        const read = await resetForChange(tx, states, { orgId, id });
        // Can't be believed (the ask refuses it), or confirmed or moved on by another ask since it was read.
        if (person.outcome !== 'found' || read.outcome !== 'found' || !hasLapsed(read.reset, clock.now())) return;
        await moveReset(tx, states, { orgId, id, event: 'expire', actor: { type: 'system', id: 'api' }, details: {} });
        await outbox.add(
          tx,
          toldOfReset(orgId, 'factor_reset_expired', person.member.userId, sentToContacts(read.reset)),
        );
      });
    }
  };

  return {
    async ask(admin, idempotent, membershipId, correlationId) {
      const services = servicesFor(correlationId);
      await expireLapsed(admin.orgId, membershipId, services);
      const done = await write(admin, idempotent, services, async (tx, states) => {
        await oneAtATime(tx, admin.orgId, membershipId);
        const people = await peopleOf(tx, states, admin, membershipId);
        await withinBudget(tx, admin.orgId, services.logger);
        await mustBeResettable(tx, admin.orgId, people);
        someoneToConfirm(await countingContacts(tx, states, admin.orgId));
        const open = await openResetsFor(tx, states, admin.orgId, people.person.id);
        if (open.outcome === 'tampered') throw new ResetRefused(503, 'INTEGRITY_FAILED');
        if (open.resets.length > 0) throw new ResetRefused(409, 'RESET_OPEN');
        const id = ids.next();
        const { change, changeHash } = resetChange({
          orgId: admin.orgId,
          id,
          person: people.person.id,
          requestedBy: people.adminId,
          expiresAt: resetExpiresAt(clock.now()),
        });
        const challenge = await challenges.open(tx, {
          sessionId: admin.sessionId,
          action: RESET_ASK_OPERATION,
          changeHash,
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new ResetRefused(401, 'UNAUTHENTICATED');
        await draftReset(tx, states, change, {
          stepUpChallengeId: challenge.challengeId,
          createdAt: clock.now(),
          actor: { type: 'user', id: admin.userId },
        });
        return { status: 202, resourceId: id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, services, done.result.status, done.result.resourceId);
    },

    async confirm(admin, idempotent, resetId, correlationId) {
      const services = servicesFor(correlationId);
      const done = await write(admin, idempotent, services, async (tx, states) => {
        const personId = await listedPersonOf(tx, admin.orgId, resetId);
        if (personId === undefined) throw new ResetRefused(404, 'NOT_FOUND');
        const people = await peopleOf(tx, states, admin, personId);
        await mustBeResettable(tx, admin.orgId, people);
        const contactIds = await countingContacts(tx, states, admin.orgId);
        const read = await resetOfPerson(tx, states, admin.orgId, resetId, people.person.id);
        const { reset } = read;
        if (reset.status !== 'DRAFT' || !confirmableAt(reset.expiresAt, clock.now())) {
          throw new ResetRefused(409, 'RESET_CLOSED');
        }
        someoneToConfirm(contactIds);
        const consumed = await challenges.consume(
          tx,
          reset.stepUpChallengeId,
          { sessionId: admin.sessionId, action: RESET_ASK_OPERATION, changeHash: read.changeHash },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new ResetRefused(403, 'STEP_UP_FAILED');
        await askContacts(tx, states, keys, {
          orgId: admin.orgId,
          id: reset.id,
          contactIds,
          createdAt: clock.now(),
          actor: { type: 'user', id: admin.userId },
          details: stepUpDetails(consumed),
        });
        await outbox.add(tx, [
          ...linksTo(admin.orgId, reset.id, contactIds),
          ...toldOfReset(admin.orgId, 'factor_reset_asked', people.person.userId, false),
        ]);
        return { status: 200, resourceId: reset.id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, services, done.result.status, done.result.resourceId);
    },

    async cancel(admin, idempotent, resetId, correlationId) {
      const services = servicesFor(correlationId);
      const done = await write(admin, idempotent, services, async (tx, states) => {
        const personId = await listedPersonOf(tx, admin.orgId, resetId);
        if (personId === undefined) throw new ResetRefused(404, 'NOT_FOUND');
        const { person } = await peopleOf(tx, states, admin, personId);
        const { reset } = await resetOfPerson(tx, states, admin.orgId, resetId, person.id);
        if (!isOpenReset(reset.status)) throw new ResetRefused(409, 'RESET_CLOSED');
        await moveReset(tx, states, {
          orgId: admin.orgId,
          id: reset.id,
          event: 'cancel',
          actor: { type: 'user', id: admin.userId },
          details: {},
        });
        await outbox.add(tx, toldOfReset(admin.orgId, 'factor_reset_cancelled', person.userId, sentToContacts(reset)));
        return { status: 200, resourceId: reset.id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, services, done.result.status, done.result.resourceId);
    },

    async list(orgId, correlationId) {
      try {
        const listed = await inOrganization(orgId, servicesFor(correlationId), (tx, states) =>
          resetsOf(tx, states, orgId),
        );
        if (listed.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
        return { outcome: 'listed', resets: listed.resets };
      } catch (error) {
        if (error instanceof TooManyResets) return { outcome: 'refused', status: 409, code: 'TOO_MANY_RESETS' };
        throw error;
      }
    },
  };
}
