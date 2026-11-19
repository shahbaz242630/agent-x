// Changing a member's role, or deactivating them (PRD §7.1
// `POST /v1/members/{id}/role`, `…/deactivate`; ADR-003 §7-§9, SEC-HA-10;
// B4-5a): an admin's change to another member, with step-up, that ends every
// session the member has in the same transaction.
//
// 1. `ask` (`members.role`, `members.deactivate`): the key claimed first; the
//    admin read again, active and still an admin; the member read, active,
//    and not the admin (OWN_MEMBERSHIP: so the organisation always keeps an
//    admin, the admin changing being one); for a role, a new one
//    (ROLE_UNCHANGED); then the change's SHA-256 (the organisation, the membership, the new
//    role, the version its signed state has reached) bound into a step-up
//    challenge for the admin's own session, the action naming the change.
//    The challenge is the write's resource, so a retry answers with it. The
//    pending change is the request itself: confirming names it again, and
//    only the same change, on the membership as it was, hashes alike.
// 2. `confirm` (`members.role.confirm`, `members.deactivate.confirm`): the
//    key claimed first (level 0); then level 0b (ADR-006 §6): the sessions,
//    then the challenges, of the admin and the member, each in order of ID;
//    then the two memberships in order of ID (2a), the admin's for a
//    decision and the member's for the change; the same checks, the hash
//    worked out again, the challenge consumed only for this session, action
//    and hash; every session of the member ended; then the change, recorded
//    with the step-up's evidence and how many sessions ended (`signInsEnded`:
//    the audit trail refuses a detail named for sessions, as it would a
//    session's secret); last, the end's signed record on the platform chain
//    (R-15), which a sign-in begun before it is refused by.
//
// Deactivating a member also ends what `leaving` names outside this module
// (6E3b, decision 7: the MCP connections they made, the API's composition):
// its brakes taken first, right after the key's claim and before any session
// or challenge (ADR-006 §6, 1b: the agents' brakes, in order of agent ID, the
// one change that may hold more than one); read for change after the
// memberships and before the first event; ended after the membership's own.
// A brake's wait run out answers 503 ORGANISATION_BUSY, nothing changed, with
// the alarm a stop raises (`brake.not_applied`).
//
// So a session of the member's never outlives the role it was opened under,
// and nothing is locked backwards: two admins changing each other at the same
// moment, a step-up's return, or a sign-out wait on each other in order,
// never in a cycle. A session opened after the sessions were ended reads the
// membership as it is once this commits.
//
// A refusal throws inside the write, so the claim and everything written roll
// back. Each statement is limited to 10 seconds.
import {
  createIdempotentWrites,
  type IdempotentRequest,
  isLockWaitRunOut,
  isRetryable,
  isStatementLimit,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, type Transaction } from 'kysely';

import type { Clock, IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import {
  type AuditActor,
  type AuditTables,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '../../audit/index.ts';
import { type DirectoryTables, listedMember, listedMembership } from '../../directory/index.ts';
import type { NotificationsTables, Outbox } from '../../notifications/index.ts';
import { createPlatformChain, type PlatformTransaction } from '../../platform-controls/index.ts';
import type { Role } from '../domain/membership.ts';
import type { InvitingAdmin } from './inviting.ts';
import { grantsToChange, tamperThrown } from './membership-grants.ts';
import {
  changeMembershipRole,
  deactivateMembership,
  type MemberCheck,
  memberOf,
  type MemberRecord,
  type MembershipsTransaction,
} from './memberships.ts';
import { tellAdminsOfGrant, tellAdminsOfRemoval } from './grant-notices.ts';
import { endSessionsOf, lockSessionsOf, sessionsEndedEvent } from './sessions.ts';
import { changeHashOf, lockChallengesOf, type StepUpChallenges, stepUpDetails } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { Refusal } from './refusals.ts';

/** Asking to change a member's role: its operation, which the step-up challenge names as its action too. */
export const ROLE_OPERATION = 'members.role';
/** Changing it, once stepped up. */
export const ROLE_CONFIRM_OPERATION = 'members.role.confirm';
/** Asking to deactivate a member. */
export const DEACTIVATE_OPERATION = 'members.deactivate';
/** Deactivating them, once stepped up. */
export const DEACTIVATE_CONFIRM_OPERATION = 'members.deactivate.confirm';

/** A change to a member: a new role, or deactivation. */
export type MembershipChange = { readonly kind: 'role'; readonly role: Role } | { readonly kind: 'deactivate' };

/** What a change's write answers. */
export type MembershipChangeWrite =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'written'; readonly member: MemberRecord }
  | { readonly outcome: 'conflict' | 'busy' }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

export interface MembershipChanges {
  ask(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    membershipId: string,
    change: MembershipChange,
    correlationId: string,
  ): Promise<MembershipChangeWrite>;
  confirm(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    membershipId: string,
    change: MembershipChange,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<MembershipChangeWrite>;
}

/** The member a deactivation removes. */
interface Leaving {
  readonly orgId: string;
  readonly membershipId: string;
}

/**
 * What else deactivating a member ends, outside this module (6E3b: the MCP connections they made). `brakes`: first in
 * the deactivation's transaction, right after its key's claim, before any session, challenge or row, the brakes its
 * changes need (ADR-006 §6, 1b), answering whether it took any. `read`: for change, after the memberships and before
 * the first event; then `end` after the membership's own event; or something it read was tampered with (its alarm
 * raised), refusing the change.
 */
export interface MemberLeaving<Theirs> {
  readonly brakes: (tx: Transaction<Tables & Theirs>, leaving: Leaving) => Promise<boolean>;
  readonly read: (
    tx: Transaction<Tables & Theirs>,
    states: SignedStates,
    leaving: Leaving,
  ) => Promise<
    { readonly outcome: 'read'; readonly end: (actor: AuditActor) => Promise<void> } | { readonly outcome: 'tampered' }
  >;
}

/**
 * Two modules' leavings as one (AG7: the MCP connections and the payee registrations): the first's brakes, then the
 * second's (each its own order, the first's agents' brakes the only ones today); both read, a tampered read in either
 * refusing the change; then both ended, in the same order.
 */
export const bothLeaving = <First extends object, Second extends object>(
  first: MemberLeaving<First>,
  second: MemberLeaving<Second>,
): MemberLeaving<First & Second> => ({
  async brakes(tx, leaving) {
    const firstHeld = await first.brakes(tx, leaving);
    return (await second.brakes(tx, leaving)) || firstHeld;
  },
  async read(tx, states, leaving) {
    const firstRead = await first.read(tx, states, leaving);
    if (firstRead.outcome === 'tampered') return firstRead;
    const secondRead = await second.read(tx, states, leaving);
    if (secondRead.outcome === 'tampered') return secondRead;
    return {
      outcome: 'read',
      end: async (actor) => {
        await firstRead.end(actor);
        await secondRead.end(actor);
      },
    };
  },
});

class ChangeRefused extends Refusal {
  constructor(status: number, code: ReasonCode) {
    super(`a membership's change refused: ${code}`, status, code);
    this.name = 'ChangeRefused';
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables;

/** The step-up's action for a change: its ask's operation. */
const actionOf = (change: MembershipChange): string => (change.kind === 'role' ? ROLE_OPERATION : DEACTIVATE_OPERATION);

/**
 * The pending change's SHA-256: the membership, by its organisation and ID
 * (the table's key: an ID alone is unique only as the ID generator makes
 * it), the new role or none, and the version its signed state has reached, so
 * any change to it since the ask hashes otherwise. Whose it is follows from
 * the membership; which change it is, the challenge's action binds.
 */
const membershipChangeHash = (orgId: string, member: MemberRecord, change: MembershipChange, version: number) =>
  changeHashOf([orgId.toLowerCase(), member.id, change.kind === 'role' ? change.role : '', String(version)]);

/** Throws the refusal a read that found no member, or one tampered with, gives. */
function found(read: MemberCheck): Extract<MemberCheck, { outcome: 'found' }> {
  if (read.outcome === 'tampered') throw new ChangeRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome === 'missing') throw new ChangeRefused(404, 'NOT_FOUND');
  return read;
}

export function createMembershipChanges<Theirs extends object = object>({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
  leaving,
}: {
  /** Holding `leaving`'s tables too, when it is given. */
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** When a change ends the member's sessions, as their sign-ins made before it are then refused (0098, AG10). */
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  /** Where the admins' notices of a role granted are written (B5-1b). */
  readonly outbox: Outbox;
  readonly logger: Logger;
  /** What else a deactivation ends (MemberLeaving); nothing when not given. */
  readonly leaving?: MemberLeaving<Theirs>;
}): MembershipChanges {
  const platform = createPlatformChain({ keys, ids });
  /**
   * The admin's membership and the member's, each read once, in order of
   * membership ID (ADR-006 §6 level 2a): the admin's for a decision, the
   * member's as `memberLock` asks. The admin must be an active admin, and
   * the member someone else, active, listed as the person the directory
   * names, and, for a role, not holding it already.
   */
  const bothRead = async (
    tx: MembershipsTransaction,
    states: SignedStates,
    admin: InvitingAdmin,
    membershipId: string,
    memberUserId: string,
    change: MembershipChange,
    memberLock: 'share' | 'change',
  ) => {
    const adminId = await listedMembership(tx, admin.orgId, admin.userId);
    if (adminId === undefined) throw new ChangeRefused(403, 'FORBIDDEN');
    const readAdmin = () => memberOf(tx, states, { orgId: admin.orgId, id: adminId }, 'share');
    const readMember = () => memberOf(tx, states, { orgId: admin.orgId, id: membershipId }, memberLock);
    const adminFirst = adminId < membershipId.toLowerCase();
    const first = await (adminFirst ? readAdmin() : readMember());
    const second = await (adminFirst ? readMember() : readAdmin());
    const [adminRead, memberRead] = adminFirst ? [first, second] : [second, first];

    if (adminRead.outcome === 'tampered') throw new ChangeRefused(503, 'INTEGRITY_FAILED');
    if (
      adminRead.outcome !== 'found' ||
      adminRead.member.userId !== admin.userId.toLowerCase() ||
      adminRead.member.status !== 'ACTIVE' ||
      adminRead.member.role !== 'admin'
    ) {
      throw new ChangeRefused(403, 'FORBIDDEN');
    }
    const { member, state } = found(memberRead);
    if (member.id === adminId) throw new ChangeRefused(409, 'OWN_MEMBERSHIP');
    // The directory's entry named someone else's membership: not this one's.
    if (member.userId !== memberUserId.toLowerCase()) throw new ChangeRefused(404, 'NOT_FOUND');
    if (member.status !== 'ACTIVE') throw new ChangeRefused(409, 'MEMBER_DEACTIVATED');
    if (change.kind === 'role' && member.role === change.role) throw new ChangeRefused(409, 'ROLE_UNCHANGED');
    return { member, state };
  };

  /** The person the directory lists with the membership. */
  const memberUserOf = async (tx: MembershipsTransaction, admin: InvitingAdmin, membershipId: string) => {
    const userId = await listedMember(tx, admin.orgId, membershipId);
    if (userId === undefined) throw new ChangeRefused(404, 'NOT_FOUND');
    return userId;
  };

  /** Runs a write in the organisation's transaction, its key claimed first; a refusal becomes an answer. */
  const write = async (
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: Transaction<Tables>, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const services = { keys, ids, logger: logger.child({ correlationId }), correlationId };
    const idempotency = createIdempotentWrites({ keys, logger: services.logger });
    try {
      const done = await withSignedStates(database, admin.orgId, services, (tx, states) =>
        idempotency.run(tx, idempotent, () => work(tx, states)),
      );
      return { done, services };
    } catch (error) {
      if (error instanceof ChangeRefused) {
        return { refused: { outcome: 'refused', status: error.status, code: error.code } as const, services };
      }
      if (tamperThrown(error)) {
        return { refused: { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' } as const, services };
      }
      throw error;
    }
  };

  /** Answers from the membership, re-read by its ID in a transaction of its own. */
  const answer = async (
    admin: InvitingAdmin,
    services: SignedStatesServices,
    id: string,
  ): Promise<MembershipChangeWrite> => {
    const read = await withSignedStates(database, admin.orgId, services, (tx, states) =>
      memberOf(tx, states, { orgId: admin.orgId, id }, 'share'),
    );
    if (read.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    if (read.outcome === 'missing') throw new Error('a membership changed, or changed before, is not there');
    return { outcome: 'written', member: read.member };
  };

  return {
    async ask(admin, idempotent, membershipId, change, correlationId) {
      const ran = await write(admin, idempotent, correlationId, async (tx, states) => {
        const memberUserId = await memberUserOf(tx, admin, membershipId);
        const { member, state } = await bothRead(tx, states, admin, membershipId, memberUserId, change, 'share');
        const challenge = await challenges.open(tx, {
          sessionId: admin.sessionId,
          action: actionOf(change),
          changeHash: membershipChangeHash(admin.orgId, member, change, state.version),
        });
        if (challenge === undefined) throw new ChangeRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if ('refused' in ran) return ran.refused;
      const { done } = ran;
      if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(admin, idempotent, membershipId, change, stepUpChallengeId, correlationId) {
      const leavingNow = change.kind === 'deactivate' ? leaving : undefined;
      const started = performance.now();
      // Set inside the write, read once it has thrown.
      const brakes = { held: false };
      const confirmed = () =>
        write(admin, idempotent, correlationId, async (tx, states) => {
          // Opened on `database`, which holds their tables too.
          const wider = tx as unknown as Transaction<Tables & Theirs>;
          const removed = { orgId: admin.orgId, membershipId };
          // Level 1b's brakes first, after the key's claim alone, before any session or challenge (ADR-006 §6). Held
          // from the first one's wait: its lookup before takes no lock, so only a brake's wait can run out in it.
          brakes.held = leavingNow !== undefined;
          brakes.held = (await leavingNow?.brakes(wider, removed)) ?? false;
          return deactivatedOrChanged(tx, wider, states, removed);
        });
      const deactivatedOrChanged = async (
        tx: Transaction<Tables>,
        wider: Transaction<Tables & Theirs>,
        states: SignedStates,
        removed: Leaving,
      ) => {
        const memberUserId = await memberUserOf(tx, admin, membershipId);
        // Level 0b, before any membership: the admin's and the member's sessions, then their challenges.
        const people = [admin.userId.toLowerCase(), memberUserId];
        await lockSessionsOf(tx, people);
        await lockChallengesOf(tx, people);
        // The admin's own are among those just locked: held again, in the same order, for consume.
        const held = await challenges.hold(tx, admin.sessionId);
        const { member, state } = await bothRead(tx, states, admin, membershipId, memberUserId, change, 'change');
        // The member's grant summary for the change, after the memberships (ADR-006 §6, 2a; OR1).
        const grants = await grantsToChange(tx, states, { orgId: admin.orgId, id: member.id });
        if (grants.outcome === 'tampered') throw new ChangeRefused(503, 'INTEGRITY_FAILED');
        const ending = await leavingNow?.read(wider, states, { ...removed, membershipId: member.id });
        if (ending?.outcome === 'tampered') throw new ChangeRefused(503, 'INTEGRITY_FAILED');
        const consumed = await challenges.consume(
          tx,
          held,
          stepUpChallengeId,
          {
            sessionId: admin.sessionId,
            action: actionOf(change),
            changeHash: membershipChangeHash(admin.orgId, member, change, state.version),
          },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new ChangeRefused(403, 'STEP_UP_FAILED');
        const endedAt = clock.now();
        const signInsEnded = await endSessionsOf(tx, member.userId, endedAt);
        const actor = { type: 'user' as const, id: admin.userId };
        const key = { orgId: admin.orgId, id: member.id };
        const evidence = { signInsEnded, ...stepUpDetails(consumed) };
        const read = { key, member, grants, actor, evidence };
        if (change.kind === 'role') {
          await changeMembershipRole(tx, states, { ...read, state, roleTo: change.role });
          await tellAdminsOfGrant(tx, outbox, {
            orgId: admin.orgId,
            membershipId: member.id,
            role: change.role,
            rejoined: false,
          });
          // An admin or approver given a lesser role: told too (the S68 audit), with the role taken away.
          await tellAdminsOfRemoval(tx, outbox, {
            orgId: admin.orgId,
            membershipId: member.id,
            kind: 'demoted',
            role: member.role,
          });
        } else {
          await deactivateMembership(tx, states, read);
          await ending?.end(actor);
          // Told to the admins (the S68 audit): who is removed, with the role they held.
          await tellAdminsOfRemoval(tx, outbox, {
            orgId: admin.orgId,
            membershipId: member.id,
            kind: 'deactivated',
            role: member.role,
          });
        }
        // The end's signed record, on the platform chain, its head the last lock of all (ADR-006 §6; R-15).
        // The platform chain's tables are in the same database, and belong to no organisation.
        await platform.record(tx as unknown as PlatformTransaction, sessionsEndedEvent(member.userId, endedAt));
        return { status: 200, resourceId: member.id };
      };
      let ran: Awaited<ReturnType<typeof confirmed>>;
      try {
        ran = await confirmed();
      } catch (error) {
        // A brake's wait run out, or the statements behind it past their limit: nothing changed, the key free again.
        if (!brakes.held || !(isLockWaitRunOut(error) || isStatementLimit(error) || isRetryable(error))) throw error;
        logger
          .child({ correlationId, orgId: admin.orgId })
          .error('brake.not_applied', { waitedMs: Math.round(performance.now() - started) });
        return { outcome: 'refused', status: 503, code: 'ORGANISATION_BUSY' };
      }
      if ('refused' in ran) return ran.refused;
      const { done, services } = ran;
      if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, services, done.result.resourceId);
    },
  };
}
