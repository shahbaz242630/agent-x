// Changing a member's role, or deactivating them (PRD §7.1
// `POST /v1/members/{id}/role`, `…/deactivate`; ADR-003 §7-§9, SEC-HA-10;
// B4-5a): an admin's change to another member, with step-up, that ends every
// session the member has in the same transaction.
//
// 1. `ask` (`members.role`, `members.deactivate`): the key claimed first; the
//    admin read again, active and still an admin; the member read, active,
//    and not the admin (OWN_MEMBERSHIP: so the organisation always keeps an
//    admin, the admin changing being one); for a role, a new one
//    (ROLE_UNCHANGED); then the change's SHA-256 (the membership, the new
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
//    session's secret).
//
// So a session of the member's never outlives the role it was opened under,
// and nothing is locked backwards: two admins changing each other at the same
// moment, a step-up's return, or a sign-out wait on each other in order,
// never in a cycle. A session opened after the sessions were ended reads the
// membership as it is once this commits.
//
// A refusal throws inside the write, so the claim and everything written roll
// back. Each statement is limited to 10 seconds.
import { createIdempotentWrites, type IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql } from 'kysely';

import type { IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, type SignedStatesServices, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedMember, listedMembership } from '../../directory/index.ts';
import type { Role } from '../domain/membership.ts';
import type { InvitingAdmin } from './inviting.ts';
import {
  type MemberCheck,
  memberOf,
  type MemberRecord,
  MEMBERSHIPS,
  type MembershipsTransaction,
} from './memberships.ts';
import { endSessionsOf, lockSessionsOf } from './sessions.ts';
import { changeHashOf, lockChallengesOf, type StepUpChallenges, stepUpDetails } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

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

class ChangeRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`a membership's change refused: ${code}`);
    this.name = 'ChangeRefused';
    this.status = status;
    this.code = code;
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables;

/** The step-up's action for a change: its ask's operation. */
const actionOf = (change: MembershipChange): string => (change.kind === 'role' ? ROLE_OPERATION : DEACTIVATE_OPERATION);

/**
 * The pending change's SHA-256: the membership (its ID, unique across every
 * organisation, and one per person in one), the new role or none, and the
 * version its signed state has reached, so any change to it since the ask
 * hashes otherwise. Which change it is, the challenge's action binds.
 */
const membershipChangeHash = (member: MemberRecord, change: MembershipChange, version: number) =>
  changeHashOf([member.id, change.kind === 'role' ? change.role : '', String(version)]);

/** Throws the refusal a read that found no member, or one tampered with, gives. */
function found(read: MemberCheck): Extract<MemberCheck, { outcome: 'found' }> {
  if (read.outcome === 'tampered') throw new ChangeRefused(503, 'INTEGRITY_FAILED');
  if (read.outcome === 'missing') throw new ChangeRefused(404, 'NOT_FOUND');
  return read;
}

export function createMembershipChanges({
  database,
  keys,
  ids,
  challenges,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): MembershipChanges {
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
    work: (tx: MembershipsTransaction, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const services = { keys, ids, logger: logger.child({ correlationId }) };
    const idempotency = createIdempotentWrites({ keys, logger: services.logger });
    try {
      const done = await withSignedStates(database, admin.orgId, services, async (tx, states) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        return idempotency.run(tx, idempotent, () => work(tx, states));
      });
      return { done, services };
    } catch (error) {
      if (error instanceof ChangeRefused) {
        return { refused: { outcome: 'refused', status: error.status, code: error.code } as const, services };
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
    const read = await withSignedStates(database, admin.orgId, services, async (tx, states) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return memberOf(tx, states, { orgId: admin.orgId, id }, 'share');
    });
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
          changeHash: membershipChangeHash(member, change, state.version),
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
      const ran = await write(admin, idempotent, correlationId, async (tx, states) => {
        const memberUserId = await memberUserOf(tx, admin, membershipId);
        // Level 0b, before any membership: the admin's and the member's sessions, then their challenges.
        const people = [admin.userId.toLowerCase(), memberUserId];
        await lockSessionsOf(tx, people);
        await lockChallengesOf(tx, people);
        const { member, state } = await bothRead(tx, states, admin, membershipId, memberUserId, change, 'change');
        const consumed = await challenges.consume(tx, stepUpChallengeId, {
          sessionId: admin.sessionId,
          action: actionOf(change),
          changeHash: membershipChangeHash(member, change, state.version),
        });
        if (consumed === undefined) throw new ChangeRefused(403, 'STEP_UP_FAILED');
        const signInsEnded = await endSessionsOf(tx, member.userId);
        const actor = { type: 'user' as const, id: admin.userId };
        const key = { orgId: admin.orgId, id: member.id };
        if (change.kind === 'role') {
          await states.record(
            tx,
            MEMBERSHIPS,
            key,
            state,
            { role: change.role },
            {
              actor,
              action: 'membership.role_changed',
              details: { roleFrom: member.role, roleTo: change.role, signInsEnded, ...stepUpDetails(consumed) },
            },
          );
        } else {
          const moved = await states.changeStatus(tx, MEMBERSHIPS, key, 'deactivate', {
            actor,
            action: 'membership.deactivated',
            details: { role: member.role, signInsEnded, ...stepUpDetails(consumed) },
          });
          if (moved.outcome !== 'changed')
            throw new Error(`a membership read as active did not move: ${moved.outcome}`);
        }
        return { status: 200, resourceId: member.id };
      });
      if ('refused' in ran) return ran.refused;
      const { done, services } = ran;
      if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, services, done.result.resourceId);
    },
  };
}
