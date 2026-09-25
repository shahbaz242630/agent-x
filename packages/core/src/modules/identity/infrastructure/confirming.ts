// Confirming who accepted an admin's or finance approver's invitation
// (ADR-005 §6, ADR-003 §8, SEC-HA-08; B4-4d): a privileged role becomes
// active only once an existing admin confirms who accepted, with step-up.
//
// 1. `ask` (`members.approve`): the key claimed first; the admin read again,
//    active and still an admin; the invitation read, AWAITING_CONFIRMATION;
//    the pending change's SHA-256 (the organisation, the invitation, who
//    accepted it, the role, the version its signed state has reached) bound
//    into a step-up challenge for the admin's own session. The challenge is
//    the write's resource, so a retry answers with the same challenge.
// 2. `confirm` (`members.approve.confirm`): the key claimed first; the admin
//    read again; the invitation read for the change, still waiting, its hash
//    worked out again; the challenge consumed only for this session, action
//    and hash, verified and in time; who accepted must not be in the
//    organisation yet; then the invitation moves to ACCEPTED with the
//    step-up's evidence on its event, and the membership is added with the
//    invitation's role, in the same transaction.
// 3. `decline` (`members.decline`): the key claimed first; the admin read
//    again; the invitation, waiting, moves to DECLINED. No step-up: declining
//    grants nothing (ADR-003 §8's list is of changes that grant or restore).
//
// A refusal throws inside the write, so the claim and everything written roll
// back. Each statement is limited to 10 seconds.
import { createIdempotentWrites, type IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import {
  type InvitationRecord,
  invitationRecord,
  INVITATIONS,
  type InvitationsTransaction,
  invitationToConfirm,
} from './invitations.ts';
import type { InvitingAdmin } from './inviting.ts';
import { addMembership, isMembershipTaken, membershipOf } from './memberships.ts';
import { changeHashOf, type StepUpChallenges, stepUpDetails } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

/** Asking to confirm: its operation, which the step-up challenge names as its action too. */
export const APPROVE_OPERATION = 'members.approve';
/** Confirming, once stepped up. */
export const APPROVE_CONFIRM_OPERATION = 'members.approve.confirm';
/** Declining. */
export const DECLINE_OPERATION = 'members.decline';

/** What a confirmation's write answers. */
export type ConfirmationWrite =
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'written'; readonly invitation: InvitationRecord }
  | { readonly outcome: 'conflict' | 'busy' }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

export interface AcceptanceConfirmations {
  ask(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    invitationId: string,
    correlationId: string,
  ): Promise<ConfirmationWrite>;
  confirm(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    invitationId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<ConfirmationWrite>;
  decline(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    invitationId: string,
    correlationId: string,
  ): Promise<ConfirmationWrite>;
}

class ConfirmationRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`an acceptance's confirmation refused: ${code}`);
    this.name = 'ConfirmationRefused';
    this.status = status;
    this.code = code;
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables;

/** The pending change's SHA-256: each fact in a fixed order, IDs in lower case. */
export const confirmationHash = (orgId: string, invitation: InvitationRecord, version: number): Buffer =>
  changeHashOf([orgId.toLowerCase(), invitation.id, invitation.acceptedBy ?? '', invitation.role, String(version)]);

export function createAcceptanceConfirmations({
  database,
  keys,
  ids,
  clock,
  challenges,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  readonly logger: Logger;
}): AcceptanceConfirmations {
  const adminOf = async (tx: InvitationsTransaction, states: SignedStates, admin: InvitingAdmin): Promise<void> => {
    const membership = await membershipOf(tx, states, admin.orgId, admin.userId);
    if (membership.outcome === 'tampered') throw new ConfirmationRefused(503, 'INTEGRITY_FAILED');
    if (membership.outcome !== 'active' || membership.role !== 'admin') throw new ConfirmationRefused(403, 'FORBIDDEN');
  };

  /** The invitation, read for the change, still waiting for confirmation, with its signed state's version. */
  const waiting = async (
    tx: InvitationsTransaction,
    states: SignedStates,
    orgId: string,
    id: string,
  ): Promise<{ invitation: InvitationRecord; version: number }> => {
    const read = await invitationToConfirm(tx, states, { orgId, id });
    if (read.outcome === 'missing') throw new ConfirmationRefused(404, 'NOT_FOUND');
    if (read.outcome === 'tampered') throw new ConfirmationRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'not_waiting') throw new ConfirmationRefused(409, 'INVITATION_CLOSED');
    return { invitation: read.invitation, version: read.version };
  };

  /** Runs a write in the organisation's transaction, its key claimed first; a refusal becomes an answer. */
  const write = async (
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: InvitationsTransaction, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
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
      if (error instanceof ConfirmationRefused) {
        return { refused: { outcome: 'refused', status: error.status, code: error.code } as const, services };
      }
      throw error;
    }
  };

  /** Answers from the invitation, re-read by its ID in a transaction of its own. */
  const answer = async (
    admin: InvitingAdmin,
    services: Parameters<typeof withSignedStates>[2],
    id: string,
  ): Promise<ConfirmationWrite> => {
    const read = await withSignedStates(database, admin.orgId, services, async (tx, states) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return invitationRecord(tx, states, admin.orgId, id);
    });
    if (read.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    if (read.outcome === 'missing') throw new Error('an invitation written, or written before, is not there');
    return { outcome: 'written', invitation: read.invitation };
  };

  return {
    async ask(admin, idempotent, invitationId, correlationId) {
      const ran = await write(admin, idempotent, correlationId, async (tx, states) => {
        await adminOf(tx, states, admin);
        const { invitation, version } = await waiting(tx, states, admin.orgId, invitationId);
        const challenge = await challenges.open(tx, {
          sessionId: admin.sessionId,
          action: APPROVE_OPERATION,
          changeHash: confirmationHash(admin.orgId, invitation, version),
        });
        if (challenge === undefined) throw new ConfirmationRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if ('refused' in ran) return ran.refused;
      const { done } = ran;
      if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async confirm(admin, idempotent, invitationId, stepUpChallengeId, correlationId) {
      const ran = await write(admin, idempotent, correlationId, async (tx, states) => {
        await adminOf(tx, states, admin);
        const { invitation, version } = await waiting(tx, states, admin.orgId, invitationId);
        const consumed = await challenges.consume(tx, stepUpChallengeId, {
          sessionId: admin.sessionId,
          action: APPROVE_OPERATION,
          changeHash: confirmationHash(admin.orgId, invitation, version),
        });
        if (consumed === undefined) throw new ConfirmationRefused(403, 'STEP_UP_FAILED');
        const { acceptedBy, role } = invitation;
        if (acceptedBy === null) throw new Error('an invitation waiting for confirmation names no one who accepted it');
        const already = await membershipOf(tx, states, admin.orgId, acceptedBy);
        if (already.outcome === 'tampered') throw new ConfirmationRefused(503, 'INTEGRITY_FAILED');
        if (already.outcome !== 'none') throw new ConfirmationRefused(409, 'ALREADY_A_MEMBER');
        const actor = { type: 'user' as const, id: admin.userId };
        try {
          const moved = await states.changeStatus(
            tx,
            INVITATIONS,
            { orgId: admin.orgId, id: invitationId },
            'confirm',
            {
              actor,
              action: 'invitation.confirmed',
              details: { role, ...stepUpDetails(consumed) },
            },
          );
          if (moved.outcome !== 'changed')
            throw new Error(`an invitation read as waiting did not move: ${moved.outcome}`);
          await addMembership(tx, states, {
            orgId: admin.orgId,
            id: ids.next(),
            userId: acceptedBy,
            role,
            joinedAt: clock.now(),
            actor,
          });
        } catch (error) {
          // Another of the person's invitations there, confirmed at the same moment, added them first.
          if (isMembershipTaken(error)) throw new ConfirmationRefused(409, 'ALREADY_A_MEMBER');
          throw error;
        }
        return { status: 200, resourceId: invitation.id };
      });
      if ('refused' in ran) return ran.refused;
      const { done, services } = ran;
      if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, services, done.result.resourceId);
    },

    async decline(admin, idempotent, invitationId, correlationId) {
      const ran = await write(admin, idempotent, correlationId, async (tx, states) => {
        await adminOf(tx, states, admin);
        const { invitation } = await waiting(tx, states, admin.orgId, invitationId);
        const moved = await states.changeStatus(tx, INVITATIONS, { orgId: admin.orgId, id: invitationId }, 'decline', {
          actor: { type: 'user', id: admin.userId },
          action: 'invitation.declined',
          details: { role: invitation.role },
        });
        if (moved.outcome !== 'changed')
          throw new Error(`an invitation read as waiting did not move: ${moved.outcome}`);
        return { status: 200, resourceId: invitation.id };
      });
      if ('refused' in ran) return ran.refused;
      const { done, services } = ran;
      if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, services, done.result.resourceId);
    },
  };
}
