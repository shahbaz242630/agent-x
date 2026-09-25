// Inviting a member (PRD §7.1, ADR-003 §8-§9, ADR-005 §6; B4-3b): the use
// case the API's routes call, composing in the organisation's own transaction the idempotency
// store (ADR-007 §4), the step-up (identity's challenges) and the invitation
// itself (ADR-003 §9 step 7: one unit of work consumes the challenge, then
// makes the change; all three are the identity module's, so no cycle).
//
// Asking (`members.invite`): the key claimed first; the admin's membership
// read again inside the transaction, active and still an admin; the pending
// change settled and its SHA-256 bound into a step-up challenge for the
// admin's own session; the invitation kept as a DRAFT naming the challenge.
// Answered 202: the admin is to sign in again for it.
//
// Confirming (`members.invite.confirm`): the key claimed first; the admin
// read again; the draft read for the change (locked, still a DRAFT, in time)
// and its hash worked out again from the verified row and the decrypted
// address; the challenge it names consumed only for that session, action and
// hash, verified and in time; then the invitation opened, the step-up's
// evidence on its event (ADR-003 §9 step 6). The token comes back once, from
// the write that made it; a replay answers without it.
//
// A refusal inside the write throws, so the key's claim and everything
// written roll back and the same key may be sent again (the idempotency
// store keeps only answers from 200 to 299). Each statement is limited to
// 10 seconds.
import { createIdempotentWrites, type IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import type { Role } from '../domain/membership.ts';
import {
  draftInvitation,
  invitationChange,
  type InvitationRecord,
  invitationRecord,
  invitationToOpen,
  openInvitation,
} from './invitations.ts';
import { membershipOf, type MembershipsTransaction } from './memberships.ts';
import { type StepUpChallenges, stepUpDetails } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

/** The asking route's operation, which its step-up challenge names as its action too. */
export const INVITE_OPERATION = 'members.invite';
/** The confirming route's operation. */
export const CONFIRM_OPERATION = 'members.invite.confirm';

/** Who is writing: the signed-in admin, in the organisation the access hook verified. */
export interface InvitingAdmin {
  readonly orgId: string;
  readonly userId: string;
  /** The session the step-up binds to (ADR-003 §7: the stable session record). */
  readonly sessionId: string;
}

/** What a write answers. */
export type InvitationWrite =
  | {
      readonly outcome: 'written';
      readonly status: number;
      readonly invitation: InvitationRecord;
      /** The token, from the write that opened the invitation; never on a replay. */
      readonly token?: string;
    }
  | { readonly outcome: 'conflict' | 'busy' }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

export interface InvitationWrites {
  ask(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    invited: { readonly email: string; readonly role: Role },
    correlationId: string,
  ): Promise<InvitationWrite>;
  confirm(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    invitationId: string,
    correlationId: string,
  ): Promise<InvitationWrite>;
}

/** A refusal inside a write: thrown, so the claim and all the write did roll back. */
class WriteRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`an invitation's write refused: ${code}`);
    this.name = 'WriteRefused';
    this.status = status;
    this.code = code;
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables;

export function createInvitationWrites({
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
}): InvitationWrites {
  /** The admin's membership, read again for this write's decision: its ID, or a refusal. */
  const adminOf = async (tx: MembershipsTransaction, states: SignedStates, admin: InvitingAdmin): Promise<string> => {
    const membership = await membershipOf(tx, states, admin.orgId, admin.userId);
    if (membership.outcome === 'tampered') throw new WriteRefused(503, 'INTEGRITY_FAILED');
    if (membership.outcome !== 'active' || membership.role !== 'admin') throw new WriteRefused(403, 'FORBIDDEN');
    return membership.id;
  };

  /**
   * Runs the write in the organisation's transaction, its key claimed first,
   * then answers from the invitation, re-read by the ID the answer names.
   */
  const write = async (
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: MembershipsTransaction, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ): Promise<InvitationWrite> => {
    const services = { keys, ids, logger: logger.child({ correlationId }) };
    const idempotency = createIdempotentWrites({ keys, logger: services.logger });
    let done;
    try {
      done = await withSignedStates(database, admin.orgId, services, async (tx, states) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        return idempotency.run(tx, idempotent, () => work(tx, states));
      });
    } catch (error) {
      if (error instanceof WriteRefused) {
        return { outcome: 'refused', status: error.status, code: error.code };
      }
      throw error;
    }
    if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
    const read = await withSignedStates(database, admin.orgId, services, async (tx, states) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return invitationRecord(tx, states, admin.orgId, done.result.resourceId);
    });
    if (read.outcome === 'tampered') {
      return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    }
    if (read.outcome === 'missing') throw new Error('an invitation written, or written before, is not there');
    return { outcome: 'written', status: done.result.status, invitation: read.invitation };
  };

  return {
    async ask(admin, idempotent, { email, role }, correlationId) {
      return write(admin, idempotent, correlationId, async (tx, states) => {
        const invitedBy = await adminOf(tx, states, admin);
        const id = ids.next();
        const createdAt = clock.now();
        const { change, changeHash } = invitationChange({
          orgId: admin.orgId,
          id,
          email,
          role,
          invitedBy,
          createdAt,
        });
        const challenge = await challenges.open(tx, {
          sessionId: admin.sessionId,
          action: INVITE_OPERATION,
          changeHash,
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new WriteRefused(401, 'UNAUTHENTICATED');
        await draftInvitation(tx, states, keys, change, {
          stepUpChallengeId: challenge.challengeId,
          createdAt,
          actor: { type: 'user', id: admin.userId },
        });
        return { status: 202, resourceId: id };
      });
    },

    async confirm(admin, idempotent, invitationId, correlationId) {
      let token: string | undefined;
      const written = await write(admin, idempotent, correlationId, async (tx, states) => {
        await adminOf(tx, states, admin);
        const read = await invitationToOpen(tx, states, keys, {
          orgId: admin.orgId,
          id: invitationId,
          now: clock.now(),
        });
        if (read.outcome === 'missing') throw new WriteRefused(404, 'NOT_FOUND');
        if (read.outcome === 'tampered') throw new WriteRefused(503, 'INTEGRITY_FAILED');
        if (read.outcome !== 'draft') throw new WriteRefused(409, 'INVITATION_CLOSED');
        const consumed = await challenges.consume(tx, read.stepUpChallengeId, {
          sessionId: admin.sessionId,
          action: INVITE_OPERATION,
          changeHash: read.changeHash,
        });
        if (consumed === undefined) throw new WriteRefused(403, 'STEP_UP_FAILED');
        token = await openInvitation(tx, states, {
          orgId: admin.orgId,
          id: read.invitation.id,
          actor: { type: 'user', id: admin.userId },
          details: stepUpDetails(consumed),
        });
        return { status: 200, resourceId: read.invitation.id };
      });
      // Set only by a write that ran now: a replay never runs it, so never has a token.
      if (written.outcome === 'written' && token !== undefined) return { ...written, token };
      return written;
    },
  };
}
