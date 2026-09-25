// Accepting an invitation (ADR-005 §6, SEC-HA-08, PRD §7.1; B4-4c): the use
// case the API's route calls, for a signed-in person with the token from the
// link.
//
// 1. The token's SHA-256 is looked up in the directory, which names the
//    organisation and the invitation: the organisation comes from there,
//    never from the request (ADR-005 §5). An unknown token is refused as
//    INVITATION_INVALID, the same answer as an address that doesn't match, so
//    the answer tells nothing of which.
// 2. In the organisation's own transaction, the idempotency key is claimed
//    first (the person as client, the organisation the directory named), then
//    the invitation is read for the change: still OPEN and in time
//    (otherwise 409 INVITATION_CLOSED), with the invited address decrypted.
// 3. The person's session must hold a verified address (B4-4a) equal to the
//    invited one; a session with none, or another, is INVITATION_INVALID.
// 4. The person must not be an active member already (409 ALREADY_A_MEMBER).
//    Two of their invitations there accepted at the same moment: the second
//    finds the directory's key taken, and is refused the same way.
// 5. The invitation is accepted: a developer or viewer joins now, the
//    membership added in the same transaction, or, for a person deactivated
//    there, their membership brought back with the invitation's role and
//    today's start (B4-5c); an admin or finance approver waits for an
//    existing admin to confirm who accepted (B4-4d), who brings them back
//    the same way.
//
// A refusal throws inside the write, so the claim and everything written roll
// back; a retry with the same key answers as the first did. Each statement is
// limited to 10 seconds.
import { createIdempotentWrites, type IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedInvite } from '../../directory/index.ts';
import {
  acceptInvitation,
  type InvitationRecord,
  invitationRecord,
  invitationToAccept,
  inviteTokenHash,
} from './invitations.ts';
import { addMembership, isMembershipTaken, membershipOf, reactivateMembership } from './memberships.ts';
import { sessionEmailOf } from './session-emails.ts';
import type { IdentityTables } from './tables.ts';

/** The route's operation. */
export const ACCEPT_OPERATION = 'invitations.accept';

/** Who is accepting: a signed-in person, by their session. */
export interface AcceptingPerson {
  readonly userId: string;
  readonly sessionId: string;
}

/** What accepting answers. */
export type Acceptance =
  | { readonly outcome: 'accepted'; readonly orgId: string; readonly invitation: InvitationRecord }
  | { readonly outcome: 'conflict' | 'busy' }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

export interface InvitationAcceptance {
  /**
   * Accepts the invitation the token opens. `idempotent` gives the key's
   * request once the organisation is known, from the directory.
   */
  accept(
    person: AcceptingPerson,
    token: string,
    idempotent: (orgId: string) => IdempotentRequest,
    correlationId: string,
  ): Promise<Acceptance>;
}

/** A refusal inside the write: thrown, so the claim and all the write did roll back. */
class AcceptanceRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`an invitation's acceptance refused: ${code}`);
    this.name = 'AcceptanceRefused';
    this.status = status;
    this.code = code;
  }
}

const refused = (status: number, code: ReasonCode): Acceptance => ({ outcome: 'refused', status, code });

type Tables = IdentityTables & DirectoryTables & AuditTables;

export function createInvitationAcceptance({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): InvitationAcceptance {
  return {
    async accept(person, token, idempotent, correlationId) {
      const listed = await listedInvite(database, inviteTokenHash(token));
      if (listed === undefined) return refused(403, 'INVITATION_INVALID');
      const { orgId, invitationId } = listed;
      const address = await sessionEmailOf(database, keys, person.sessionId);
      const services = { keys, ids, logger: logger.child({ correlationId }) };
      const idempotency = createIdempotentWrites({ keys, logger: services.logger });
      let done;
      try {
        done = await withSignedStates(database, orgId, services, async (tx, states) => {
          await sql`set local statement_timeout = '10s'`.execute(tx);
          return idempotency.run(tx, idempotent(orgId), async () => {
            const now = clock.now();
            const read = await invitationToAccept(tx, states, keys, { orgId, id: invitationId, now });
            // Listed but not there: the directory is where to look, never proof.
            if (read.outcome === 'missing') throw new AcceptanceRefused(403, 'INVITATION_INVALID');
            if (read.outcome === 'tampered') throw new AcceptanceRefused(503, 'INTEGRITY_FAILED');
            if (read.outcome === 'closed') throw new AcceptanceRefused(409, 'INVITATION_CLOSED');
            if (address === undefined || address !== read.email) throw new AcceptanceRefused(403, 'INVITATION_INVALID');
            const membership = await membershipOf(tx, states, orgId, person.userId, 'change');
            if (membership.outcome === 'tampered') throw new AcceptanceRefused(503, 'INTEGRITY_FAILED');
            if (membership.outcome === 'active') throw new AcceptanceRefused(409, 'ALREADY_A_MEMBER');
            const actor = { type: 'user' as const, id: person.userId };
            try {
              const accepted = await acceptInvitation(tx, states, {
                orgId,
                id: invitationId,
                userId: person.userId,
                actor,
              });
              if (accepted.outcome === 'accepted' && membership.outcome === 'deactivated') {
                await reactivateMembership(tx, states, {
                  orgId,
                  id: membership.id,
                  role: accepted.role,
                  joinedAt: now,
                  actor,
                });
              } else if (accepted.outcome === 'accepted') {
                await addMembership(tx, states, {
                  orgId,
                  id: ids.next(),
                  userId: person.userId,
                  role: accepted.role,
                  joinedAt: now,
                  actor,
                });
              }
            } catch (error) {
              // Another of the person's invitations there, accepted at the same moment, joined them first.
              if (isMembershipTaken(error)) throw new AcceptanceRefused(409, 'ALREADY_A_MEMBER');
              throw error;
            }
            return { status: 200, resourceId: invitationId };
          });
        });
      } catch (error) {
        if (error instanceof AcceptanceRefused) return refused(error.status, error.code);
        throw error;
      }
      if (done.outcome === 'conflict' || done.outcome === 'busy') return done;
      const answered = await withSignedStates(database, orgId, services, async (tx, states) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        return invitationRecord(tx, states, orgId, done.result.resourceId);
      });
      if (answered.outcome === 'tampered') return refused(503, 'INTEGRITY_FAILED');
      if (answered.outcome === 'missing') throw new Error('an invitation accepted, or accepted before, is not there');
      return { outcome: 'accepted', orgId, invitation: answered.invitation };
    },
  };
}
