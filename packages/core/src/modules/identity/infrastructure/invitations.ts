// Invitations (0016): an admin asks for a person to join the organisation with
// a role. An authority table (ADR-012 §2), since accepting one grants that
// role: its role, its status, the admin who asked (by their membership), when
// it ends and the step-up challenge opened for it must equal its latest signed
// event, and every read a decision rests on goes through the audit module's
// verifiedState with the description below, on the product's authority-table
// list (packages/core/src/authority-tables.ts).
//
// How an invitation is made, in the API's transactions (B4-3b composes them
// with the step-up, ADR-003 §9 step 7):
// 1. `invitationChange` settles the pending change and its SHA-256, which the
//    step-up challenge binds to.
// 2. `draftInvitation` keeps it as a DRAFT, with the challenge's ID; the
//    invited address is encrypted with the organisation and the invitation
//    as its associated data (ADR-011 §2).
// 3. On confirming, `invitationToOpen` reads the draft for the change, still
//    a DRAFT and in time, and gives its change and hash again, from the
//    verified row and the address it decrypts: the challenge is consumed
//    only for that hash, so what opens is exactly what was stepped up for.
// 4. `openInvitation` makes the token, lists its SHA-256 in the directory,
//    and moves the invitation to OPEN, with the step-up's evidence on the
//    event. The token is given back once, to be shown once, and kept nowhere.
//
// The insert is the one query on this table outside the audit module's steps
// but for reading the encrypted address, as for a membership's row
// (organizations.ts says why a plain insert is safe, and must stay plain).
import { createHash, randomBytes } from 'node:crypto';

import type { SignedStateTable } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Transaction } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
} from '../../audit/index.ts';
import { type DirectoryTables, registerInvite } from '../../directory/index.ts';
import { INVITATION, invitationEmail, invitationEnds } from '../domain/invitation.ts';
import { isRole, type Role } from '../domain/membership.ts';
import type { IdentityTables } from './tables.ts';

/** An invitation's row, as the signed state reads, records and moves it. */
export const INVITATIONS = {
  table: 'identity.invitations',
  subject: 'invitation',
  fields: [
    { column: 'role', type: 'text' },
    { column: 'status', type: 'text' },
    { column: 'invited_by', type: 'uuid' },
    { column: 'expires_at', type: 'timestamptz' },
    { column: 'step_up_challenge_id', type: 'uuid' },
  ],
  rules: INVITATION,
} as const satisfies SignedStateTable & { readonly rules: typeof INVITATION };

/** A transaction on the tables an invitation is made and read in, opened by withSignedStates for its organisation. */
export type InvitationsTransaction = Transaction<IdentityTables & DirectoryTables & AuditTables>;

/** An invitation as it is asked for: the pending change a step-up binds to. */
export interface InvitationChange {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** The invited address, in lower case. */
  readonly email: string;
  readonly role: Role;
  /** The membership of the admin who asked. */
  readonly invitedBy: string;
  readonly expiresAt: Date;
}

/** What an invitation is asked with. */
export interface InvitationRequest {
  readonly orgId: string;
  readonly id: string;
  readonly email: string;
  readonly role: Role;
  readonly invitedBy: string;
  /** When it was asked for: it ends INVITATION_HOURS later. */
  readonly createdAt: Date;
}

/** The label the change's hash starts with, so it is never another change's. */
const CHANGE_LABEL = 'agentx.invitation.v1';

/** Each part's length, then its bytes, so no two lists of parts hash alike. */
function hashOf(parts: readonly string[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest();
}

/** The change's SHA-256: every fact it is made of, in a fixed order, IDs in lower case. */
const changeHashOf = (change: InvitationChange): Buffer =>
  hashOf([
    CHANGE_LABEL,
    change.orgId.toLowerCase(),
    change.id.toLowerCase(),
    change.email,
    change.role,
    change.invitedBy.toLowerCase(),
    change.expiresAt.toISOString(),
  ]);

/**
 * The invitation as a pending change, and its SHA-256 for the step-up
 * challenge. Throws a RangeError for an address or role that isn't one: the
 * API's own checks come first, so this is a failure on our side.
 */
export function invitationChange(request: InvitationRequest): { change: InvitationChange; changeHash: Buffer } {
  const email = invitationEmail(request.email);
  if (email === undefined) throw new RangeError('An invitation refused: the address is not one');
  if (!isRole(request.role)) throw new RangeError('An invitation refused: the role is not one');
  const change: InvitationChange = {
    orgId: request.orgId,
    id: request.id,
    email,
    role: request.role,
    invitedBy: request.invitedBy,
    expiresAt: invitationEnds(request.createdAt),
  };
  return { change, changeHash: changeHashOf(change) };
}

/** The address's associated data: the row it belongs to, so it opens nowhere else. */
const emailAssociatedData = (orgId: string, id: string) =>
  ['identity.invitations.email', orgId.toLowerCase(), id.toLowerCase()] as const;

/**
 * Keeps the invitation as a DRAFT, in the caller's transaction, which must be
 * withSignedStates' for its organisation; `states` are that transaction's.
 * The admin who asked must be a membership of the organisation (the table's
 * key); whether they may ask is the caller's to have decided.
 */
export async function draftInvitation(
  tx: InvitationsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  change: InvitationChange,
  { stepUpChallengeId, createdAt, actor }: { stepUpChallengeId: string; createdAt: Date; actor: AuditActor },
): Promise<RecordedState> {
  const { orgId, id, email, role, invitedBy, expiresAt } = change;
  const sealed = keys.encrypt('field-encryption', Buffer.from(email, 'utf8'), emailAssociatedData(orgId, id));
  const fields = {
    role,
    status: INVITATION.initial,
    invited_by: invitedBy,
    expires_at: expiresAt,
    step_up_challenge_id: stepUpChallengeId,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(INVITATIONS.table)
    .values({
      org_id: orgId,
      id,
      ...fields,
      created_at: createdAt,
      email_ciphertext: sealed.ciphertext,
      email_key_version: sealed.keyVersion,
    })
    .execute();
  return states.record(tx, INVITATIONS, { orgId, id }, 'new', fields, {
    actor,
    action: 'invitation.drafted',
    details: { role },
  });
}

/** An invitation as its answers show it, from its verified state. */
export interface InvitationRecord {
  readonly id: string;
  readonly role: Role;
  readonly status: (typeof INVITATION.states)[number];
  readonly expiresAt: Date;
  readonly stepUpChallengeId: string;
}

type Found<T> = T | { readonly outcome: 'missing' } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const recordOf = (id: string, fields: ReadonlyMap<string, string | null>): InvitationRecord => {
  const role = fields.get('role');
  const status = fields.get('status');
  const expiresAt = fields.get('expires_at');
  const stepUpChallengeId = fields.get('step_up_challenge_id');
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    !isRole(role) ||
    !INVITATION.states.some((state) => state === status) ||
    typeof expiresAt !== 'string' ||
    typeof stepUpChallengeId !== 'string'
  ) {
    throw new Error(`A verified invitation holds a field that isn't one of its own: ${id}`);
  }
  return {
    id,
    role,
    status: status as InvitationRecord['status'],
    expiresAt: new Date(expiresAt),
    stepUpChallengeId,
  };
};

/**
 * The invitation, read for an answer (`share`) and verified, in the caller's
 * transaction, which must be withSignedStates' for its organisation.
 */
export async function invitationRecord(
  tx: InvitationsTransaction,
  states: SignedStates,
  orgId: string,
  id: string,
): Promise<Found<{ readonly outcome: 'found'; readonly invitation: InvitationRecord }>> {
  const state = await states.verifiedState(tx, INVITATIONS, { orgId, id }, 'share');
  if (state.outcome !== 'verified') return state;
  return { outcome: 'found', invitation: recordOf(id.toLowerCase(), state.fields) };
}

/** An invitation that can't be read as it was written: its address won't open. */
export class InvitationUnreadable extends Error {
  constructor(id: string, options: ErrorOptions) {
    super(`An invitation's address can't be opened: ${id}`, options);
    this.name = 'InvitationUnreadable';
  }
}

/**
 * The draft, read for the change that opens it (`change`, so it is locked
 * until the transaction ends) and verified, in the caller's transaction,
 * which must be withSignedStates' for its organisation: its change and that
 * change's hash, from the verified row and the address decrypted; or why it
 * can't open: missing, tampered with, no longer a DRAFT, or past its end at
 * `now`. An address that won't open throws InvitationUnreadable.
 */
export async function invitationToOpen(
  tx: InvitationsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  { orgId, id, now }: { orgId: string; id: string; now: Date },
): Promise<
  Found<
    | {
        readonly outcome: 'draft';
        readonly invitation: InvitationRecord;
        readonly change: InvitationChange;
        readonly changeHash: Buffer;
      }
    | { readonly outcome: 'not_draft' | 'ended' }
  >
> {
  const state = await states.verifiedState(tx, INVITATIONS, { orgId, id }, 'change');
  if (state.outcome !== 'verified') return state;
  const invitation = recordOf(id.toLowerCase(), state.fields);
  if (invitation.status !== 'DRAFT') return { outcome: 'not_draft' };
  if (invitation.expiresAt.getTime() <= now.getTime()) return { outcome: 'ended' };
  const invitedBy = state.fields.get('invited_by');
  if (typeof invitedBy !== 'string') throw new Error(`A verified invitation names no admin who asked: ${id}`);
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the encrypted address, no authority field: it opens only with its own row's IDs, and the row is locked by the verified read above
    .selectFrom(INVITATIONS.table)
    .select(['email_ciphertext', 'email_key_version'])
    .where('org_id', '=', orgId)
    .where('id', '=', id)
    .executeTakeFirstOrThrow();
  let email: string;
  try {
    email = keys
      .decrypt(
        'field-encryption',
        { keyVersion: row.email_key_version, ciphertext: row.email_ciphertext },
        emailAssociatedData(orgId, id),
      )
      .toString('utf8');
  } catch (error) {
    throw new InvitationUnreadable(id, { cause: error });
  }
  const change: InvitationChange = {
    orgId,
    id,
    email,
    role: invitation.role,
    invitedBy,
    expiresAt: invitation.expiresAt,
  };
  return { outcome: 'draft', invitation, change, changeHash: changeHashOf(change) };
}

/** The token's SHA-256, as the directory lists it. */
const tokenHashOf = (token: string): Buffer => createHash('sha256').update(token, 'ascii').digest();

/**
 * Opens the draft `invitationToOpen` read in this same transaction: its
 * token made, its SHA-256 listed in the directory, and the invitation moved
 * to OPEN, with `details` (the step-up's evidence) on the event. The token
 * is given back to be shown once; nothing keeps it.
 */
export async function openInvitation(
  tx: InvitationsTransaction,
  states: SignedStates,
  { orgId, id, actor, details }: { orgId: string; id: string; actor: AuditActor; details: AuditDetails },
): Promise<
  Found<{ readonly outcome: 'opened'; readonly token: string } | { readonly outcome: 'refused'; readonly from: string }>
> {
  const token = randomBytes(32).toString('base64url');
  await registerInvite(tx, { orgId, invitationId: id, tokenHash: tokenHashOf(token) });
  const moved = await states.changeStatus(tx, INVITATIONS, { orgId, id }, 'open', {
    actor,
    action: 'invitation.opened',
    details,
  });
  if (moved.outcome !== 'changed') return moved;
  return { outcome: 'opened', token };
}
