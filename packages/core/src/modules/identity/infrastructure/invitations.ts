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
import { INVITATION, invitationEmail, invitationEnds, needsConfirmation } from '../domain/invitation.ts';
import { isRole, type Role } from '../domain/membership.ts';
import { changeHashOf } from './step-up-challenges.ts';
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
    { column: 'accepted_by', type: 'uuid' },
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
  /** The membership of the admin who asked; null for the first admin's, which the operator's command asks for (B4-6a). */
  readonly invitedBy: string | null;
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

/** The change's SHA-256: every fact it is made of, in a fixed order, IDs in lower case. */
const invitationHash = (change: InvitationChange): Buffer =>
  changeHashOf([
    change.orgId.toLowerCase(),
    change.id.toLowerCase(),
    change.email,
    change.role,
    change.invitedBy?.toLowerCase() ?? '',
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
  return { change, changeHash: invitationHash(change) };
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
  {
    stepUpChallengeId,
    createdAt,
    actor,
  }: {
    /** The step-up the admin signs in again for; null only for the operator's first admin (0020). */
    stepUpChallengeId: string | null;
    createdAt: Date;
    actor: AuditActor;
  },
): Promise<RecordedState> {
  const { orgId, id, email, role, invitedBy, expiresAt } = change;
  const sealed = keys.encrypt('field-encryption', Buffer.from(email, 'utf8'), emailAssociatedData(orgId, id));
  const fields = {
    role,
    status: INVITATION.initial,
    invited_by: invitedBy,
    expires_at: expiresAt,
    step_up_challenge_id: stepUpChallengeId,
    accepted_by: null,
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
  /** The step-up the admin who asked signed in again for; null for the operator's first admin (B4-6a). */
  readonly stepUpChallengeId: string | null;
  /** Whether a member asked for it, or the operator's command, for an organisation's first admin (B4-6a). */
  readonly byOperator: boolean;
  /** The person who accepted it (B4-4b), once one has. */
  readonly acceptedBy: string | null;
}

type Found<T> = T | { readonly outcome: 'missing' } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const recordOf = (id: string, fields: ReadonlyMap<string, string | null>): InvitationRecord => {
  const role = fields.get('role');
  const status = fields.get('status');
  const expiresAt = fields.get('expires_at');
  const stepUpChallengeId = fields.get('step_up_challenge_id');
  const invitedBy = fields.get('invited_by');
  const acceptedBy = fields.get('accepted_by');
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    !isRole(role) ||
    !INVITATION.states.some((state) => state === status) ||
    typeof expiresAt !== 'string' ||
    stepUpChallengeId === undefined ||
    invitedBy === undefined ||
    acceptedBy === undefined
  ) {
    throw new Error(`A verified invitation holds a field that isn't one of its own: ${id}`);
  }
  return {
    id,
    role,
    status: status as InvitationRecord['status'],
    expiresAt: new Date(expiresAt),
    stepUpChallengeId,
    byOperator: invitedBy === null,
    acceptedBy,
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
 * The invited address, decrypted, from a row the caller has read through its
 * signed state in this transaction. An address that won't open throws
 * InvitationUnreadable.
 */
async function invitedEmail(tx: InvitationsTransaction, keys: KeyProvider, orgId: string, id: string): Promise<string> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the encrypted address, no authority field: it opens only with its own row's IDs, and the caller read the row through its signed state first
    .selectFrom(INVITATIONS.table)
    .select(['email_ciphertext', 'email_key_version'])
    .where('org_id', '=', orgId)
    .where('id', '=', id)
    .executeTakeFirstOrThrow();
  try {
    return keys
      .decrypt(
        'field-encryption',
        { keyVersion: row.email_key_version, ciphertext: row.email_ciphertext },
        emailAssociatedData(orgId, id),
      )
      .toString('utf8');
  } catch (error) {
    throw new InvitationUnreadable(id, { cause: error });
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
        /** The step-up the admin who asked signs in again for: a member's draft names one (0020). */
        readonly stepUpChallengeId: string;
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
  const { stepUpChallengeId } = invitation;
  // The operator's first admin opens as it is made, so a draft is always a member's (0020's check holds both).
  if (typeof invitedBy !== 'string' || stepUpChallengeId === null) {
    throw new Error(`A verified invitation names no admin who asked: ${id}`);
  }
  const email = await invitedEmail(tx, keys, orgId, id);
  const change: InvitationChange = {
    orgId,
    id,
    email,
    role: invitation.role,
    invitedBy,
    expiresAt: invitation.expiresAt,
  };
  return { outcome: 'draft', invitation, stepUpChallengeId, change, changeHash: invitationHash(change) };
}

/** A token's SHA-256, as the directory lists it and as accepting looks it up (B4-4c). */
export const inviteTokenHash = (token: string): Buffer => createHash('sha256').update(token, 'ascii').digest();

/** An invitation that didn't open: the caller read it as a DRAFT first, so this is a failure on our side. */
export class InvitationNotOpened extends Error {
  readonly outcome: string;

  constructor(id: string, outcome: string) {
    super(`An invitation didn't open (${outcome}): ${id}`);
    this.name = 'InvitationNotOpened';
    this.outcome = outcome;
  }
}

/**
 * Opens the draft `invitationToOpen` read in this same transaction: its
 * token made, its SHA-256 listed in the directory, and the invitation moved
 * to OPEN, with `details` (the step-up's evidence) on the event. The token
 * is given back to be shown once; nothing keeps it. Anything but the move
 * (the invitation missing, no longer a DRAFT, or tampered with) throws
 * InvitationNotOpened, so the directory's entry rolls back with the rest and
 * no token is ever listed for an invitation that didn't open.
 */
export async function openInvitation(
  tx: InvitationsTransaction,
  states: SignedStates,
  { orgId, id, actor, details }: { orgId: string; id: string; actor: AuditActor; details: AuditDetails },
): Promise<string> {
  const token = randomBytes(32).toString('base64url');
  await openListed(tx, states, { orgId, id, actor, details, tokenHash: inviteTokenHash(token) });
  return token;
}

/** Lists the token's SHA-256 for the invitation, then moves it to OPEN; InvitationNotOpened otherwise. */
async function openListed(
  tx: InvitationsTransaction,
  states: SignedStates,
  {
    orgId,
    id,
    actor,
    details,
    tokenHash,
  }: { orgId: string; id: string; actor: AuditActor; details: AuditDetails; tokenHash: Buffer },
): Promise<void> {
  // Before the move, whose event takes the chain's head, the last lock of all (ADR-006 §6).
  await registerInvite(tx, { orgId, invitationId: id, tokenHash });
  const moved = await states.changeStatus(tx, INVITATIONS, { orgId, id }, 'open', {
    actor,
    action: 'invitation.opened',
    details,
  });
  if (moved.outcome !== 'changed') throw new InvitationNotOpened(id, moved.outcome);
}

/** The operator's invitation of an organisation's first admin (B4-6a). */
export interface FirstAdminInvitation {
  readonly orgId: string;
  /** Its ID, made by the command. */
  readonly id: string;
  /** The invited address, as given: checked and put in lower case here. */
  readonly email: string;
  /** The SHA-256 of the token in the link, made where the link is shown, never here: the token never reaches the job. */
  readonly tokenHash: Buffer;
  readonly createdAt: Date;
  /** The operator's command. */
  readonly actor: AuditActor;
}

/**
 * The operator's invitation of an organisation's first admin (0020, B4-6a),
 * in the caller's transaction, which must be withSignedStates' for the
 * organisation: an admin's invitation naming no member who asked and no
 * step-up, kept as a DRAFT and opened at once with the token's SHA-256 the
 * caller was given. Accepted while the organisation has no members, it makes
 * the first admin at once; otherwise an admin confirms who accepted. Throws a
 * RangeError for an address that isn't one, or a hash that isn't 32 bytes.
 */
export async function inviteFirstAdmin(
  tx: InvitationsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  { orgId, id, email, tokenHash, createdAt, actor }: FirstAdminInvitation,
): Promise<void> {
  const address = invitationEmail(email);
  if (address === undefined) throw new RangeError('A first admin refused: the address is not one');
  if (!Buffer.isBuffer(tokenHash) || tokenHash.length !== 32) {
    throw new RangeError("A first admin refused: the token's hash is not 32 bytes");
  }
  const change: InvitationChange = {
    orgId,
    id,
    email: address,
    role: 'admin',
    invitedBy: null,
    expiresAt: invitationEnds(createdAt),
  };
  await draftInvitation(tx, states, keys, change, { stepUpChallengeId: null, createdAt, actor });
  await openListed(tx, states, { orgId, id, actor, details: { role: 'admin', byOperator: true }, tokenHash });
}

/**
 * The open invitation, read for the change that accepts it (`change`, so it
 * is locked until the transaction ends) and verified, in the caller's
 * transaction, which must be withSignedStates' for its organisation: with the
 * invited address decrypted, for the caller to match against the accepting
 * person's verified one; or why it can't be accepted: missing, tampered
 * with, or closed (not OPEN, or past its end at `now`).
 */
export async function invitationToAccept(
  tx: InvitationsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  { orgId, id, now }: { orgId: string; id: string; now: Date },
): Promise<
  Found<
    | { readonly outcome: 'open'; readonly invitation: InvitationRecord; readonly email: string }
    | { readonly outcome: 'closed' }
  >
> {
  const state = await states.verifiedState(tx, INVITATIONS, { orgId, id }, 'change');
  if (state.outcome !== 'verified') return state;
  const invitation = recordOf(id.toLowerCase(), state.fields);
  if (invitation.status !== 'OPEN' || invitation.expiresAt.getTime() <= now.getTime()) return { outcome: 'closed' };
  return { outcome: 'open', invitation, email: await invitedEmail(tx, keys, orgId, id) };
}

/** An invitation that didn't take its acceptance: the caller read it as OPEN first, so this is a failure on our side. */
export class InvitationNotAccepted extends Error {
  readonly outcome: string;

  constructor(id: string, outcome: string) {
    super(`An invitation didn't take its acceptance (${outcome}): ${id}`);
    this.name = 'InvitationNotAccepted';
    this.outcome = outcome;
  }
}

/**
 * Accepts the open invitation `invitationToAccept` read in this same
 * transaction for `userId`, who the caller has matched to it: who accepted is
 * recorded and sealed, then it moves to ACCEPTED, or, for a role an admin
 * must confirm (admin, approver), to AWAITING_CONFIRMATION. The membership of
 * a role that joins at once is the caller's to add, in the same transaction.
 * Anything but those moves throws InvitationNotAccepted, so nothing is kept.
 */
export async function acceptInvitation(
  tx: InvitationsTransaction,
  states: SignedStates,
  {
    orgId,
    id,
    userId,
    actor,
    noMembers = false,
  }: {
    orgId: string;
    id: string;
    userId: string;
    actor: AuditActor;
    /** The organisation has no members at all: the operator's first admin then joins at once (B4-6a). */
    noMembers?: boolean;
  },
): Promise<{ readonly outcome: 'accepted' | 'awaiting_confirmation'; readonly role: Role }> {
  const key = { orgId, id };
  const state = await states.verifiedState(tx, INVITATIONS, key, 'change');
  if (state.outcome !== 'verified') throw new InvitationNotAccepted(id, state.outcome);
  const { role, status, byOperator } = recordOf(id.toLowerCase(), state.fields);
  if (status !== 'OPEN') throw new InvitationNotAccepted(id, status);
  await states.record(
    tx,
    INVITATIONS,
    key,
    state,
    { accepted_by: userId },
    {
      actor,
      action: 'invitation.acceptance_recorded',
      details: { role },
    },
  );
  // The first admin has no one to confirm them: the operator's command asked, for an organisation no one belongs to.
  const waits = needsConfirmation(role) && !(byOperator && noMembers);
  const moved = await states.changeStatus(tx, INVITATIONS, key, waits ? 'await' : 'accept', {
    actor,
    action: waits ? 'invitation.awaiting_confirmation' : 'invitation.accepted',
    details: { role },
  });
  if (moved.outcome !== 'changed') throw new InvitationNotAccepted(id, moved.outcome);
  return { outcome: waits ? 'awaiting_confirmation' : 'accepted', role };
}

/**
 * The invitation, read for the change that confirms or declines who accepted
 * it (`change`, so it is locked until the transaction ends) and verified, in
 * the caller's transaction, which must be withSignedStates' for its
 * organisation: waiting for confirmation, with the version its signed state
 * has reached (a confirmation's step-up binds to it, B4-4d); or why not.
 */
export async function invitationToConfirm(
  tx: InvitationsTransaction,
  states: SignedStates,
  { orgId, id }: { orgId: string; id: string },
): Promise<
  Found<
    | { readonly outcome: 'waiting'; readonly invitation: InvitationRecord; readonly version: number }
    | { readonly outcome: 'not_waiting' }
  >
> {
  const state = await states.verifiedState(tx, INVITATIONS, { orgId, id }, 'change');
  if (state.outcome !== 'verified') return state;
  const invitation = recordOf(id.toLowerCase(), state.fields);
  if (invitation.status !== 'AWAITING_CONFIRMATION') return { outcome: 'not_waiting' };
  return { outcome: 'waiting', invitation, version: state.version };
}
