// Resets of a lost second factor (0025): an authority table (ADR-012 §2),
// since a reset ends in a login's second factor removed. Its status, whom it
// is for and who asked (by their memberships), the step-up challenge opened
// for it, when it lapses, the contact who confirmed it and when its
// cooling-off ends must equal its latest signed event, and every read a
// decision rests on goes through the audit module's verifiedState with the
// description below, on the product's authority-table list
// (packages/core/src/authority-tables.ts).
//
// How a reset goes, in the API's transactions (B6-3b composes them with the
// step-up, ADR-003 §9, and the notices):
// 1. `resetChange` settles the pending change and its SHA-256, which the
//    admin's step-up challenge binds to; `draftReset` keeps it as a DRAFT,
//    naming the challenge.
// 2. Once stepped up, `resetForChange` reads it for the change (DRAFT), and
//    `askContacts` writes one secret for each contact that counts, encrypted,
//    and moves it to AWAITING_CONTACT. The sender reads each secret back with
//    `confirmationSecret` to make the contact's link.
// 3. A contact's link: `confirmationMatches` checks the secret it carries
//    against the one written for that reset and contact, and `confirmReset`
//    names the contact, sets the cooling-off and moves it to COOLING_OFF.
// 4. `moveReset` cancels it, lets it lapse, or (B6-3c) completes it.
//
// A secret is kept encrypted with field-encryption, its organisation, reset
// and contact as associated data (ADR-011 §2): one planted by someone without
// the key, or copied from another row, won't open, which throws
// ConfirmationUnreadable rather than matching.
//
// The inserts are the queries on these tables outside the audit module's
// steps, with the reads of a secret and of the rows' IDs (organizations.ts
// says why a plain insert is safe, and must stay plain).
import { randomBytes, timingSafeEqual } from 'node:crypto';

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
  VerifiedState,
} from '../../audit/index.ts';
import { FACTOR_RESET, type FactorResetStatus, OPEN_RESET_STATUSES } from '../domain/factor-reset.ts';
import { changeHashOf } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

/** A reset's row, as the signed state reads, records and moves it. */
export const FACTOR_RESETS = {
  table: 'identity.factor_resets',
  subject: 'factor_reset',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'person', type: 'uuid' },
    { column: 'requested_by', type: 'uuid' },
    { column: 'step_up_challenge_id', type: 'uuid' },
    { column: 'expires_at', type: 'timestamptz' },
    { column: 'confirmed_by', type: 'uuid' },
    { column: 'cooling_off_until', type: 'timestamptz' },
  ],
  rules: FACTOR_RESET,
} as const satisfies SignedStateTable & { readonly rules: typeof FACTOR_RESET };

/** A transaction on the tables a reset is made and read in, opened by withSignedStates for its organisation. */
export type ResetsTransaction = Transaction<IdentityTables & AuditTables>;

/** A reset as an admin asks for it: the pending change a step-up binds to. */
export interface ResetChange {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** The membership of the person whose second factor is lost. */
  readonly person: string;
  /** The membership of the admin who asked. */
  readonly requestedBy: string;
  /** When it lapses if no contact has confirmed it. */
  readonly expiresAt: Date;
}

/** The change's SHA-256: every fact it is made of, in a fixed order, IDs in lower case. */
const resetHash = (change: ResetChange): Buffer =>
  changeHashOf([
    change.orgId.toLowerCase(),
    change.id.toLowerCase(),
    change.person.toLowerCase(),
    change.requestedBy.toLowerCase(),
    change.expiresAt.toISOString(),
  ]);

/**
 * The reset as a pending change, and its SHA-256 for the step-up challenge.
 * Throws a RangeError for one asked by the person it is for: the caller's own
 * checks come first, so this is a failure on our side (0025 refuses it too).
 */
export function resetChange(change: ResetChange): { change: ResetChange; changeHash: Buffer } {
  if (change.person.toLowerCase() === change.requestedBy.toLowerCase()) {
    throw new RangeError('A reset refused: no one asks for their own');
  }
  return { change, changeHash: resetHash(change) };
}

/**
 * Keeps the reset as a DRAFT, in the caller's transaction, which must be
 * withSignedStates' for its organisation; `states` are that transaction's.
 * Both memberships must be the organisation's (the table's keys); whether the
 * admin may ask, and for whom, is the caller's to have decided.
 */
export async function draftReset(
  tx: ResetsTransaction,
  states: SignedStates,
  change: ResetChange,
  { stepUpChallengeId, createdAt, actor }: { stepUpChallengeId: string; createdAt: Date; actor: AuditActor },
): Promise<RecordedState> {
  const { orgId, id } = change;
  const fields = {
    status: FACTOR_RESET.initial,
    person: change.person,
    requested_by: change.requestedBy,
    step_up_challenge_id: stepUpChallengeId,
    expires_at: change.expiresAt,
    confirmed_by: null,
    cooling_off_until: null,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(FACTOR_RESETS.table)
    .values({ org_id: orgId, id, ...fields, created_at: createdAt })
    .execute();
  return states.record(tx, FACTOR_RESETS, { orgId, id }, 'new', fields, {
    actor,
    action: 'factor_reset.drafted',
    details: {},
  });
}

/** A reset as its answers show it, from its verified state. */
export interface ResetRecord {
  readonly id: string;
  readonly status: FactorResetStatus;
  /** The membership of the person it is for. */
  readonly person: string;
  /** The membership of the admin who asked. */
  readonly requestedBy: string;
  /** The step-up the admin who asked signed in again for. */
  readonly stepUpChallengeId: string;
  readonly expiresAt: Date;
  /** The registered contact who confirmed it; null until one has. */
  readonly confirmedBy: string | null;
  /** When the factor may be removed; null until a contact has confirmed. */
  readonly coolingOffUntil: Date | null;
}

type Found<T> = T | { readonly outcome: 'missing' } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const recordOf = (id: string, fields: ReadonlyMap<string, string | null>): ResetRecord => {
  const status = fields.get('status');
  const person = fields.get('person');
  const requestedBy = fields.get('requested_by');
  const stepUpChallengeId = fields.get('step_up_challenge_id');
  const expiresAt = fields.get('expires_at');
  const confirmedBy = fields.get('confirmed_by');
  const coolingOffUntil = fields.get('cooling_off_until');
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    !FACTOR_RESET.isState(status ?? '') ||
    typeof person !== 'string' ||
    typeof requestedBy !== 'string' ||
    typeof stepUpChallengeId !== 'string' ||
    typeof expiresAt !== 'string' ||
    confirmedBy === undefined ||
    coolingOffUntil === undefined
  ) {
    throw new Error(`A verified reset holds a field that isn't one of its own: ${id}`);
  }
  return {
    id,
    status: status as FactorResetStatus,
    person,
    requestedBy,
    stepUpChallengeId,
    expiresAt: new Date(expiresAt),
    confirmedBy,
    coolingOffUntil: coolingOffUntil === null ? null : new Date(coolingOffUntil),
  };
};

/**
 * The reset, read for an answer (`share`) and verified, in the caller's
 * transaction, which must be withSignedStates' for its organisation.
 */
export async function resetRecord(
  tx: ResetsTransaction,
  states: SignedStates,
  orgId: string,
  id: string,
): Promise<Found<{ readonly outcome: 'found'; readonly reset: ResetRecord }>> {
  const state = await states.verifiedState(tx, FACTOR_RESETS, { orgId, id }, 'share');
  if (state.outcome !== 'verified') return state;
  return { outcome: 'found', reset: recordOf(id.toLowerCase(), state.fields) };
}

/**
 * The reset, read for a change (`change`, so it is locked until the
 * transaction ends) and verified, in the caller's transaction, which must be
 * withSignedStates' for its organisation: as it stands, with the change it
 * was asked as and that change's hash (what the admin's step-up binds to), and
 * the state a move records from. Whether its status allows the move is the
 * caller's to judge.
 */
export async function resetForChange(
  tx: ResetsTransaction,
  states: SignedStates,
  { orgId, id }: { orgId: string; id: string },
): Promise<
  Found<{
    readonly outcome: 'found';
    readonly reset: ResetRecord;
    readonly change: ResetChange;
    readonly changeHash: Buffer;
    readonly state: VerifiedState;
  }>
> {
  const state = await states.verifiedState(tx, FACTOR_RESETS, { orgId, id }, 'change');
  if (state.outcome !== 'verified') return state;
  const reset = recordOf(id.toLowerCase(), state.fields);
  const change: ResetChange = {
    orgId,
    id,
    person: reset.person,
    requestedBy: reset.requestedBy,
    expiresAt: reset.expiresAt,
  };
  return { outcome: 'found', reset, change, changeHash: resetHash(change), state };
}

/**
 * The person's open resets (DRAFT, AWAITING_CONTACT or COOLING_OFF), each
 * read for a change and verified, in the caller's transaction, which must be
 * withSignedStates' for the organisation; or tampered with, at the first that
 * doesn't verify. At most one is open at a time, which the ask holds (B6-3b):
 * under a lock for the person, it finds the one there, to refuse it, or to let
 * it lapse first. The status narrows the rows read; each is then judged by its
 * signed state, and one planted as closed can't hide an open one it isn't.
 */
export async function openResetsFor(
  tx: ResetsTransaction,
  states: SignedStates,
  orgId: string,
  person: string,
): Promise<
  | { readonly outcome: 'found'; readonly resets: readonly ResetRecord[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the rows' IDs alone, each then read through its signed state
    .selectFrom(FACTOR_RESETS.table)
    .select('id')
    .where('person', '=', person)
    .where('status', 'in', OPEN_RESET_STATUSES)
    .orderBy('id')
    .execute();
  const resets: ResetRecord[] = [];
  for (const { id } of rows) {
    const read = await resetForChange(tx, states, { orgId, id });
    if (read.outcome === 'tampered') return read;
    // Gone between the two reads: the row's check finds that too, on the next read.
    if (read.outcome === 'missing') continue;
    resets.push(read.reset);
  }
  return { outcome: 'found', resets };
}

/** A reset that didn't move as its caller read it would: a failure on our side, or the row tampered with. */
export class ResetNotChanged extends Error {
  readonly outcome: string;

  constructor(id: string, outcome: string) {
    super(`A reset didn't change (${outcome}): ${id}`);
    this.name = 'ResetNotChanged';
    this.outcome = outcome;
  }
}

/** A secret's associated data: the reset and contact it was written for, so it opens nowhere else. */
const secretAssociatedData = (orgId: string, resetId: string, contactId: string) =>
  [
    'identity.factor_reset_confirmations.secret',
    orgId.toLowerCase(),
    resetId.toLowerCase(),
    contactId.toLowerCase(),
  ] as const;

/** A secret a link carries: 32 random bytes, base64url. */
const newSecret = (): string => randomBytes(32).toString('base64url');

/**
 * Sends the reset to its contacts, from the state `resetForChange` gave in
 * this same transaction: a secret written for each contact named (encrypted,
 * for its link), then moved to AWAITING_CONTACT, with `details` (the step-up's
 * evidence) on the move's event. Which contacts count is the caller's to
 * have decided; there must be at least one. Anything but the move throws
 * ResetNotChanged.
 */
export async function askContacts(
  tx: ResetsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  {
    orgId,
    id,
    contactIds,
    createdAt,
    actor,
    details,
  }: {
    orgId: string;
    id: string;
    contactIds: readonly string[];
    createdAt: Date;
    actor: AuditActor;
    details: AuditDetails;
  },
): Promise<void> {
  if (contactIds.length === 0) throw new RangeError('A reset is sent to at least one contact');
  await tx
    .insertInto('identity.factor_reset_confirmations')
    .values(
      contactIds.map((contactId) => {
        const sealed = keys.encrypt(
          'field-encryption',
          Buffer.from(newSecret(), 'utf8'),
          secretAssociatedData(orgId, id, contactId),
        );
        return {
          org_id: orgId,
          reset_id: id,
          contact_id: contactId,
          secret_ciphertext: sealed.ciphertext,
          secret_key_version: sealed.keyVersion,
          created_at: createdAt,
        };
      }),
    )
    .execute();
  const moved = await states.changeStatus(tx, FACTOR_RESETS, { orgId, id }, 'ask_contacts', {
    actor,
    action: 'factor_reset.sent_to_contacts',
    details: { ...details, contacts: contactIds.length },
  });
  if (moved.outcome !== 'changed') throw new ResetNotChanged(id, moved.outcome);
}

/** A secret written for a reset and contact that won't open: planted or copied, or its key gone. */
export class ConfirmationUnreadable extends Error {
  constructor(resetId: string, contactId: string, options: ErrorOptions) {
    super(`A reset's confirmation can't be opened: ${resetId}, ${contactId}`, options);
    this.name = 'ConfirmationUnreadable';
  }
}

/**
 * The secret written for the reset and contact, decrypted, in the caller's
 * transaction, which must be withTenant's (or withSignedStates') for the
 * organisation: what the contact's link carries (B6-3b's sender). Undefined
 * when none was written for them; one that won't open throws
 * ConfirmationUnreadable.
 */
export async function confirmationSecret(
  tx: Transaction<IdentityTables>,
  keys: KeyProvider,
  { orgId, resetId, contactId }: { orgId: string; resetId: string; contactId: string },
): Promise<string | undefined> {
  const row = await tx
    .selectFrom('identity.factor_reset_confirmations')
    .select(['secret_ciphertext', 'secret_key_version'])
    .where('org_id', '=', orgId)
    .where('reset_id', '=', resetId)
    .where('contact_id', '=', contactId)
    .executeTakeFirst();
  if (row === undefined) return undefined;
  try {
    return keys
      .decrypt(
        'field-encryption',
        { keyVersion: row.secret_key_version, ciphertext: row.secret_ciphertext },
        secretAssociatedData(orgId, resetId, contactId),
      )
      .toString('utf8');
  } catch (error) {
    throw new ConfirmationUnreadable(resetId, contactId, { cause: error });
  }
}

/**
 * Whether `secret`, as a contact's link carries it, is the one written for
 * the reset and contact: `matches`, `no_link` when none was written for them,
 * or `wrong`, compared in constant time. One written that won't open throws
 * ConfirmationUnreadable.
 */
export async function confirmationMatches(
  tx: Transaction<IdentityTables>,
  keys: KeyProvider,
  link: { orgId: string; resetId: string; contactId: string; secret: string },
): Promise<'matches' | 'no_link' | 'wrong'> {
  const written = await confirmationSecret(tx, keys, link);
  if (written === undefined) return 'no_link';
  const expected = Buffer.from(written, 'utf8');
  const given = Buffer.from(link.secret, 'utf8');
  return expected.length === given.length && timingSafeEqual(expected, given) ? 'matches' : 'wrong';
}

/**
 * Confirms the reset `resetForChange` read in this same transaction, from
 * the state it gave: the contact who confirmed and the cooling-off's end set,
 * then moved to COOLING_OFF, with `details` on the move's event. Whether the
 * contact counts, and the link matched, is the caller's to have decided.
 * Anything but the move throws ResetNotChanged.
 */
export async function confirmReset(
  tx: ResetsTransaction,
  states: SignedStates,
  {
    orgId,
    id,
    state,
    contactId,
    coolingOffUntil,
    details,
  }: {
    orgId: string;
    id: string;
    state: VerifiedState;
    contactId: string;
    coolingOffUntil: Date;
    details: AuditDetails;
  },
): Promise<void> {
  const key = { orgId, id };
  // A contact is no user of Agent X: the API records its link's confirmation, naming the contact.
  const actor: AuditActor = { type: 'system', id: 'api' };
  await states.record(
    tx,
    FACTOR_RESETS,
    key,
    state,
    { confirmed_by: contactId, cooling_off_until: coolingOffUntil },
    { actor, action: 'factor_reset.cooling_off_set', details: { contact: contactId } },
  );
  const moved = await states.changeStatus(tx, FACTOR_RESETS, key, 'confirm', {
    actor,
    action: 'factor_reset.confirmed',
    details: { ...details, contact: contactId },
  });
  if (moved.outcome !== 'changed') throw new ResetNotChanged(id, moved.outcome);
}

/** The moves that set no field: an admin's cancel, a lapse, and (B6-3c) the factor removed. */
const MOVES = {
  cancel: 'factor_reset.cancelled',
  expire: 'factor_reset.expired',
  complete: 'factor_reset.completed',
} as const;

/**
 * Moves the reset `resetForChange` read in this same transaction: cancelled,
 * lapsed or completed, with `details` on the event. Whether its status and
 * clocks allow it is the caller's to have decided (a refused move throws).
 * Anything but the move throws ResetNotChanged.
 */
export async function moveReset(
  tx: ResetsTransaction,
  states: SignedStates,
  {
    orgId,
    id,
    event,
    actor,
    details,
  }: { orgId: string; id: string; event: keyof typeof MOVES; actor: AuditActor; details: AuditDetails },
): Promise<void> {
  const moved = await states.changeStatus(tx, FACTOR_RESETS, { orgId, id }, event, {
    actor,
    action: MOVES[event],
    details,
  });
  if (moved.outcome !== 'changed') throw new ResetNotChanged(id, moved.outcome);
}
