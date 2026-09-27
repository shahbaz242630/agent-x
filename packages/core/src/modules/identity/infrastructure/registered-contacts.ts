// Registered contacts (0022): an organisation's own contacts, by email
// address, its trust anchor (ADR-012 §1, §8). An authority table (ADR-012
// §2), since a contact confirms a reset (B6-3): its status, the admin who
// added it (by their membership), when it starts to count and the step-up
// challenge opened for it must equal its latest signed event, and every read
// a decision rests on goes through the audit module's verifiedState with the
// description below, on the product's authority-table list
// (packages/core/src/authority-tables.ts).
//
// How a contact is added, in the API's transactions (B6-1c composes them with
// the step-up, ADR-003 §9 step 7):
// 1. `contactChange` settles the pending change and its SHA-256, which the
//    step-up challenge binds to.
// 2. `draftContact` keeps it as a DRAFT, with the challenge's ID; the address
//    is encrypted with the organisation and the contact as its associated
//    data (ADR-011 §2).
// 3. On confirming, `contactToActivate` reads the draft for the change, still
//    a DRAFT, and gives its change and hash again, from the verified row and
//    the address it decrypts: the challenge is consumed only for that hash,
//    so what becomes a contact is exactly what was stepped up for.
// 4. `activateContact` sets when it starts to count, a cooling-off from now,
//    and moves it to ACTIVE, with the step-up's evidence on the event.
//
// Removing one: `contactToRemove` reads it for the change, ACTIVE, with the
// hash a removal's step-up binds to (the organisation and the contact: it is
// ACTIVE once only); `removeContact` moves it to REMOVED.
//
// `contactsOf` gives the organisation's contacts, each verified, with its
// address: only once every contact the table or the log knows of verifies
// (verifyAll), so an owner who deletes a contact's row, to keep it from being
// told, is caught as surely as one who changes it.
//
// The insert is the one query on this table outside the audit module's steps
// but for reading the encrypted address and the rows' IDs, as for an
// invitation (organizations.ts says why a plain insert is safe, and must stay
// plain).
import type { SignedStateTable } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type Kysely, sql, type Transaction } from 'kysely';

import {
  type AuditActor,
  type AuditDetails,
  type AuditTables,
  type RecordedState,
  type SignedStates,
  type SignedStatesServices,
  type TamperSign,
  type VerifiedState,
  withSignedStates,
} from '../../audit/index.ts';
import { invitationEmail } from '../domain/invitation.ts';
import { REGISTERED_CONTACT } from '../domain/registered-contact.ts';
import { changeHashOf } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';

/** A registered contact's row, as the signed state reads, records and moves it. */
export const REGISTERED_CONTACTS = {
  table: 'identity.registered_contacts',
  subject: 'registered_contact',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'added_by', type: 'uuid' },
    { column: 'counts_from', type: 'timestamptz' },
    { column: 'step_up_challenge_id', type: 'uuid' },
  ],
  rules: REGISTERED_CONTACT,
} as const satisfies SignedStateTable & { readonly rules: typeof REGISTERED_CONTACT };

/** A transaction on the tables a contact is made and read in, opened by withSignedStates for its organisation. */
export type ContactsTransaction = Transaction<IdentityTables & AuditTables>;

/** A contact as an admin asks for it: the pending change a step-up binds to. */
export interface ContactChange {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** The address, in lower case. */
  readonly email: string;
  /** The membership of the admin who asked. */
  readonly addedBy: string;
}

/** The change's SHA-256: every fact it is made of, in a fixed order, IDs in lower case. */
const contactHash = (change: ContactChange): Buffer =>
  changeHashOf([change.orgId.toLowerCase(), change.id.toLowerCase(), change.email, change.addedBy.toLowerCase()]);

/**
 * The contact as a pending change, and its SHA-256 for the step-up
 * challenge. Throws a RangeError for an address that isn't one: the API's own
 * checks come first, so this is a failure on our side.
 */
export function contactChange(request: ContactChange): { change: ContactChange; changeHash: Buffer } {
  const email = invitationEmail(request.email);
  if (email === undefined) throw new RangeError('A contact refused: the address is not one');
  const change: ContactChange = { ...request, email };
  return { change, changeHash: contactHash(change) };
}

/** The address's associated data: the row it belongs to, so it opens nowhere else. */
const emailAssociatedData = (orgId: string, id: string) =>
  ['identity.registered_contacts.email', orgId.toLowerCase(), id.toLowerCase()] as const;

/**
 * Keeps the contact as a DRAFT, in the caller's transaction, which must be
 * withSignedStates' for its organisation; `states` are that transaction's.
 * The admin who asked must be a membership of the organisation (the table's
 * key); whether they may ask, and whether the organisation has room for
 * another, is the caller's to have decided.
 */
export async function draftContact(
  tx: ContactsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  change: ContactChange,
  {
    stepUpChallengeId,
    createdAt,
    actor,
  }: {
    /** The step-up the admin signs in again for. */
    stepUpChallengeId: string;
    createdAt: Date;
    actor: AuditActor;
  },
): Promise<RecordedState> {
  const { orgId, id, email, addedBy } = change;
  const sealed = keys.encrypt('field-encryption', Buffer.from(email, 'utf8'), emailAssociatedData(orgId, id));
  const fields = {
    status: REGISTERED_CONTACT.initial,
    added_by: addedBy,
    counts_from: null,
    step_up_challenge_id: stepUpChallengeId,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(REGISTERED_CONTACTS.table)
    .values({
      org_id: orgId,
      id,
      ...fields,
      created_at: createdAt,
      email_ciphertext: sealed.ciphertext,
      email_key_version: sealed.keyVersion,
    })
    .execute();
  return states.record(tx, REGISTERED_CONTACTS, { orgId, id }, 'new', fields, {
    actor,
    action: 'registered_contact.drafted',
    details: {},
  });
}

/** A contact as its answers show it, from its verified state. */
export interface ContactRecord {
  readonly id: string;
  readonly status: (typeof REGISTERED_CONTACT.states)[number];
  /** The membership of the admin who added it. */
  readonly addedBy: string;
  /** When it starts to count; null for a DRAFT. */
  readonly countsFrom: Date | null;
  /** The step-up the admin who added it signed in again for. */
  readonly stepUpChallengeId: string;
}

type Found<T> = T | { readonly outcome: 'missing' } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const recordOf = (id: string, fields: ReadonlyMap<string, string | null>): ContactRecord => {
  const status = fields.get('status');
  const addedBy = fields.get('added_by');
  const countsFrom = fields.get('counts_from');
  const stepUpChallengeId = fields.get('step_up_challenge_id');
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (
    !REGISTERED_CONTACT.states.some((state) => state === status) ||
    typeof addedBy !== 'string' ||
    countsFrom === undefined ||
    typeof stepUpChallengeId !== 'string'
  ) {
    throw new Error(`A verified contact holds a field that isn't one of its own: ${id}`);
  }
  return {
    id,
    status: status as ContactRecord['status'],
    addedBy,
    countsFrom: countsFrom === null ? null : new Date(countsFrom),
    stepUpChallengeId,
  };
};

/**
 * The contact, read for an answer (`share`) and verified, in the caller's
 * transaction, which must be withSignedStates' for its organisation.
 */
export async function contactRecord(
  tx: ContactsTransaction,
  states: SignedStates,
  orgId: string,
  id: string,
): Promise<Found<{ readonly outcome: 'found'; readonly contact: ContactRecord }>> {
  const state = await states.verifiedState(tx, REGISTERED_CONTACTS, { orgId, id }, 'share');
  if (state.outcome !== 'verified') return state;
  return { outcome: 'found', contact: recordOf(id.toLowerCase(), state.fields) };
}

/** A contact that can't be read as it was written: its address won't open. */
export class ContactUnreadable extends Error {
  constructor(id: string, options: ErrorOptions) {
    super(`A contact's address can't be opened: ${id}`, options);
    this.name = 'ContactUnreadable';
  }
}

/**
 * The contact's address, decrypted, from a row the caller has read through
 * its signed state in this transaction. An address that won't open throws
 * ContactUnreadable.
 */
async function contactEmail(tx: ContactsTransaction, keys: KeyProvider, orgId: string, id: string): Promise<string> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the encrypted address, no authority field: it opens only with its own row's IDs, and the caller read the row through its signed state first
    .selectFrom(REGISTERED_CONTACTS.table)
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
    throw new ContactUnreadable(id, { cause: error });
  }
}

/**
 * The draft, read for the change that activates it (`change`, so it is
 * locked until the transaction ends) and verified, in the caller's
 * transaction, which must be withSignedStates' for its organisation: its
 * change and that change's hash, from the verified row and the address
 * decrypted, and the state `activateContact` records from; or why it can't
 * be: missing, tampered with, or no longer a DRAFT. An address that won't
 * open throws ContactUnreadable.
 */
export async function contactToActivate(
  tx: ContactsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  { orgId, id }: { orgId: string; id: string },
): Promise<
  Found<
    | {
        readonly outcome: 'draft';
        readonly contact: ContactRecord;
        readonly change: ContactChange;
        readonly changeHash: Buffer;
        readonly state: VerifiedState;
      }
    | { readonly outcome: 'not_draft' }
  >
> {
  const state = await states.verifiedState(tx, REGISTERED_CONTACTS, { orgId, id }, 'change');
  if (state.outcome !== 'verified') return state;
  const contact = recordOf(id.toLowerCase(), state.fields);
  if (contact.status !== 'DRAFT') return { outcome: 'not_draft' };
  const change: ContactChange = {
    orgId,
    id,
    email: await contactEmail(tx, keys, orgId, id),
    addedBy: contact.addedBy,
  };
  return { outcome: 'draft', contact, change, changeHash: contactHash(change), state };
}

/** A contact that didn't move as its caller read it would: a failure on our side, or the row tampered with. */
export class ContactNotChanged extends Error {
  readonly outcome: string;

  constructor(id: string, outcome: string) {
    super(`A contact didn't change (${outcome}): ${id}`);
    this.name = 'ContactNotChanged';
    this.outcome = outcome;
  }
}

/**
 * Activates the draft `contactToActivate` read in this same transaction,
 * from the state it gave: its start set to `countsFrom`, then moved to
 * ACTIVE, with `details` (the step-up's evidence) on the move's event.
 * Anything but the move throws ContactNotChanged, so nothing is left half
 * done.
 */
export async function activateContact(
  tx: ContactsTransaction,
  states: SignedStates,
  {
    orgId,
    id,
    state,
    countsFrom,
    actor,
    details,
  }: { orgId: string; id: string; state: VerifiedState; countsFrom: Date; actor: AuditActor; details: AuditDetails },
): Promise<void> {
  const key = { orgId, id };
  await states.record(
    tx,
    REGISTERED_CONTACTS,
    key,
    state,
    { counts_from: countsFrom },
    { actor, action: 'registered_contact.counts_from_set', details: {} },
  );
  const moved = await states.changeStatus(tx, REGISTERED_CONTACTS, key, 'activate', {
    actor,
    action: 'registered_contact.activated',
    details,
  });
  if (moved.outcome !== 'changed') throw new ContactNotChanged(id, moved.outcome);
}

/**
 * A removal's SHA-256: the organisation and the contact. A contact is ACTIVE
 * once only (it is never brought back), so these name the one state a
 * removal can apply to; the challenge binds the action beside it.
 */
const removalHash = (orgId: string, id: string): Buffer => changeHashOf([orgId.toLowerCase(), id.toLowerCase()]);

/**
 * The contact, read for the change that removes it (`change`, so it is locked
 * until the transaction ends) and verified, in the caller's transaction,
 * which must be withSignedStates' for its organisation: ACTIVE, with the hash
 * a removal's step-up binds to; or why it can't be removed: missing, tampered
 * with, or not ACTIVE.
 */
export async function contactToRemove(
  tx: ContactsTransaction,
  states: SignedStates,
  { orgId, id }: { orgId: string; id: string },
): Promise<
  Found<
    | { readonly outcome: 'active'; readonly contact: ContactRecord; readonly changeHash: Buffer }
    | { readonly outcome: 'not_active' }
  >
> {
  const state = await states.verifiedState(tx, REGISTERED_CONTACTS, { orgId, id }, 'change');
  if (state.outcome !== 'verified') return state;
  const contact = recordOf(id.toLowerCase(), state.fields);
  if (contact.status !== 'ACTIVE') return { outcome: 'not_active' };
  return { outcome: 'active', contact, changeHash: removalHash(orgId, id) };
}

/**
 * Removes the contact `contactToRemove` read in this same transaction, with
 * `details` (the step-up's evidence) on the event. Anything but the move
 * throws ContactNotChanged.
 */
export async function removeContact(
  tx: ContactsTransaction,
  states: SignedStates,
  { orgId, id, actor, details }: { orgId: string; id: string; actor: AuditActor; details: AuditDetails },
): Promise<void> {
  const moved = await states.changeStatus(tx, REGISTERED_CONTACTS, { orgId, id }, 'remove', {
    actor,
    action: 'registered_contact.removed',
    details,
  });
  if (moved.outcome !== 'changed') throw new ContactNotChanged(id, moved.outcome);
}

/**
 * The most contacts, removed ones included, and the most objects the log
 * holds about them, that `contactsOf` reads: a removed contact stays, so this
 * allows many changes of a list of MOST_CONTACTS.
 */
export const MOST_CONTACT_RECORDS = 200;

/** More contacts, or objects in the log about them, than `contactsOf` reads. */
export class TooManyContacts extends Error {
  constructor() {
    super(`The organisation has more than ${String(MOST_CONTACT_RECORDS)} contact records, more than a list reads`);
    this.name = 'TooManyContacts';
  }
}

/** A contact with its address. */
export interface ContactWithAddress extends ContactRecord {
  readonly email: string;
}

/**
 * The organisation's contacts, drafts and removed ones included, in order of
 * ID, each read for a decision (`share`) and verified, with its address, in
 * the caller's transaction, which must be withSignedStates' for it; or
 * tampered with, when any contact the table or the log knows of doesn't
 * verify (every alarm is raised, and the organisation held), so no list is
 * given that one deleted, planted or changed would make wrong. More than
 * MOST_CONTACT_RECORDS throws TooManyContacts; an address that won't open
 * throws ContactUnreadable.
 */
export async function contactsOf(
  tx: ContactsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
): Promise<
  | { readonly outcome: 'listed'; readonly contacts: readonly ContactWithAddress[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const whole = await states.verifyAll(tx, orgId, [REGISTERED_CONTACTS], MOST_CONTACT_RECORDS);
  if (whole.outcome === 'too_many') throw new TooManyContacts();
  if (whole.outcome === 'tampered') {
    const [first] = whole.findings;
    if (first === undefined) throw new Error('verifyAll found tampering it names no finding for');
    return { outcome: 'tampered', sign: first.sign };
  }
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the rows' IDs alone, each then read through its signed state; verifyAll has just checked every one the table or the log knows of
    .selectFrom(REGISTERED_CONTACTS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .orderBy('id')
    .execute();
  const contacts: ContactWithAddress[] = [];
  for (const { id } of rows) {
    const read = await contactRecord(tx, states, orgId, id);
    // Verified by verifyAll in this transaction, and locked for share since.
    if (read.outcome !== 'found') throw new Error(`a contact verifyAll verified reads as ${read.outcome}: ${id}`);
    contacts.push({ ...read.contact, email: await contactEmail(tx, keys, orgId, id) });
  }
  return { outcome: 'listed', contacts };
}

/** An organisation's contacts couldn't be believed: whatever rested on them waits (the alarm is raised). */
export class ContactsTampered extends Error {
  constructor(orgId: string) {
    super(`An organisation's registered contacts failed their check: ${orgId}`);
    this.name = 'ContactsTampered';
  }
}

/**
 * The organisation's ACTIVE contacts' IDs, counted or not yet, read and
 * verified in a transaction of their own, withSignedStates' for it: whom a
 * notice to its contacts goes to (B6-1b). Contacts that can't be believed
 * throw ContactsTampered. Each statement is limited to 10 seconds.
 */
export function activeContactsFor(
  db: Kysely<IdentityTables & AuditTables>,
  services: SignedStatesServices,
  orgId: string,
): Promise<readonly string[]> {
  return withSignedStates(db, orgId, services, async (tx, states) => {
    await sql`set local statement_timeout = '10s'`.execute(tx);
    const listed = await contactsOf(tx, states, services.keys, orgId);
    if (listed.outcome === 'tampered') throw new ContactsTampered(orgId);
    return listed.contacts.filter((contact) => contact.status === 'ACTIVE').map((contact) => contact.id);
  });
}

/**
 * The contact's address, from its verified row, in a transaction of its own,
 * withSignedStates' for the organisation: where a notice to it goes (B6-1b).
 * A removed contact's too, as it is told of its own removal; undefined for a
 * draft, or no such contact. A contact that can't be believed throws
 * ContactsTampered; an address that won't open, ContactUnreadable. Each
 * statement is limited to 10 seconds.
 */
export function contactAddressFor(
  db: Kysely<IdentityTables & AuditTables>,
  services: SignedStatesServices,
  orgId: string,
  contactId: string,
): Promise<string | undefined> {
  return withSignedStates(db, orgId, services, async (tx, states) => {
    await sql`set local statement_timeout = '10s'`.execute(tx);
    const read = await contactRecord(tx, states, orgId, contactId);
    if (read.outcome === 'tampered') throw new ContactsTampered(orgId);
    if (read.outcome === 'missing' || read.contact.status === 'DRAFT') return undefined;
    return contactEmail(tx, services.keys, orgId, read.contact.id);
  });
}

/**
 * One contact with its address, read for an answer (`share`) and verified, in
 * the caller's transaction, which must be withSignedStates' for its
 * organisation: what a change's answer shows (B6-1c).
 */
export async function contactShown(
  tx: ContactsTransaction,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  id: string,
): Promise<Found<{ readonly outcome: 'found'; readonly contact: ContactWithAddress }>> {
  const read = await contactRecord(tx, states, orgId, id);
  if (read.outcome !== 'found') return read;
  return {
    outcome: 'found',
    contact: { ...read.contact, email: await contactEmail(tx, keys, orgId, read.contact.id) },
  };
}

/**
 * The organisation's ACTIVE contacts, each with its address, read and
 * verified in a transaction of their own, withSignedStates' for it: what the
 * contacts route lists (B6-1c), logged with the request's correlation ID; or
 * tampered with. Each statement is limited to 10 seconds.
 */
export function registeredContactsFor(
  db: Kysely<IdentityTables & AuditTables>,
  { keys, ids, logger }: SignedStatesServices,
  orgId: string,
  correlationId: string,
): Promise<
  | { readonly outcome: 'listed'; readonly contacts: readonly ContactWithAddress[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const services = { keys, ids, logger: logger.child({ correlationId }) };
  return withSignedStates(db, orgId, services, async (tx, states) => {
    await sql`set local statement_timeout = '10s'`.execute(tx);
    const listed = await contactsOf(tx, states, keys, orgId);
    if (listed.outcome === 'tampered') return listed;
    return { outcome: 'listed', contacts: listed.contacts.filter((contact) => contact.status === 'ACTIVE') };
  });
}
