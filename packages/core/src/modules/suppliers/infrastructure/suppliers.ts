// Suppliers and their versions (0032). Both are authority tables (ADR-012
// §2), so a supplier's status, its current, pending and verified versions,
// its cooling-off, its verifier and its payee key, and everything a version
// says (its supplier and number, its name, which contacts it holds and since
// when its phone is the one it has, the independent source, who entered it
// and when, and its payee reference) must equal the row's latest signed
// event, and every read goes through the audit module's verifiedState with
// the descriptions below. Both are on the product's authority-table list
// (packages/core/src/authority-tables.ts), at the supplier's level in the
// lock order (ADR-006 §6: 6), the supplier before its versions.
//
// A supplier is added in one transaction, withSignedStates' for its
// organisation, with its first version: both rows, then the supplier's first
// signed state, then the version's. A later version is added the same way,
// its supplier read for change first. The inserts are the only queries on
// these tables outside the audit module's steps but for reading a version's
// encrypted contacts and the rows' IDs and creation times, as for an agent's
// row (agents.ts says why a plain insert is safe). The seals are MACs, so no
// name or contact is ever put in an event. A version is made once: 0032's
// `made_once` refuses any change to one after its first signed state.
//
// A supplier is VERIFIED only on the version verified, with no change
// waiting (0032's `verified_rests_on_its_version`; the domain's
// stillVerified): verifying records the verifier and that version first,
// unverifying clears them after, and one suspended comes back verified only
// while it is still verified.
//
// A version's contacts are encrypted under one key version with the
// organisation, the version and the contact's kind as associated data
// (ADR-011 §2), and opened only from a version the caller read through its
// signed state.
import type { SignedStateTable } from '@agentx/platform/db';
import { KeyError, type KeyProvider } from '@agentx/platform/keys';
import { sql, type Transaction } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import {
  contactsHeld,
  reactivationOf,
  type SourceKind,
  SOURCE_KINDS,
  SUPPLIER,
  type SupplierContacts,
  type SupplierDetails,
  supplierDetails,
  type SupplierStatus,
} from '../domain/supplier.ts';
import type { SuppliersTables } from './tables.ts';

/** A supplier's row, as the signed state reads, records and moves it. */
export const SUPPLIERS = {
  table: 'suppliers.suppliers',
  subject: 'supplier',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'current_version_id', type: 'uuid' },
    { column: 'pending_version_id', type: 'uuid' },
    { column: 'cooling_off_until', type: 'timestamptz' },
    { column: 'verified_by', type: 'uuid' },
    { column: 'verified_version_id', type: 'uuid' },
    { column: 'payee_key', type: 'text' },
    { column: 'payee_key_version', type: 'integer' },
  ],
  rules: SUPPLIER,
  // VERIFIED only on the version verified, with nothing pending (0032): CI's A3c allows this one check over the status with other columns.
  statusConditions: ['verified_rests_on_its_version'],
} as const satisfies SignedStateTable & {
  readonly rules: typeof SUPPLIER;
  readonly statusConditions: readonly string[];
};

/** A supplier version's row, as the signed state reads and records it: made once, never moved (0032's `made_once`). */
export const SUPPLIER_VERSIONS = {
  table: 'suppliers.supplier_versions',
  subject: 'supplier_version',
  fields: [
    { column: 'supplier_id', type: 'uuid' },
    { column: 'version', type: 'integer' },
    { column: 'display_name', type: 'text' },
    { column: 'contacts', type: 'text' },
    { column: 'phone_since', type: 'timestamptz' },
    { column: 'source_kind', type: 'text' },
    { column: 'source_ref', type: 'text' },
    { column: 'entered_by', type: 'uuid' },
    { column: 'entered_at', type: 'timestamptz' },
    { column: 'registration_id', type: 'uuid' },
    { column: 'beneficiary_ref', type: 'text' },
    { column: 'payee_hint', type: 'text' },
  ],
  madeOnce: true,
} as const satisfies SignedStateTable & { readonly madeOnce: true };

/** A transaction on the tables suppliers are added and read in, opened by withSignedStates for their organisation. */
export type SuppliersTransaction = Transaction<SuppliersTables & AuditTables>;

interface SupplierKey {
  readonly orgId: string;
  readonly id: string;
}

/** The kinds of contact a version keeps encrypted, each in a column of its own (`<kind>_ciphertext`). */
type ContactKind = 'phone' | 'email' | 'licence';

/**
 * A contact's associated data: the organisation, the version (whose ID names
 * one version of one supplier) and the kind, so it opens nowhere else.
 */
const contactAssociatedData = (key: { readonly orgId: string; readonly versionId: string }, kind: ContactKind) =>
  [`suppliers.supplier_versions.${kind}`, key.orgId.toLowerCase(), key.versionId.toLowerCase()] as const;

/**
 * Each contact given, encrypted for its own version and kind, all under one
 * key version, which the row keeps once: a rotation landing between two of
 * them would leave one that never opens, so that is refused.
 */
function sealContacts(
  keys: KeyProvider,
  key: { readonly orgId: string; readonly versionId: string },
  contacts: SupplierContacts,
) {
  const seal = (kind: ContactKind, value: string) =>
    keys.encrypt('field-encryption', Buffer.from(value, 'utf8'), contactAssociatedData(key, kind));
  const phone = seal('phone', contacts.phone);
  const email = contacts.email === null ? null : seal('email', contacts.email);
  const licence = contacts.tradeLicence === null ? null : seal('licence', contacts.tradeLicence);
  if ([email, licence].some((sealed) => sealed !== null && sealed.keyVersion !== phone.keyVersion)) {
    throw new Error("A version's contacts were sealed under two key versions");
  }
  return {
    phone_ciphertext: phone.ciphertext,
    email_ciphertext: email?.ciphertext ?? null,
    licence_ciphertext: licence?.ciphertext ?? null,
    contacts_key_version: phone.keyVersion,
  };
}

/** A version of a supplier's details, as a use case makes it. */
export interface NewVersion {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  readonly supplierId: string;
  /** Its number: the supplier's next. A number the supplier has already is refused by the table's key. */
  readonly version: number;
  /** Its name, contacts and independent source, as supplierDetails keeps them (checked again here). */
  readonly supplier: SupplierDetails;
  /** The membership of the member who entered them, checked active by the use case. */
  readonly enteredBy: string;
  readonly enteredAt: Date;
  /** Who is making it. */
  readonly actor: AuditActor;
  /** More facts for its event, such as the step-up it was confirmed with. */
  readonly details?: AuditDetails;
}

/** The version's row, checked: its sealed fields, its encrypted contacts, and the facts its event names. */
function versionRow(
  keys: KeyProvider,
  { orgId, id, supplierId, version, supplier, enteredBy, enteredAt }: NewVersion,
  phoneSince: Date,
) {
  const kept = supplierDetails(supplier);
  const fields = {
    supplier_id: supplierId,
    version,
    display_name: kept.displayName,
    contacts: contactsHeld(kept.contacts),
    phone_since: phoneSince,
    source_kind: kept.source.kind,
    source_ref: kept.source.ref,
    entered_by: enteredBy,
    entered_at: enteredAt,
    registration_id: null,
    beneficiary_ref: null,
    payee_hint: null,
  };
  return {
    fields,
    sealed: sealContacts(keys, { orgId, versionId: id }, kept.contacts),
    facts: { supplierId, version, contacts: fields.contacts, sourceKind: kept.source.kind },
  };
}

type VersionRow = ReturnType<typeof versionRow>;

/** Adds the version's row, as versionRow made it. Signed by `recordVersion`, in the same transaction. */
async function insertVersion(tx: SuppliersTransaction, orgId: string, id: string, row: VersionRow): Promise<void> {
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') in the same transaction (see the top of this file)
    .insertInto(SUPPLIER_VERSIONS.table)
    .values({ org_id: orgId, id, ...row.fields, ...row.sealed })
    .execute();
}

const recordVersion = (
  tx: SuppliersTransaction,
  states: SignedStates,
  { orgId, id, actor, details = {} }: NewVersion,
  row: VersionRow,
): Promise<RecordedState> =>
  states.record(tx, SUPPLIER_VERSIONS, { orgId, id }, 'new', row.fields, {
    actor,
    action: 'supplier_version.made',
    details: { ...details, ...row.facts },
  });

/**
 * Makes a later version of a supplier's details (E2, E3), in the caller's
 * transaction, which must be withSignedStates' for its organisation and read
 * the supplier with `change` first (`of`; the lock order: the supplier, then
 * its versions). `follows` is the version it follows, as the caller read it:
 * the supplier's current version, and nothing else (RangeError otherwise, as
 * for another supplier's), so `phone_since` is carried over only from the
 * phone payments use now, while it stays the same; from a new phone it is
 * the new version's own time, so the call-back's "unchanged for 30 days"
 * (E3) reads one field. Pointing the supplier at it is the caller's. Details
 * it can't have are `SupplierDetailsRefused`; both are refused before any
 * SQL runs.
 */
export async function addVersion(
  tx: SuppliersTransaction,
  states: SignedStates,
  keys: KeyProvider,
  version: NewVersion & { readonly of: { readonly supplier: SupplierRecord }; readonly follows: VersionRecord },
): Promise<RecordedState> {
  const { supplier } = version.of;
  // Its supplier's current version is that supplier's own (0032's key), so following it is following the same supplier.
  if (supplier.id !== version.supplierId.toLowerCase() || version.follows.id !== supplier.currentVersionId) {
    throw new RangeError("A later version follows its own supplier's current version");
  }
  // Checked before any SQL runs, as the row is made below.
  const { phone } = supplierDetails(version.supplier).contacts;
  const before = await contactsOf(tx, keys, version.orgId, version.follows);
  const row = versionRow(keys, version, before.phone === phone ? version.follows.phoneSince : version.enteredAt);
  await insertVersion(tx, version.orgId, version.id, row);
  return recordVersion(tx, states, version, row);
}

export interface NewSupplier {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** Its first version's ID, made by the server. */
  readonly versionId: string;
  /** Its name, contacts and independent source, as supplierDetails keeps them (checked again here). */
  readonly supplier: SupplierDetails;
  /** The membership of the member who entered them, checked active by the use case. */
  readonly enteredBy: string;
  readonly createdAt: Date;
  /** Who is adding it. */
  readonly actor: AuditActor;
  /** More facts for its events, such as the step-up it was confirmed with. */
  readonly details?: AuditDetails;
}

/**
 * Adds the supplier, UNVERIFIED, with its first version, in the caller's
 * transaction, which must be withSignedStates' for its organisation. Details
 * it can't have are `SupplierDetailsRefused`, before any SQL runs. Gives the
 * supplier's first signed state, then the version's.
 */
export async function addSupplier(
  tx: SuppliersTransaction,
  states: SignedStates,
  keys: KeyProvider,
  { orgId, id, versionId, supplier, enteredBy, createdAt, actor, details = {} }: NewSupplier,
): Promise<{ readonly supplier: RecordedState; readonly version: RecordedState }> {
  const first: NewVersion = {
    orgId,
    id: versionId,
    supplierId: id,
    version: 1,
    supplier,
    enteredBy,
    enteredAt: createdAt,
    actor,
    details,
  };
  // Its first phone is the supplier's from when it was entered.
  const row = versionRow(keys, first, createdAt);
  const supplierFields = {
    status: SUPPLIER.initial,
    current_version_id: versionId,
    pending_version_id: null,
    cooling_off_until: null,
    verified_by: null,
    verified_version_id: null,
    payee_key: null,
    payee_key_version: null,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(SUPPLIERS.table)
    .values({ org_id: orgId, id, ...supplierFields, created_at: createdAt })
    .execute();
  await insertVersion(tx, orgId, versionId, row);
  // The supplier before its version, as the lock order has them.
  const recorded = await states.record(tx, SUPPLIERS, { orgId, id }, 'new', supplierFields, {
    actor,
    action: 'supplier.added',
    details: { ...details, versionId },
  });
  return { supplier: recorded, version: await recordVersion(tx, states, first, row) };
}

/** A supplier, as its signed state says. */
export interface SupplierRecord {
  readonly id: string;
  readonly status: SupplierStatus;
  /** The version payments use. */
  readonly currentVersionId: string;
  /** A change waiting for its step-up and verification, or null. */
  readonly pendingVersionId: string | null;
  readonly coolingOffUntil: Date | null;
  /** The verifier's membership, and the version they verified, or null. */
  readonly verifiedBy: string | null;
  readonly verifiedVersionId: string | null;
  /** The payee key (ADR-014 §3) and its key's version, or null; the version is null for a partner's own identity. */
  readonly payeeKey: string | null;
  readonly payeeKeyVersion: number | null;
}

/** A supplier read by its ID and verified, with the state a change records from; missing; or tampered with. */
export type SupplierCheck =
  | { readonly outcome: 'found'; readonly supplier: SupplierRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** One of `words`, or undefined. */
const oneOf = <const Word extends string>(words: readonly Word[], value: string | null | undefined): Word | undefined =>
  words.find((word) => word === value);

const WHOLE = /^[1-9][0-9]{0,9}$/;

/** A field's value as text or null, or undefined for one the fields don't hold at all. */
type Field = string | null | undefined;

const timeOf = (value: Field): Date | null | undefined => {
  if (value === null || value === undefined) return value;
  const time = new Date(value);
  return Number.isNaN(time.getTime()) ? undefined : time;
};

const wholeOf = (value: Field): number | null | undefined => {
  if (value === null || value === undefined) return value;
  return WHOLE.test(value) ? Number(value) : undefined;
};

/** The supplier's record from its verified fields, or undefined when one isn't of its kind. */
function supplierRecordOf(id: string, fields: ReadonlyMap<string, string | null>): SupplierRecord | undefined {
  const status = oneOf(SUPPLIER.states, fields.get('status'));
  const currentVersionId = fields.get('current_version_id');
  const pendingVersionId = fields.get('pending_version_id');
  const coolingOffUntil = timeOf(fields.get('cooling_off_until'));
  const verifiedBy = fields.get('verified_by');
  const verifiedVersionId = fields.get('verified_version_id');
  const payeeKey = fields.get('payee_key');
  const payeeKeyVersion = wholeOf(fields.get('payee_key_version'));
  if (
    status === undefined ||
    typeof currentVersionId !== 'string' ||
    pendingVersionId === undefined ||
    coolingOffUntil === undefined ||
    verifiedBy === undefined ||
    verifiedVersionId === undefined ||
    payeeKey === undefined ||
    payeeKeyVersion === undefined
  ) {
    return undefined;
  }
  return {
    id,
    status,
    currentVersionId,
    pendingVersionId,
    coolingOffUntil,
    verifiedBy,
    verifiedVersionId,
    payeeKey,
    payeeKeyVersion,
  };
}

/**
 * The supplier, by its ID, read and verified in the caller's transaction,
 * which must be withSignedStates' for its organisation: `share` for a
 * decision, `change` for a change (its state then what `record` takes).
 * Tampered with, the alarm is raised and the organisation held; anything but
 * `found` grants nothing.
 */
export async function supplierOf(
  tx: SuppliersTransaction,
  states: SignedStates,
  key: SupplierKey,
  lock: 'share' | 'change',
): Promise<SupplierCheck> {
  const state = await states.verifiedState(tx, SUPPLIERS, key, lock);
  if (state.outcome !== 'verified') return state;
  const supplier = supplierRecordOf(key.id.toLowerCase(), state.fields);
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (supplier === undefined) throw new Error(`A verified supplier holds a field that isn't one of its own: ${key.id}`);
  return { outcome: 'found', supplier, state };
}

/** Who moves a supplier, and the facts their events name. */
interface SupplierChange {
  readonly actor: AuditActor;
  readonly details?: AuditDetails;
}

/** The supplier read again for change, in this transaction, after a step moved it: it is there, or something past the app is at work. */
async function againForChange(tx: SuppliersTransaction, states: SignedStates, key: SupplierKey) {
  const read = await supplierOf(tx, states, key, 'change');
  if (read.outcome !== 'found') throw new Error(`A supplier moved in this transaction is gone: ${key.id}`);
  return read;
}

/** Moves the supplier by `event`, which its machine must allow from where it stands; the caller decided it may. */
async function move(
  tx: SuppliersTransaction,
  states: SignedStates,
  key: SupplierKey,
  event: 'verify' | 'unverify' | 'reactivate' | 'reactivate_verified',
  { actor, details = {} }: SupplierChange,
): Promise<void> {
  const moved = await states.changeStatus(tx, SUPPLIERS, key, event, {
    actor,
    action: `supplier.${event}`,
    details,
  });
  if (moved.outcome !== 'changed') throw new RangeError(`A supplier can't ${event} from where it stands: ${key.id}`);
}

/**
 * Verifies the supplier (E3), in the caller's transaction, which read it with
 * `change` (`found`): first the verifier and the version they verified (its
 * current one), then UNVERIFIED > VERIFIED. One with a change waiting, or
 * not UNVERIFIED, is refused (RangeError) before any SQL runs. Gives the
 * supplier as it now stands.
 */
export async function verifySupplier(
  tx: SuppliersTransaction,
  states: SignedStates,
  key: SupplierKey,
  found: { readonly supplier: SupplierRecord; readonly state: VerifiedState },
  { verifiedBy, ...change }: SupplierChange & { readonly verifiedBy: string },
): Promise<SupplierRecord> {
  const { supplier } = found;
  if (supplier.status !== 'UNVERIFIED' || supplier.pendingVersionId !== null) {
    throw new RangeError('Only an unverified supplier with no change waiting is verified');
  }
  const verified = { verified_by: verifiedBy, verified_version_id: supplier.currentVersionId };
  await states.record(tx, SUPPLIERS, key, found.state, verified, {
    actor: change.actor,
    action: 'supplier.verifier_recorded',
    details: { ...change.details, verifiedVersionId: supplier.currentVersionId },
  });
  await move(tx, states, key, 'verify', change);
  return (await againForChange(tx, states, key)).supplier;
}

/**
 * Takes the supplier back to UNVERIFIED (a change of its details, E3), in the
 * caller's transaction, which read it with `change` (`found`): the move, then
 * the verifier and the version they verified cleared, so nothing verified is
 * left to come back to. Gives the supplier as it now stands.
 */
export async function unverifySupplier(
  tx: SuppliersTransaction,
  states: SignedStates,
  key: SupplierKey,
  found: { readonly supplier: SupplierRecord },
  change: SupplierChange,
): Promise<SupplierRecord> {
  if (found.supplier.status !== 'VERIFIED') throw new RangeError('Only a verified supplier is unverified');
  await move(tx, states, key, 'unverify', change);
  return clearVerification(tx, states, key, change);
}

/** The verifier and the version they verified cleared, recorded; the supplier as it now stands. */
async function clearVerification(
  tx: SuppliersTransaction,
  states: SignedStates,
  key: SupplierKey,
  { actor, details = {} }: SupplierChange,
): Promise<SupplierRecord> {
  const read = await againForChange(tx, states, key);
  if (read.supplier.verifiedVersionId === null && read.supplier.verifiedBy === null) return read.supplier;
  await states.record(
    tx,
    SUPPLIERS,
    key,
    read.state,
    { verified_by: null, verified_version_id: null },
    { actor, action: 'supplier.verification_cleared', details },
  );
  return { ...read.supplier, verifiedBy: null, verifiedVersionId: null };
}

/**
 * Lets a suspended supplier off its brake, in the caller's transaction,
 * which read it with `change` (`found`): back VERIFIED only while it is still
 * verified (stillVerified), otherwise UNVERIFIED with anything once verified
 * cleared. One not SUSPENDED is refused (RangeError) before any SQL runs.
 * Gives the supplier as it now stands.
 */
export async function reactivateSupplier(
  tx: SuppliersTransaction,
  states: SignedStates,
  key: SupplierKey,
  found: { readonly supplier: SupplierRecord },
  change: SupplierChange,
): Promise<SupplierRecord> {
  if (found.supplier.status !== 'SUSPENDED') throw new RangeError('Only a suspended supplier is reactivated');
  const event = reactivationOf(found.supplier);
  await move(tx, states, key, event, change);
  if (event === 'reactivate_verified') return (await againForChange(tx, states, key)).supplier;
  return clearVerification(tx, states, key, change);
}

/** A version of a supplier's details, as its signed state says: never its contacts, which contactsOf opens. */
export interface VersionRecord {
  readonly id: string;
  readonly supplierId: string;
  readonly version: number;
  readonly displayName: string;
  /** Which contacts it holds: `phone`, then `email` and `licence` when given. */
  readonly contacts: string;
  /** Since when its phone is the supplier's: carried over from version to version while it is the same. */
  readonly phoneSince: Date;
  readonly source: { readonly kind: SourceKind; readonly ref: string };
  /** The membership of the member who entered it, and when. */
  readonly enteredBy: string;
  readonly enteredAt: Date;
  /** The beneficiary registration that gave its payee reference, the reference and the partner's masked hint (E2), or null. */
  readonly registrationId: string | null;
  readonly beneficiaryRef: string | null;
  readonly payeeHint: string | null;
}

/** A version read by its ID and verified, of the supplier asked about; missing; or tampered with. */
export type VersionCheck =
  | { readonly outcome: 'found'; readonly version: VersionRecord }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The version's record from its verified fields, or undefined when one isn't of its kind. */
function versionRecordOf(id: string, fields: ReadonlyMap<string, string | null>): VersionRecord | undefined {
  const supplierId = fields.get('supplier_id');
  const version = wholeOf(fields.get('version'));
  const displayName = fields.get('display_name');
  const contacts = fields.get('contacts');
  const phoneSince = timeOf(fields.get('phone_since'));
  const sourceKind = oneOf(SOURCE_KINDS, fields.get('source_kind'));
  const sourceRef = fields.get('source_ref');
  const enteredBy = fields.get('entered_by');
  const enteredAt = timeOf(fields.get('entered_at'));
  const registrationId = fields.get('registration_id');
  const beneficiaryRef = fields.get('beneficiary_ref');
  const payeeHint = fields.get('payee_hint');
  if (
    typeof supplierId !== 'string' ||
    typeof version !== 'number' ||
    typeof displayName !== 'string' ||
    typeof contacts !== 'string' ||
    !(phoneSince instanceof Date) ||
    sourceKind === undefined ||
    typeof sourceRef !== 'string' ||
    typeof enteredBy !== 'string' ||
    !(enteredAt instanceof Date) ||
    registrationId === undefined ||
    beneficiaryRef === undefined ||
    payeeHint === undefined
  ) {
    return undefined;
  }
  return {
    id,
    supplierId,
    version,
    displayName,
    contacts,
    phoneSince,
    source: { kind: sourceKind, ref: sourceRef },
    enteredBy,
    enteredAt,
    registrationId,
    beneficiaryRef,
    payeeHint,
  };
}

/**
 * The version, by its ID, read (`share`) and verified in the caller's
 * transaction, which must be withSignedStates' for its organisation: found
 * only as a version of `supplierId`, so a version of another supplier is
 * none of this one's. Tampered with, the alarm is raised and the
 * organisation held; anything but `found` grants nothing. Taken after its
 * supplier, as the lock order has it.
 */
export async function versionOf(
  tx: SuppliersTransaction,
  states: SignedStates,
  key: SupplierKey,
  supplierId: string,
): Promise<VersionCheck> {
  const state = await states.verifiedState(tx, SUPPLIER_VERSIONS, key, 'share');
  if (state.outcome !== 'verified') return state;
  const version = versionRecordOf(key.id.toLowerCase(), state.fields);
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (version === undefined) {
    throw new Error(`A verified supplier version holds a field that isn't one of its own: ${key.id}`);
  }
  if (version.supplierId !== supplierId.toLowerCase()) return { outcome: 'missing' };
  return { outcome: 'found', version };
}

/** A version's contacts won't open: changed past the app, or a key this process doesn't hold. Never names them. */
export class SupplierContactsUnreadable extends Error {
  constructor(versionId: string, options?: ErrorOptions) {
    super(`A supplier version's contacts won't open: ${versionId}`, options);
    this.name = 'SupplierContactsUnreadable';
  }
}

/**
 * The version's contacts, decrypted, from a version the caller read through
 * its signed state (versionOf) in this transaction. A contact its sealed
 * `contacts` says it holds but the row has lost, or one that won't open,
 * throws SupplierContactsUnreadable. (One planted where it says none needs
 * no check of its own: nothing was ever encrypted for that version and kind,
 * so it doesn't open.)
 */
export async function contactsOf(
  tx: SuppliersTransaction,
  keys: KeyProvider,
  orgId: string,
  version: VersionRecord,
): Promise<SupplierContacts> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the encrypted contacts, no authority field: each opens only with its own row's IDs and kind, and the caller read the row through its signed state first
    .selectFrom(SUPPLIER_VERSIONS.table)
    .select(['phone_ciphertext', 'email_ciphertext', 'licence_ciphertext', 'contacts_key_version'])
    .where('org_id', '=', orgId)
    .where('id', '=', version.id)
    .executeTakeFirstOrThrow();
  const key = { orgId, versionId: version.id };
  const held = new Set(version.contacts.split(' '));
  const open = (kind: ContactKind, ciphertext: Buffer | null): string | null => {
    if (ciphertext === null) {
      if (held.has(kind)) throw new SupplierContactsUnreadable(version.id);
      return null;
    }
    try {
      return keys
        .decrypt(
          'field-encryption',
          { keyVersion: row.contacts_key_version, ciphertext },
          contactAssociatedData(key, kind),
        )
        .toString('utf8');
    } catch (error) {
      if (error instanceof KeyError) throw new SupplierContactsUnreadable(version.id, { cause: error });
      throw error;
    }
  };
  const phone = open('phone', row.phone_ciphertext);
  if (phone === null) throw new SupplierContactsUnreadable(version.id);
  return {
    phone,
    email: open('email', row.email_ciphertext),
    tradeLicence: open('licence', row.licence_ciphertext),
  };
}

/** A supplier as a list shows it: its signed state, with its current version's name. */
export interface SupplierShown extends SupplierRecord {
  readonly displayName: string;
}

/** The most suppliers a page gives. */
export const MOST_SUPPLIERS_A_PAGE = 50;

/** The lowest uuid: every supplier's ID is after it. */
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

/**
 * A page of the organisation's suppliers, in order of ID, each read (`share`)
 * and verified with its current version, in the caller's transaction, which
 * must be withSignedStates' for it: at most `limit` (1 to
 * MOST_SUPPLIERS_A_PAGE) after the supplier `after`, with the ID to ask the
 * next page after, or null at the end; or tampered with, at the first
 * supplier or version that is, and then no page at all. Besides each row's
 * own read, one statement a page: its IDs.
 */
export async function suppliersPage(
  tx: SuppliersTransaction,
  states: SignedStates,
  orgId: string,
  { after, limit }: { readonly after: string | null; readonly limit: number },
): Promise<
  | { readonly outcome: 'listed'; readonly suppliers: readonly SupplierShown[]; readonly next: string | null }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  if (!Number.isInteger(limit) || limit < 1 || limit > MOST_SUPPLIERS_A_PAGE) {
    throw new RangeError(`A page is 1 to ${String(MOST_SUPPLIERS_A_PAGE)} suppliers`);
  }
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look alone; each supplier is then read through its signed state
    .selectFrom(SUPPLIERS.table)
    .select('id')
    .where('org_id', '=', orgId)
    // From the start, every ID is after the nil uuid.
    .where('id', '>', after ?? NIL_UUID)
    .orderBy('id')
    .limit(limit + 1)
    .execute();
  const found: SupplierShown[] = [];
  let last: string | null = null;
  for (const { id } of rows.slice(0, limit)) {
    const read = await supplierOf(tx, states, { orgId, id }, 'share');
    if (read.outcome === 'tampered') return read;
    if (read.outcome === 'found') {
      const current = await versionOf(tx, states, { orgId, id: read.supplier.currentVersionId }, id);
      if (current.outcome === 'tampered') return current;
      // A verified supplier's current version is its own (0032's key, checked at commit): none is past the app.
      if (current.outcome === 'missing')
        throw new Error(`A verified supplier has no current version of its own: ${id}`);
      found.push({ ...read.supplier, displayName: current.version.displayName });
    }
    last = id;
  }
  // One more than the page was there: the next page starts after this one's last.
  const next = rows.length > limit ? last : null;
  return { outcome: 'listed', suppliers: found, next };
}

/** How many suppliers the organisation added after `since`: the day's budget's count (E1-2), in one statement. */
export async function suppliersAddedSince(tx: SuppliersTransaction, orgId: string, since: Date): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a budget; no supplier is decided on from it
    .selectFrom(SUPPLIERS.table)
    .select(sql<number>`pg_catalog.count(*)::int`.as('added'))
    .where('org_id', '=', orgId)
    .where('created_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.added;
}
