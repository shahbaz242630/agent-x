// Suppliers and their versions (0032). Both are authority tables (ADR-012
// §2), so a supplier's status, its current and pending version, its
// cooling-off, its verifier and its payee key, and everything a version says
// (its supplier and number, its name, which contacts it holds, the
// independent source, who entered it and when, and its payee reference) must
// equal the row's latest signed event, and every read goes through the audit
// module's verifiedState with the descriptions below. Both are on the
// product's authority-table list (packages/core/src/authority-tables.ts), at
// the supplier's level in the lock order (ADR-006 §6: 6), the supplier before
// its versions.
//
// A supplier is added in one transaction, withSignedStates' for its
// organisation, with its first version: both rows, then the supplier's first
// signed state, then the version's. The inserts are the only queries on
// these tables outside the audit module's steps but for reading a version's
// encrypted contacts and the rows' IDs and creation times, as for an agent's
// row (agents.ts says why a plain insert is safe). The seals are MACs, so no
// name or contact is ever put in an event.
//
// A version's contacts are encrypted with the organisation, the supplier,
// the version and the contact's kind as associated data (ADR-011 §2), and
// opened only from a version the caller read through its signed state.
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
    { column: 'payee_key', type: 'text' },
    { column: 'payee_key_version', type: 'integer' },
  ],
  rules: SUPPLIER,
} as const satisfies SignedStateTable & { readonly rules: typeof SUPPLIER };

/** A supplier version's row, as the signed state reads and records it: made once, never moved. */
export const SUPPLIER_VERSIONS = {
  table: 'suppliers.supplier_versions',
  subject: 'supplier_version',
  fields: [
    { column: 'supplier_id', type: 'uuid' },
    { column: 'version', type: 'integer' },
    { column: 'display_name', type: 'text' },
    { column: 'contacts', type: 'text' },
    { column: 'source_kind', type: 'text' },
    { column: 'source_ref', type: 'text' },
    { column: 'entered_by', type: 'uuid' },
    { column: 'entered_at', type: 'timestamptz' },
    { column: 'registration_id', type: 'uuid' },
    { column: 'beneficiary_ref', type: 'text' },
    { column: 'payee_hint', type: 'text' },
  ],
} as const satisfies SignedStateTable;

/** A transaction on the tables suppliers are added and read in, opened by withSignedStates for their organisation. */
export type SuppliersTransaction = Transaction<SuppliersTables & AuditTables>;

/** The kinds of contact a version keeps encrypted, each in a column of its own (`<kind>_ciphertext`). */
type ContactKind = 'phone' | 'email' | 'licence';

/** A contact's associated data: the row and the kind it belongs to, so it opens nowhere else. */
const contactAssociatedData = (
  key: { readonly orgId: string; readonly supplierId: string; readonly versionId: string },
  kind: ContactKind,
) =>
  [
    `suppliers.supplier_versions.${kind}`,
    key.orgId.toLowerCase(),
    key.supplierId.toLowerCase(),
    key.versionId.toLowerCase(),
  ] as const;

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
  { orgId, id, versionId, supplier: given, enteredBy, createdAt, actor, details = {} }: NewSupplier,
): Promise<{ readonly supplier: RecordedState; readonly version: RecordedState }> {
  const kept = supplierDetails(given);
  const supplierFields = {
    status: SUPPLIER.initial,
    current_version_id: versionId,
    pending_version_id: null,
    cooling_off_until: null,
    verified_by: null,
    payee_key: null,
    payee_key_version: null,
  };
  const versionFields = {
    supplier_id: id,
    version: 1,
    display_name: kept.displayName,
    contacts: contactsHeld(kept.contacts),
    source_kind: kept.source.kind,
    source_ref: kept.source.ref,
    entered_by: enteredBy,
    entered_at: createdAt,
    registration_id: null,
    beneficiary_ref: null,
    payee_hint: null,
  };
  const sealed = sealContacts(keys, { orgId, supplierId: id, versionId }, kept.contacts);
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(SUPPLIERS.table)
    .values({ org_id: orgId, id, ...supplierFields, created_at: createdAt })
    .execute();
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(SUPPLIER_VERSIONS.table)
    .values({ org_id: orgId, id: versionId, ...versionFields, ...sealed })
    .execute();
  const supplier = await states.record(tx, SUPPLIERS, { orgId, id }, 'new', supplierFields, {
    actor,
    action: 'supplier.added',
    details: { ...details, versionId },
  });
  const version = await states.record(tx, SUPPLIER_VERSIONS, { orgId, id: versionId }, 'new', versionFields, {
    actor,
    action: 'supplier_version.made',
    details: { ...details, supplierId: id, version: 1, contacts: versionFields.contacts, sourceKind: kept.source.kind },
  });
  return { supplier, version };
}

/** Each contact given, encrypted for its own row and kind, with the key's version. */
function sealContacts(
  keys: KeyProvider,
  key: { readonly orgId: string; readonly supplierId: string; readonly versionId: string },
  contacts: SupplierContacts,
) {
  const seal = (kind: ContactKind, value: string | null): Buffer | null =>
    value === null
      ? null
      : keys.encrypt('field-encryption', Buffer.from(value, 'utf8'), contactAssociatedData(key, kind)).ciphertext;
  const phone = keys.encrypt(
    'field-encryption',
    Buffer.from(contacts.phone, 'utf8'),
    contactAssociatedData(key, 'phone'),
  );
  return {
    phone_ciphertext: phone.ciphertext,
    email_ciphertext: seal('email', contacts.email),
    licence_ciphertext: seal('licence', contacts.tradeLicence),
    contacts_key_version: phone.keyVersion,
  };
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
  /** The verifier's membership, or null. */
  readonly verifiedBy: string | null;
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

/** A field as it is kept: text, or null; undefined for one the fields don't hold at all. */
const fieldOf = (fields: ReadonlyMap<string, string | null>, column: string): string | null | undefined =>
  fields.get(column);

const timeOf = (value: string | null | undefined): Date | null | undefined => {
  if (value === null || value === undefined) return value;
  const time = new Date(value);
  return Number.isNaN(time.getTime()) ? undefined : time;
};

const wholeOf = (value: string | null | undefined): number | null | undefined => {
  if (value === null || value === undefined) return value;
  return WHOLE.test(value) ? Number(value) : undefined;
};

/** The supplier's record from its verified fields, or undefined when one isn't of its kind. */
function supplierRecordOf(id: string, fields: ReadonlyMap<string, string | null>): SupplierRecord | undefined {
  const status = oneOf(SUPPLIER.states, fieldOf(fields, 'status'));
  const currentVersionId = fieldOf(fields, 'current_version_id');
  const pendingVersionId = fieldOf(fields, 'pending_version_id');
  const coolingOffUntil = timeOf(fieldOf(fields, 'cooling_off_until'));
  const verifiedBy = fieldOf(fields, 'verified_by');
  const payeeKey = fieldOf(fields, 'payee_key');
  const payeeKeyVersion = wholeOf(fieldOf(fields, 'payee_key_version'));
  if (
    status === undefined ||
    typeof currentVersionId !== 'string' ||
    pendingVersionId === undefined ||
    coolingOffUntil === undefined ||
    verifiedBy === undefined ||
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
  key: { readonly orgId: string; readonly id: string },
  lock: 'share' | 'change',
): Promise<SupplierCheck> {
  const state = await states.verifiedState(tx, SUPPLIERS, key, lock);
  if (state.outcome !== 'verified') return state;
  const supplier = supplierRecordOf(key.id.toLowerCase(), state.fields);
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (supplier === undefined) throw new Error(`A verified supplier holds a field that isn't one of its own: ${key.id}`);
  return { outcome: 'found', supplier, state };
}

/** A version of a supplier's details, as its signed state says: never its contacts, which contactsOf opens. */
export interface VersionRecord {
  readonly id: string;
  readonly supplierId: string;
  readonly version: number;
  readonly displayName: string;
  /** Which contacts it holds: `phone`, then `email` and `licence` when given. */
  readonly contacts: string;
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
  const supplierId = fieldOf(fields, 'supplier_id');
  const version = wholeOf(fieldOf(fields, 'version'));
  const displayName = fieldOf(fields, 'display_name');
  const contacts = fieldOf(fields, 'contacts');
  const sourceKind = oneOf(SOURCE_KINDS, fieldOf(fields, 'source_kind'));
  const sourceRef = fieldOf(fields, 'source_ref');
  const enteredBy = fieldOf(fields, 'entered_by');
  const enteredAt = timeOf(fieldOf(fields, 'entered_at'));
  const registrationId = fieldOf(fields, 'registration_id');
  const beneficiaryRef = fieldOf(fields, 'beneficiary_ref');
  const payeeHint = fieldOf(fields, 'payee_hint');
  if (
    typeof supplierId !== 'string' ||
    typeof version !== 'number' ||
    typeof displayName !== 'string' ||
    typeof contacts !== 'string' ||
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
  key: { readonly orgId: string; readonly id: string },
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
 * its signed state (versionOf) in this transaction: each contact its sealed
 * `contacts` says it holds, and only those. One that won't open, or a
 * contact the row holds past what it says, throws SupplierContactsUnreadable.
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
  const key = { orgId, supplierId: version.supplierId, versionId: version.id };
  const held = new Set(version.contacts.split(' '));
  const open = (kind: ContactKind, ciphertext: Buffer | null): string | null => {
    if (ciphertext === null) {
      if (held.has(kind)) throw new SupplierContactsUnreadable(version.id);
      return null;
    }
    if (!held.has(kind)) throw new SupplierContactsUnreadable(version.id);
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
