// What verifying a supplier reads of its versions (ADR-012 §1; E3-2a): its
// first version, whose phone came from its independent source, and every
// version entered since it was last verified, whose enterers the two-person
// rule holds the verifier apart from. Not only the current version's: one
// member entering the contacts and another the payee, the first must not
// verify the phone they entered; and not every version ever, or two members
// who have each changed a supplier once could never verify it again.
//
// When it was last verified is read from the supplier's own history in the
// log, each event believed only whole (a verification's record names the
// version verified), since a change of its details clears the verified
// version from its row. Each version is then found by its number and read
// through its signed state; numbers run on with no gap (each one past the
// highest, nextVersionNumber), so one missing was removed past the app.
import type { SignedStates, TamperSign } from '../../audit/index.ts';
import {
  SUPPLIER_VERSIONS,
  SUPPLIERS,
  type SupplierRecord,
  type SuppliersTransaction,
  versionOf,
  type VersionRecord,
} from './suppliers.ts';

/** The most versions since the last verification one read takes: past it, refused rather than decided on part. */
export const MOST_VERSIONS_TO_VERIFY = 200;
/** The most events about one supplier one read takes: past it, the read throws (TooManyEventsToRead). */
export const MOST_SUPPLIER_EVENTS = 1000;

/** The supplier's record of a verification: it names the version verified. */
const VERIFIER_RECORDED = 'supplier.verifier_recorded';

/**
 * What verifying reads: the first version and every version since the last
 * verification up to the current one, in order; `too_many` past
 * MOST_VERSIONS_TO_VERIFY; `incomplete` for a version number with no version
 * (removed past the app); or tampered with, with the alarm raised.
 */
export type VersionsToVerify =
  | { readonly outcome: 'read'; readonly first: VersionRecord; readonly since: readonly VersionRecord[] }
  | { readonly outcome: 'too_many' }
  | { readonly outcome: 'incomplete' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The number of the version the supplier was last verified on, from its
 * history, or 0 for never; or tampered with.
 */
async function lastVerifiedNumber(
  tx: SuppliersTransaction,
  states: SignedStates,
  orgId: string,
  supplierId: string,
): Promise<number | { readonly outcome: 'tampered'; readonly sign: TamperSign }> {
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [SUPPLIERS.subject],
    subjectId: supplierId,
    limit: MOST_SUPPLIER_EVENTS,
  });
  if (history.outcome === 'tampered') return history;
  const verified = history.events.findLast(({ event }) => event.action === VERIFIER_RECORDED);
  if (verified === undefined) return 0;
  // verifySupplier records the version it verified, its supplier's own (0032's key), on every verification.
  const id = String(verified.event.details.verifiedVersionId);
  const version = await versionOf(tx, states, { orgId, id }, supplierId);
  if (version.outcome === 'tampered') return version;
  return version.outcome === 'found' ? version.version.version : { outcome: 'tampered', sign: 'deleted' };
}

/**
 * The supplier's first version and every version since it was last verified,
 * up to `current` (or `current` alone, when none is newer than the verified one) (its current version, read by the caller), read (`share`)
 * and verified in the caller's transaction, which must be withSignedStates'
 * for its organisation and read the supplier first, as the lock order has it.
 */
export async function versionsToVerify(
  tx: SuppliersTransaction,
  states: SignedStates,
  orgId: string,
  supplier: SupplierRecord,
  current: VersionRecord,
): Promise<VersionsToVerify> {
  const last = await lastVerifiedNumber(tx, states, orgId, supplier.id);
  if (typeof last !== 'number') return last;
  if (current.version - last > MOST_VERSIONS_TO_VERIFY) return { outcome: 'too_many' };
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, to find each version; each is read through its signed state below
    .selectFrom(SUPPLIER_VERSIONS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('supplier_id', '=', supplier.id)
    .where((where) =>
      where.or([
        where('version', '=', 1),
        where.and([where('version', '>', last), where('version', '<=', current.version)]),
      ]),
    )
    .orderBy('version')
    .limit(MOST_VERSIONS_TO_VERIFY + 2)
    .execute();
  const read: VersionRecord[] = [];
  for (const { id } of rows) {
    const version = await versionOf(tx, states, { orgId, id }, supplier.id);
    if (version.outcome === 'tampered') return version;
    if (version.outcome === 'found') read.push(version.version);
  }
  // Each number once, with no gap: the first, then every one past the last verified up to the current.
  const wanted = [...new Set([1, ...Array.from({ length: current.version - last }, (_, at) => last + 1 + at)])];
  const numbers = read.map(({ version }) => version);
  const [first] = read;
  if (first === undefined || numbers.length !== wanted.length || numbers.some((number, at) => number !== wanted[at])) {
    return { outcome: 'incomplete' };
  }
  const since = read.filter(({ version }) => version > last);
  // Nothing entered since it was last verified (a change waiting dropped): the current version's enterer still counts.
  return { outcome: 'read', first, since: since.length > 0 ? since : [current] };
}
