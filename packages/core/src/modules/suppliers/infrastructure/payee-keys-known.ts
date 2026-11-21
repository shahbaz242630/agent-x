// The payee keys the organisation's signed supplier records say (TR-2 review, R-15): for the order slots' cutover,
// which takes no payee key from a claim row on trust. A supplier's payee key only ever moves with the version that
// pays it (confirmPayeeChange: the version made current and its registration's key, in one signed state), so the
// key a request was decided under is its sealed supplier version's registration's key, or none for a version with no
// registration. Every row read through its signed state, FOR SHARE, a page at a time, listed from the rows and the
// log; all at level 6 (ADR-006 §6), so the cutover reads them before its requests.
import type { SignedStateTable } from '@agentx/platform/db';

import type { SignedStates } from '../../audit/index.ts';
import { BENEFICIARY_REGISTRATIONS } from './registrations.ts';
import { SUPPLIER_VERSIONS, SUPPLIERS, type SuppliersTransaction } from './suppliers.ts';

/** How many rows one statement reads: verifiedStates' most. */
const ROWS_A_READ = 500;

/** The keys each signed record says, by ID in lower case; null for none. */
export interface PayeeKeysKnown {
  /** Each supplier's payee key now. */
  readonly now: ReadonlyMap<string, string | null>;
  /**
   * The payee key each supplier version paid: its registration's, or none for a version with no registration. A version
   * whose registration isn't found is left out: no signed record says its key.
   */
  readonly byVersion: ReadonlyMap<string, string | null>;
}

/**
 * Every row of `table` in the organisation, verified, each field `pick` names by ID in lower case; `tampered` where one
 * can't be believed (its read raised the alarm).
 */
async function everyField(
  tx: SuppliersTransaction,
  states: SignedStates,
  orgId: string,
  table: SignedStateTable,
  pick: string,
): Promise<Map<string, string | null> | 'tampered'> {
  const found = new Map<string, string | null>();
  let after: string | null = null;
  do {
    const listed: { readonly ids: readonly string[]; readonly next: string | null } = await states.objectIds(
      tx,
      orgId,
      table,
      after,
      ROWS_A_READ,
    );
    const checks = listed.ids.length === 0 ? [] : await states.verifiedStates(tx, table, orgId, listed.ids);
    for (const [id, check] of checks) {
      if (check.outcome !== 'verified') return 'tampered';
      found.set(id.toLowerCase(), check.fields.get(pick) ?? null);
    }
    after = listed.next;
  } while (after !== null);
  return found;
}

/** The organisation's payee keys by its signed suppliers, versions and registrations; `tampered` for any not believed. */
export async function payeeKeysKnown(
  tx: SuppliersTransaction,
  states: SignedStates,
  orgId: string,
): Promise<PayeeKeysKnown | 'tampered'> {
  const now = await everyField(tx, states, orgId, SUPPLIERS, 'payee_key');
  // In the registry's order (authority-tables.ts): suppliers, their registrations, then their versions.
  const registered = await everyField(tx, states, orgId, BENEFICIARY_REGISTRATIONS, 'payee_key');
  const registrationOf = await everyField(tx, states, orgId, SUPPLIER_VERSIONS, 'registration_id');
  if (now === 'tampered' || registrationOf === 'tampered' || registered === 'tampered') return 'tampered';
  const byVersion = new Map<string, string | null>();
  for (const [versionId, registrationId] of registrationOf) {
    if (registrationId === null) byVersion.set(versionId, null);
    else if (registered.has(registrationId.toLowerCase())) {
      byVersion.set(versionId, registered.get(registrationId.toLowerCase()) ?? null);
    }
  }
  return { now, byVersion };
}
