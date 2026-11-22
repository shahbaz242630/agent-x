// The organisation's row (0008): an authority table (ADR-012 §2), so its
// status must equal the organisation's latest signed event, and every read a
// decision rests on goes through the audit module's verifiedState with the
// description below. The description is on the product's authority-table
// list (packages/core/src/authority-tables.ts), which CI, the lint rules and
// the live schema guard all read.
//
// An organisation is created in one transaction, withSignedStates' for its own
// ID: its directory entry first (the row points at it), then its row, then its
// first signed state, which starts the organisation's audit chain, then its
// integrity hold, CLEAR (the audit module's; it has no row, so nothing done to
// this one can keep it from being set).
//
// The insert is the one query on this table outside the audit module's
// steps, so the lint rule that refuses any other is switched off for that line
// alone, with its reason. An insert on its own is safe: a row that record
// hasn't signed is `unsigned`, which verifiedState denies with the alarm, so
// it can't grant anything; and record refuses a row that isn't new, or one
// the log already holds a state for. It must stay a plain insert: an upsert
// (ON CONFLICT DO UPDATE) would change a row past the signed state.
import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type { AuditActor, AuditTables, RecordedState, SignedStates } from '../../audit/index.ts';
import { type DirectoryTables, registerOrganization } from '../../directory/index.ts';
import { ORGANIZATION, organizationName } from '../domain/organization.ts';
import type { OrganizationsTables } from './tables.ts';

/** The organisation's row, as the signed state reads, records and moves it. */
export const ORGANIZATIONS = {
  table: 'organizations.organizations',
  subject: 'organization',
  fields: [{ column: 'status', type: 'text' }],
  rules: ORGANIZATION,
  // The actions a request's authority reads from its history (state-trail.ts, TR-3 residual 75): CANCEL_BRAKES,
  // PAUSE_EVENTS and the rest in apps/api, held to these by its tracked-actions test.
  // And where it was named whole (state-names.ts): its states from before carry names, or the naming missed them.
  tracks: ['organization.freeze', 'organization.unfreeze', 'organization.history_named'],
} as const satisfies SignedStateTable & { readonly rules: typeof ORGANIZATION };

/** A transaction on the tables an organisation is created in, opened by withTenant for it. */
export type OrganizationsTransaction = Transaction<OrganizationsTables & DirectoryTables & AuditTables>;

export interface NewOrganization {
  /** Its ID, made by the server, never by a caller: the transaction is withTenant's for it. */
  readonly id: string;
  /** Stored composed (NFC), as organizationName gives it back. */
  readonly name: string;
  /** Who is creating it. */
  readonly actor: AuditActor;
}

/**
 * Creates the organisation, ACTIVE and with its integrity hold CLEAR, in the
 * caller's transaction, which must be withSignedStates' for its ID; `states`
 * are that transaction's. A name it can't have is refused before any SQL runs
 * (`OrganizationRefused`); an organisation that exists already is refused by
 * the directory's key.
 */
export async function createOrganization(
  tx: OrganizationsTransaction,
  states: SignedStates,
  { id, name, actor }: NewOrganization,
): Promise<RecordedState> {
  const kept = organizationName(name);
  await registerOrganization(tx, id);
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(ORGANIZATIONS.table)
    .values({ org_id: id, id, name: kept, status: ORGANIZATION.initial })
    .execute();
  const recorded = await states.record(
    tx,
    ORGANIZATIONS,
    { orgId: id, id },
    'new',
    { status: ORGANIZATION.initial },
    // Born counting its agents' months in signed totals (GM-1a), its payees' split windows in signed windows (GM-1b)
    // and its orders' claims in signed slots (TR-2): nothing held before it to open (monthTotalsCutOver,
    // payeeWindowsCutOver and orderSlotsCutOver read these details; the module map keeps it from importing them).
    {
      actor,
      action: 'organization.created',
      details: { monthTotals: 'signed', payeeWindows: 'signed', orderSlots: 'signed' },
    },
  );
  await states.startIntegrityHold(tx, id, actor);
  return recorded;
}
