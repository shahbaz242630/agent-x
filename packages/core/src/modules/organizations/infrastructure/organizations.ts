// The organisation's row (0008): an authority table (ADR-012 §2), so its
// status must equal the organisation's latest signed event, and every read a
// decision rests on goes through the audit module's verifiedState with the
// description below. The description is on the product's authority-table
// list (packages/core/src/authority-tables.ts), which CI, the lint rules and
// the live schema guard all read.
//
// An organisation is created in one transaction, withTenant's for its own ID:
// its directory entry first (the row points at it), then its row, then its
// first signed state, which starts the organisation's audit chain. The row is
// inserted through its description because the lint rule refuses the table's
// name in a query. That is safe for an insert on its own: a row that record
// hasn't signed is `unsigned`, which verifiedState denies with the alarm, so
// an insert can't grant anything; and record refuses a row that isn't new, or
// one the log already holds a state for.
import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type { AuditActor, AuditTables, RecordedState, SignedStates } from '../../audit/index.ts';
import { type DirectoryTables, registerOrganization } from '../../directory/index.ts';
import { checkName, ORGANIZATION } from '../domain/organization.ts';
import type { OrganizationsTables } from './tables.ts';

/** The organisation's row, as the signed state reads, records and moves it. */
export const ORGANIZATIONS = {
  table: 'organizations.organizations',
  subject: 'organization',
  fields: [{ column: 'status', type: 'text' }],
  rules: ORGANIZATION,
} as const satisfies SignedStateTable & { readonly rules: typeof ORGANIZATION };

/** A transaction on the tables an organisation is created in, opened by withTenant for it. */
export type OrganizationsTransaction = Transaction<OrganizationsTables & DirectoryTables & AuditTables>;

export interface NewOrganization {
  /** Its ID, made by the server, never by a caller: the transaction is withTenant's for it. */
  readonly id: string;
  readonly name: string;
  /** Who is creating it. */
  readonly actor: AuditActor;
}

/**
 * Creates the organisation, ACTIVE, in the caller's transaction, which must
 * be withTenant's for its ID; `states` is that transaction's signed states. A
 * name it can't have is refused before any SQL runs (`OrganizationRefused`);
 * an organisation that exists already is refused by the directory's key.
 */
export async function createOrganization(
  tx: OrganizationsTransaction,
  states: SignedStates,
  { id, name, actor }: NewOrganization,
): Promise<RecordedState> {
  checkName(name);
  await registerOrganization(tx, id);
  await tx.insertInto(ORGANIZATIONS.table).values({ org_id: id, id, name, status: ORGANIZATION.initial }).execute();
  return states.record(
    tx,
    ORGANIZATIONS,
    { orgId: id, id },
    'new',
    { status: ORGANIZATION.initial },
    { actor, action: 'organization.created', details: {} },
  );
}
