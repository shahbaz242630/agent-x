// A mandate's end by the clock (PRD §4.1; BR-05; FX-MANDATES "expired by
// clock"; Phase 2 B4): an ACTIVE or SUSPENDED mandate whose version in force
// has reached its end moves to EXPIRED, by the API's job (mandate-expiry.ts).
//
// This finds the candidates by the rows as they read, IDs alone: the job then
// reads each through its signed state and checks its end again before moving
// it. A row changed past the app to hide from this query (an end cleared, a
// status flipped) is caught by every verified read of it, and a spend checks
// the version's end itself, so an end the job hasn't reached yet never
// authorises anything (SEC-AG-12).
import type { Transaction } from 'kysely';

import { MANDATE_VERSIONS, MANDATES } from './mandates.ts';
import type { MandatesTables } from './tables.ts';

/**
 * The IDs of the organisation's ACTIVE or SUSPENDED mandates whose version in
 * force ends at or before `now`, in order of ID, after `after` when given, at
 * most `most`: each to be read through its signed state. The job pages on
 * past the last, so mandates that stay here (tampered with, refused on every
 * read) can't fill a page and keep the others from their end.
 */
export async function mandatesPastTheirEnd(
  tx: Transaction<MandatesTables>,
  orgId: string,
  now: Date,
  most: number,
  after?: string,
): Promise<readonly string[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state by the job before it moves anything
    .selectFrom(`${MANDATES.table} as m`)
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the same: the version's end is checked again on its verified read
    .innerJoin(`${MANDATE_VERSIONS.table} as v`, (join) =>
      join.onRef('v.org_id', '=', 'm.org_id').onRef('v.id', '=', 'm.current_version_id'),
    )
    .select('m.id')
    .where('m.org_id', '=', orgId)
    .where('m.status', 'in', ['ACTIVE', 'SUSPENDED'])
    .where('v.ends_at', '<=', now)
    .where((where) => (after === undefined ? where.lit(true) : where('m.id', '>', after)))
    .orderBy('m.id')
    .limit(most)
    .execute();
  return rows.map(({ id }) => id);
}
