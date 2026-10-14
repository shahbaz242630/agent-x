// One detail of an object's newest event of one action, as a query's
// expression, unverified (Phase 3 C2a): a candidate's filter alone, never a
// decision. A caller believes what it then acts on only through the
// verified read (SignedStates.historyOf, `newest`). 0005's
// `events_by_subject` index finds the object's events newest first. The
// details are kept as canonical JSON text, read as JSON here: text that
// isn't JSON (edited past the app) fails the query, as it fails the chain.
import { type RawBuilder, sql } from 'kysely';

/**
 * The text of `key` in the details of the newest `action` event about the
 * object of `type` whose ID is the column `idColumn`, in the organisation
 * the column `orgColumn` names; null for none.
 */
export const newestDetail = ({
  type,
  idColumn,
  orgColumn,
  action,
  key,
}: {
  readonly type: string;
  readonly idColumn: string;
  readonly orgColumn: string;
  readonly action: string;
  readonly key: string;
}): RawBuilder<string | null> =>
  sql<string | null>`(select (e.details::jsonb) ->> ${key}::text from audit.events e
    where e.org_id = ${sql.ref(orgColumn)} and e.subject_type = ${type} and e.subject_id = ${sql.ref(idColumn)}
      and e.action = ${action}
    order by e.seq desc limit 1)`;
