// One detail of an object's newest event of the actions named, and whether an
// object moved otherwise than one way since another's first event (E3), as a
// query's expressions, unverified (Phase 3 C2a, C3b): a candidate's filter
// alone, never a
// decision. A caller believes what it then acts on only through the
// verified read (SignedStates.historyOf, `newest`). 0005's
// `events_by_subject` index finds the object's events newest first. The
// details are kept as canonical JSON text, read as JSON here: text that
// isn't JSON (edited past the app) fails the query, as it fails the chain.
import { type RawBuilder, sql } from 'kysely';

/**
 * The text of `key` in the details of the newest event of `actions` about the
 * object of `type` whose ID is the column `idColumn`, in the organisation
 * the column `orgColumn` names; null for none.
 */
export const newestDetail = ({
  type,
  idColumn,
  orgColumn,
  actions,
  key,
}: {
  readonly type: string;
  readonly idColumn: string;
  readonly orgColumn: string;
  readonly actions: readonly string[];
  readonly key: string;
}): RawBuilder<string | null> =>
  sql<string | null>`(select (e.details::jsonb) ->> ${key}::text from audit.events e
    where e.org_id = ${sql.ref(orgColumn)} and e.subject_type = ${type} and e.subject_id = ${sql.ref(idColumn)}
      and e.action = any(${actions}::text[])
    order by e.seq desc limit 1)`;

/**
 * Whether, of the events of `actions` about the object of `type` whose ID is
 * the column `idColumn`, recorded after the first event about the object of
 * `since.type` whose ID is the column `since.idColumn`, in the organisation
 * the column `orgColumn` names, any is other than `only` (its action with
 * `key` at `value`; a detail missing is other), or more than `most` are:
 * false when none was recorded since.
 */
export const movedOtherwiseSince = ({
  type,
  idColumn,
  orgColumn,
  actions,
  since,
  only,
  most,
}: {
  readonly type: string;
  readonly idColumn: string;
  readonly orgColumn: string;
  readonly actions: readonly string[];
  readonly since: { readonly type: string; readonly idColumn: string };
  readonly only: { readonly action: string; readonly key: string; readonly value: string };
  readonly most: number;
}): RawBuilder<boolean> =>
  sql<boolean>`(select pg_catalog.count(*) filter (where e.action <> ${only.action}
        or ((e.details::jsonb) ->> ${only.key}::text) is distinct from ${only.value}) > 0
      or pg_catalog.count(*) > ${most}
    from audit.events e
    where e.org_id = ${sql.ref(orgColumn)} and e.subject_type = ${type} and e.subject_id = ${sql.ref(idColumn)}
      and e.action = any(${actions}::text[])
      and e.seq > (select pg_catalog.min(f.seq) from audit.events f
        where f.org_id = ${sql.ref(orgColumn)} and f.subject_type = ${since.type}
          and f.subject_id = ${sql.ref(since.idColumn)}))`;
