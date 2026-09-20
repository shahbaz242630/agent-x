// The one search path every connection of ours runs with (A3e), in one place
// because two parts need it and they must never drift: database.ts sets it in
// the startup packet, and tenant.ts checks that a connection still carries it.
//
// They are derived from a single literal rather than written twice. A second
// hand-kept copy would be worse than no check at all: strengthening the pin
// while forgetting the other copy would make every connection fail the check,
// and `tenantCheckedPool` would then refuse every query — an outage that no
// unit test would show, since those report the value rather than read it from
// a server.
//
// This file imports nothing: database.ts already imports tenant.ts, so the
// constants can't live in either without making a cycle.

/**
 * `pg_catalog` first, so an unqualified name finds one of Postgres's own and a
 * planted function or operator can't stand in for it (the CVE-2018-1058
 * pattern), and it is the schema an unqualified CREATE would go to — which no
 * role of ours may write, so such a statement fails loudly rather than landing
 * somewhere unintended.
 *
 * **`pg_temp` is named, and named last, on purpose.** When it is left out,
 * Postgres still searches the session's temporary schema for relation and type
 * names, and searches it *first* — ahead of pg_catalog (`recomputeNamespacePath`
 * puts the temporary schema in front; the documentation says so too). It is
 * never searched for function or operator names. Our casts to `text`, `uuid`,
 * `timestamptz` and `oid` in signed-rows.ts are type-name lookups written as
 * plain identifiers, so a temporary type could otherwise change the canonical
 * text a state seal is built from, while `current_setting('search_path')` still
 * read as expected. (`::bigint` is safe whatever the path: the grammar turns
 * that keyword into `pg_catalog.int8` before any lookup happens.) Naming
 * `pg_temp` last puts it after pg_catalog instead, and leaves the creation
 * namespace as pg_catalog, so an unqualified CREATE still fails.
 *
 * It is not the only thing standing in the way: the app role can't make a
 * temporary object at all (`db/bootstrap/database.sql` revokes TEMPORARY from
 * PUBLIC and grants it only CONNECT, proven in tenant.db.test.ts). Neither
 * guard is relied on alone.
 */
export const PINNED_SEARCH_PATH_VALUE = 'pg_catalog,pg_temp';

/** The startup-packet option that sets it, which beats a `search_path` set on the database or the role. */
export const PINNED_SEARCH_PATH = `-c search_path=${PINNED_SEARCH_PATH_VALUE}`;
