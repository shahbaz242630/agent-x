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
 * names, and searches it *first* — ahead of pg_catalog. Our casts to `text`,
 * `uuid`, `timestamptz` and `bigint` in signed-rows.ts are type-name lookups,
 * so a temporary type could otherwise change the canonical text a state seal is
 * built from, while `current_setting('search_path')` still read as expected.
 * Naming it last puts it after pg_catalog instead. The app role can't make a
 * temporary object anyway (`db/bootstrap/database.sql` revokes TEMPORARY from
 * PUBLIC and grants it only CONNECT, proven in tenant.db.test.ts), so this is
 * the second of two barriers, not the only one.
 */
export const PINNED_SEARCH_PATH_VALUE = 'pg_catalog,pg_temp';

/** The startup-packet option that sets it, which beats a `search_path` set on the database or the role. */
export const PINNED_SEARCH_PATH = `-c search_path=${PINNED_SEARCH_PATH_VALUE}`;
