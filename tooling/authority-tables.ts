import { AUTHORITY_TABLES as PRODUCT_AUTHORITY_TABLES } from '../packages/core/src/authority-tables.ts';
import type { AuthorityTable } from '../packages/testing/src/index.ts';

/**
 * Every authority table: a table whose fields grant, restore or limit
 * authority (a status, a role, a limit, an expiry), which ADR-012 §2 says must
 * equal the object's latest signed event. The list is checked against the
 * schema db/migrations builds on every run
 * (tooling/checks/authority-schema.db.test.ts), and an entry for a table that
 * no longer exists fails the check, so it can't go stale.
 *
 * **The list itself is the product's** (packages/core/src/authority-tables.ts,
 * A3f-2): the running API's live schema guard reads it too, and the image
 * carries no tooling. This is the same list in the shape the checks take, its
 * `rules` as `status`. So CI, the lint rules and the guard can't drift.
 *
 * An entry is the module's own table description, imported, never a copy: the
 * signed state (@agentx/platform/db's SignedStateTable, which the module
 * passes to verifiedState and record) plus the state machine that rules its
 * status, when it has one. So the checks are made against the very facts the
 * app runs on — the same column names, the same declared types, the same
 * states and moves — and a table whose migration drifts from its module fails
 * here rather than at a status change on staging.
 *
 * Phase 1's first authority table arrives with slice B1 (organisations), in
 * the product's list. Until then both are empty: no module has one yet
 * (main's only tables are the migration ledger and the two audit chains). The
 * rules themselves are proven on broken fixtures, table by table, in
 * packages/testing/src/db/authority-checks.db.test.ts.
 */
export const AUTHORITY_TABLES: readonly AuthorityTable[] = PRODUCT_AUTHORITY_TABLES.map(({ rules, ...table }) =>
  rules === undefined ? table : { ...table, status: rules },
);
