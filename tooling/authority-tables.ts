import type { AuthorityTable } from '../packages/testing/src/index.ts';

/**
 * Every authority table: a table whose fields grant, restore or limit
 * authority (a status, a role, a limit, an expiry), which ADR-012 §2 says must
 * equal the object's latest signed event. The list is checked against the
 * schema db/migrations builds on every run
 * (tooling/checks/authority-schema.db.test.ts), and an entry for a table that
 * no longer exists fails the check, so it can't go stale.
 *
 * An entry is the module's own table description, imported, never a copy: the
 * signed state (@agentx/platform/db's SignedStateTable, which the module
 * passes to verifiedState and record) plus the state machine that rules its
 * status, when it has one. So the checks are made against the very facts the
 * app runs on — the same column names, the same declared types, the same
 * states and moves — and a table whose migration drifts from its module fails
 * here rather than at a status change on staging.
 *
 * Phase 1's first authority table arrives with slice B1 (organisations), as:
 *
 *   import { ORGANISATIONS, ORGANISATION_MACHINE } from '../packages/core/src/modules/organizations/index.ts';
 *   export const AUTHORITY_TABLES: readonly AuthorityTable[] = [
 *     { ...ORGANISATIONS, status: ORGANISATION_MACHINE },
 *   ];
 *
 * Until then it is empty: no module has one yet (main's only tables are the
 * migration ledger and the two audit chains). The rules themselves are proven
 * on broken fixtures, table by table, in
 * packages/testing/src/db/authority-checks.db.test.ts.
 */
export const AUTHORITY_TABLES: readonly AuthorityTable[] = [];
