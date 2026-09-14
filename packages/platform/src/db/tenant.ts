// ADR-005 §2, §4: tenant data is reached only inside withTenant. Every tenant
// table has forced row-level security with one policy, which lets a query see
// or write a row only when the row's org_id equals the `app.org_id` setting:
//
//   org_id = nullif(current_setting('app.org_id', true), '')::uuid
//
// withTenant opens a transaction and sets `app.org_id` for that transaction
// only (set_config's third argument). The setting is gone at commit or
// rollback, so a pooled connection never carries it to the next caller. With
// no setting, or an empty one, the policy matches no rows: it fails closed.
// This is the only product file that names the setting (lint), and pg_catalog
// is named explicitly, so no other function called set_config can stand in.
import { type Kysely, sql, type Transaction } from 'kysely';
import type { ClientBase } from 'pg';

/** A UUID in its canonical form, which is how every organisation ID is written (ADR-007). */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class TenantContextError extends Error {
  constructor(problem: string) {
    super(`Tenant context refused: ${problem}`);
    this.name = 'TenantContextError';
  }
}

/**
 * Runs `work` in one READ COMMITTED transaction scoped to the organisation.
 * The orgId must come from the server (the authenticated principal or the
 * directory), never from the request (ADR-005 §5). It commits when `work`
 * resolves and rolls back when it throws. Transactions can't be nested: a
 * second withTenant inside `work` throws.
 */
export async function withTenant<Schema, Result>(
  db: Kysely<Schema>,
  orgId: string,
  work: (tx: Transaction<Schema>) => Promise<Result>,
): Promise<Result> {
  // Checked before the transaction opens; the ID itself is never echoed.
  if (!UUID.test(orgId)) throw new TenantContextError('the organisation ID is not a UUID');
  // READ COMMITTED is Postgres's default, but the default can be changed per
  // server, database or role; the locking rules in ADR-006 rely on it.
  return db
    .transaction()
    .setIsolationLevel('read committed')
    .execute(async (tx) => {
      await sql`select pg_catalog.set_config('app.org_id', ${orgId}, true)`.execute(tx);
      return work(tx);
    });
}

/**
 * SEC-TEN-06: a new connection must start with no tenant. One could arrive
 * with a tenant already set (by PGOPTIONS in the environment, or by ALTER ROLE
 * or ALTER DATABASE … SET), and every query outside withTenant would then see
 * that organisation's rows. The pool runs this on each new connection and
 * closes the connection if it throws.
 */
export async function refuseTenantPreset(client: ClientBase): Promise<void> {
  const { rows } = await client.query<{ org_id: string | null }>(
    "select pg_catalog.current_setting('app.org_id', true) as org_id",
  );
  const preset = rows[0]?.org_id ?? '';
  if (preset !== '') {
    throw new TenantContextError(
      'a new database connection already carries an organisation (from PGOPTIONS, or ALTER ROLE or ALTER DATABASE ... SET), so it is closed unused',
    );
  }
}
