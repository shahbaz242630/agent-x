// ADR-005 §2, §4: tenant data is reached only inside withTenant. Every tenant
// table has forced row-level security with one policy, which lets a query see
// or write a row only when the row's org_id equals the `app.org_id` setting:
//
//   org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid
//
// withTenant opens a transaction and sets `app.org_id` for that transaction
// only (set_config's third argument). The setting is gone at commit or
// rollback, so a pooled connection doesn't carry it to the next caller. With
// no setting, or an empty one, the policy matches no rows: it fails closed.
//
// SEC-TEN-06: a setting made for the whole session (by a bug or injected SQL
// inside the work, or before a connection was opened) would outlive the
// transaction. So every connection is checked when it is opened, and again
// each time it is taken from the pool. This is the only product file that
// names the setting (lint), and pg_catalog is named explicitly, so no other
// function called set_config can stand in.
import { AsyncLocalStorage } from 'node:async_hooks';

import { type Kysely, type PostgresPool, sql, type Transaction } from 'kysely';
import type pg from 'pg';

import type { Logger } from '../observability/index.ts';

/** A UUID in its canonical form, which is how every organisation ID is written (ADR-007). */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class TenantContextError extends Error {
  constructor(problem: string) {
    super(`Tenant context refused: ${problem}`);
    this.name = 'TenantContextError';
  }
}

/** Set while withTenant's work runs, to refuse a second withTenant inside it. */
const insideTenant = new AsyncLocalStorage<true>();

/**
 * Runs `work` in one READ COMMITTED transaction scoped to the organisation.
 * The orgId must come from the server (the authenticated principal or the
 * directory), never from the request (ADR-005 §5). It commits when `work`
 * resolves and rolls back when it throws. It can't be nested: a second
 * withTenant inside `work` would open another transaction on another
 * connection, committed separately, and under load every connection could
 * end up waiting on another.
 */
export async function withTenant<Schema, Result>(
  db: Kysely<Schema>,
  orgId: string,
  work: (tx: Transaction<Schema>) => Promise<Result>,
): Promise<Result> {
  // Checked before the transaction opens; the ID itself is never echoed.
  if (!UUID.test(orgId)) throw new TenantContextError('the organisation ID is not a UUID');
  if (insideTenant.getStore() === true) {
    throw new TenantContextError('withTenant was called inside another withTenant; pass the transaction on instead');
  }
  // READ COMMITTED is Postgres's default, but the default can be changed per
  // server, database or role; the locking rules in ADR-006 rely on it.
  return insideTenant.run(true, () =>
    db
      .transaction()
      .setIsolationLevel('read committed')
      .execute(async (tx) => {
        await sql`select pg_catalog.set_config('app.org_id', ${orgId}, true)`.execute(tx);
        return work(tx);
      }),
  );
}

/** The tenant the connection carries: its `app.org_id` setting, or '' for none. */
async function tenantOn(client: pg.ClientBase): Promise<string> {
  const { rows } = await client.query<{ org_id: string | null }>(
    "select pg_catalog.current_setting('app.org_id', true) as org_id",
  );
  return rows[0]?.org_id ?? '';
}

/**
 * A new connection must start with no tenant. One could arrive with a tenant
 * already set, by PGOPTIONS in the environment or by ALTER ROLE or ALTER
 * DATABASE … SET, which points at tampering or a bad setting. The pool runs
 * this on each new connection and closes the connection if it throws.
 */
export async function refuseTenantPreset(client: pg.ClientBase): Promise<void> {
  if ((await tenantOn(client)) !== '') {
    throw new TenantContextError(
      'a new database connection already carries an organisation (from PGOPTIONS, or ALTER ROLE or ALTER DATABASE ... SET), so it is closed unused',
    );
  }
}

/**
 * Wraps the pool so that every connection taken from it carries no tenant. A
 * connection that still does was given a session-wide tenant by an earlier
 * caller, which is a bug or an attack: it is closed (so any other session
 * settings go with it), the event is logged, and another connection is taken.
 * New connections are checked on opening, so after at most `attempts` tries
 * one is clean, or the pool is failing and the error says so.
 */
export function tenantCheckedPool(pool: pg.Pool, logger: Logger, attempts: number): PostgresPool {
  return {
    options: pool.options,
    end: () => pool.end(),
    connect: async () => {
      for (let attempt = 1; attempt <= attempts; attempt += 1) {
        const client = await pool.connect();
        let tenant: string;
        try {
          tenant = await tenantOn(client);
        } catch (error) {
          client.release(error instanceof Error ? error : true);
          throw error;
        }
        if (tenant === '') return client;
        client.release(true);
        logger.error('db.tenant.leftover_discarded', { attempt });
      }
      throw new TenantContextError(`no connection without a leftover tenant after ${String(attempts)} tries`);
    },
  };
}
