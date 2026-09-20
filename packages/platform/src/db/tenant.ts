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
import { PINNED_SEARCH_PATH_VALUE } from './search-path.ts';

/** A UUID in its canonical form, which is how every organisation ID is written (ADR-007). */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The tenant policy's expression as `pg_get_expr` prints it back, which the
 * live schema guard (A3e-1b) compares every tenant table's policy with.
 *
 * It lives here because this is the one product file allowed to name the
 * setting (lint), and the policy is the other half of what withTenant sets:
 * the two have to say the same thing or the walls don't hold. How Postgres
 * prints it can differ between major versions, so schema-guard.db.test.ts
 * proves this is what the server really says on each version we support — a
 * future major that words it differently fails there, never silently.
 */
export const TENANT_POLICY_EXPRESSION =
  "(org_id = (NULLIF(current_setting('app.org_id'::text, true), ''::text))::uuid)";

export class TenantContextError extends Error {
  constructor(problem: string) {
    super(`Tenant context refused: ${problem}`);
    this.name = 'TenantContextError';
  }
}

/**
 * Open while withTenant's transaction runs, to refuse a second withTenant
 * inside it. Callbacks the work starts (a timer, say) inherit the scope, so it
 * is closed when the transaction ends: after that they may use withTenant.
 */
const insideTenant = new AsyncLocalStorage<{ open: boolean }>();

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
  if (insideTenant.getStore()?.open === true) {
    throw new TenantContextError('withTenant was called inside another withTenant; pass the transaction on instead');
  }
  const scope = { open: true };
  try {
    // READ COMMITTED is Postgres's default, but the default can be changed per
    // server, database or role; the locking rules in ADR-006 rely on it.
    return await insideTenant.run(scope, () =>
      db
        .transaction()
        .setIsolationLevel('read committed')
        .execute(async (tx) => {
          await sql`select pg_catalog.set_config('app.org_id', ${orgId}, true)`.execute(tx);
          return work(tx);
        }),
    );
  } finally {
    scope.open = false;
  }
}

/**
 * Refuses unless the transaction carries this organisation as its tenant,
 * which only withTenant sets (lint keeps the setting's name in this file).
 * Row security shows another tenant's rows as no rows at all, so work that
 * only reads, such as checking an audit chain, would take a wrong tenant's
 * view for an empty record.
 */
export async function assertTenant<Schema>(tx: Transaction<Schema>, orgId: string): Promise<void> {
  const { rows } = await sql<{ org_id: string | null }>`
    select pg_catalog.current_setting('app.org_id', true) as org_id
  `.execute(tx);
  const tenant = rows[0]?.org_id ?? '';
  if (!UUID.test(orgId) || tenant.toLowerCase() !== orgId.toLowerCase()) {
    throw new TenantContextError("the transaction isn't withTenant's for this organisation");
  }
}

/**
 * What a connection must carry before any work runs on it: no tenant, and the
 * `search_path` the startup packet pinned. Both come back from one statement,
 * so checking the second costs no extra round trip on a pooled connection.
 */
interface ConnectionState {
  /** Its `app.org_id` setting, or '' for none. */
  readonly tenant: string;
  /** Its `search_path`, which the startup packet pins to PINNED_SEARCH_PATH_VALUE. */
  readonly searchPath: string;
}

/** Both settings in one statement, so the search_path costs no extra round trip. */
const CONNECTION_STATE =
  "select pg_catalog.current_setting('app.org_id', true) as org_id, pg_catalog.current_setting('search_path', true) as search_path";

async function stateOf(client: pg.ClientBase): Promise<ConnectionState> {
  const { rows } = await client.query<{ org_id: string | null; search_path: string | null }>(CONNECTION_STATE);
  return { tenant: rows[0]?.org_id ?? '', searchPath: rows[0]?.search_path ?? '' };
}

/**
 * The reason a connection can't be used, or undefined when it is sound.
 *
 * A connection must start with no tenant. One could arrive with a tenant
 * already set, by PGOPTIONS in the environment or by ALTER ROLE or ALTER
 * DATABASE … SET, which points at tampering or a bad setting.
 *
 * Its search_path must be the pinned one, exactly (A3e). The startup packet's
 * setting beats a setting on the database or the role, so this holds unless the
 * pin was dropped from poolConfig or something in the session changed it — and
 * with any other schema in front of pg_catalog, a planted function or operator
 * could stand in for one of Postgres's own, which is how canonical text (and
 * so a state seal) could be made to read alike for two different values.
 *
 * Compared whole rather than by parts: a path that merely *contains* pg_catalog
 * would pass while another schema sat in front of it, and `pg_temp` must keep
 * its place at the end (search-path.ts says why).
 */
function unusable({ tenant, searchPath }: ConnectionState): string | undefined {
  if (tenant !== '') {
    return 'it already carries an organisation (from PGOPTIONS, or ALTER ROLE or ALTER DATABASE ... SET)';
  }
  if (searchPath !== PINNED_SEARCH_PATH_VALUE) {
    // The path itself is not echoed: it names schemas, and the line is enough to find it.
    return `its search_path is not the pinned ${PINNED_SEARCH_PATH_VALUE}`;
  }
  return undefined;
}

/**
 * A new connection must be sound before anything runs on it. The pool runs
 * this on each new connection and closes the connection if it throws.
 */
export async function refuseTenantPreset(client: pg.ClientBase): Promise<void> {
  const problem = unusable(await stateOf(client));
  if (problem !== undefined) {
    throw new TenantContextError(`a new database connection is refused: ${problem}, so it is closed unused`);
  }
}

/**
 * Wraps the pool so that every connection taken from it carries no tenant and
 * still has the pinned search_path. A connection that carries either fault was
 * given a session-wide setting by an earlier caller, which is a bug or an
 * attack: it is closed (so any other session settings go with it), the event
 * is logged, and another connection is taken. New connections are checked on
 * opening, so after at most `attempts` tries one is sound, or the pool is
 * failing and the error says so.
 */
export function tenantCheckedPool(pool: pg.Pool, logger: Logger, attempts: number): PostgresPool {
  return {
    options: pool.options,
    end: () => pool.end(),
    connect: async () => {
      for (let attempt = 1; attempt <= attempts; attempt += 1) {
        const client = await pool.connect();
        let problem: string | undefined;
        try {
          problem = unusable(await stateOf(client));
        } catch (error) {
          client.release(error instanceof Error ? error : true);
          throw error;
        }
        if (problem === undefined) return client;
        client.release(true);
        logger.error('db.tenant.leftover_discarded', { attempt, problem });
      }
      throw new TenantContextError(`no sound connection after ${String(attempts)} tries`);
    },
  };
}
