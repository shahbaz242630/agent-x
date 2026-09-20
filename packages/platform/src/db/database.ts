// The app's connection to Postgres (ADR-001: Kysely on pg; ADR-002: password
// auth, with TLS in every deployed environment). Only this folder may import
// the driver (ADR-004 §8), so every connection is made here, with the checks
// below, and nothing else in the product can open one.
import { Kysely, PostgresDialect } from 'kysely';
import pg, { type PoolConfig } from 'pg';

import type { Logger } from '../observability/index.ts';
import { refuseTenantPreset, tenantCheckedPool } from './tenant.ts';

export interface DatabaseConnectionOptions {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly password: string;
  /**
   * `verify-full` checks the server's certificate and host name, and is what
   * every deployed environment uses. `disable` is for a local stack or a
   * throwaway test database only.
   */
  readonly tls: 'verify-full' | 'disable';
  /** The most connections the pool keeps open. Default 10. */
  readonly maxConnections?: number;
  /** Names the connection in Postgres's own views, e.g. `agentx-api`. Default `agentx`. */
  readonly applicationName?: string;
}

export class DatabaseOptionsError extends Error {
  constructor(problem: string) {
    super(`Database connection options refused: ${problem}`);
    this.name = 'DatabaseOptionsError';
  }
}

/**
 * ADR-006: a bigint column (money in minor units) arrives as a BigInt, never
 * as a float that could lose digits; pg's default hands it back as text. Set
 * per pool, not in pg's global settings, so nothing else is affected.
 */
function typeParsers(): pg.TypeOverrides {
  const types = new pg.TypeOverrides();
  types.setTypeParser(pg.types.builtins.INT8, (value) => BigInt(value));
  return types;
}

/**
 * Every name our SQL leaves unqualified is looked up in pg_catalog alone, so
 * nothing planted in another schema can stand in for one of Postgres's own
 * (the CVE-2018-1058 pattern). The setup job and the schema checks have always
 * pinned their connections this way; the app's pool is pinned for a second
 * reason (A3e).
 *
 * The database's owner is no superuser and can't set `search_path` on the app's
 * role, but it can on the database it owns, and a connection takes that up. On
 * a real server (S32) `ALTER DATABASE ... SET search_path = audit, pg_catalog`
 * with a planted `audit.length(text)` made the app read `length('abc')` as 999
 * rather than 3 — and canonical text made of such reads is what a state seal is
 * built from, so a tampered value could be made to seal alike. The startup
 * packet's own setting beats a setting on the database or the role, so pinning
 * it here stops that rather than merely reporting it (A3e's live check reports
 * the setting as well, since it is a sign someone tried).
 *
 * It also settles PGOPTIONS: pg would otherwise pass the environment's, and
 * this replaces it.
 */
export const PINNED_SEARCH_PATH = '-c search_path=pg_catalog';

function tlsSetting(tls: string): PoolConfig['ssl'] {
  // Set to true explicitly, so NODE_TLS_REJECT_UNAUTHORIZED=0 can't turn the check off (SEC-PTR-07).
  if (tls === 'verify-full') return { rejectUnauthorized: true };
  if (tls === 'disable') return false;
  throw new DatabaseOptionsError('tls must be verify-full or disable');
}

/**
 * pg's settings for these options. pg fills a missing or empty host, port,
 * database, user, password or application name from the PG* environment
 * variables, so each is given and must not be empty. `options` is given too,
 * which replaces PGOPTIONS rather than adding to it (PINNED_SEARCH_PATH); a
 * tenant set on the database or the role is still refused on connection, and
 * the start-up config check will refuse PG* variables (piece E).
 */
export function poolConfig(options: DatabaseConnectionOptions): PoolConfig & { readonly max: number } {
  for (const name of ['host', 'database', 'user', 'password', 'applicationName'] as const) {
    if (options[name] === '') throw new DatabaseOptionsError(`${name} is empty`);
  }
  if (!Number.isSafeInteger(options.port) || options.port < 1 || options.port > 65_535) {
    throw new DatabaseOptionsError('port must be a whole number from 1 to 65535');
  }
  const max = options.maxConnections ?? 10;
  if (!Number.isSafeInteger(max) || max < 1) {
    throw new DatabaseOptionsError('maxConnections must be a whole number of at least 1');
  }
  return {
    host: options.host,
    port: options.port,
    database: options.database,
    user: options.user,
    password: options.password,
    ssl: tlsSetting(options.tls),
    max,
    options: PINNED_SEARCH_PATH,
    application_name: options.applicationName ?? 'agentx',
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
    types: typeParsers(),
    // SEC-TEN-06: a new connection that already carries a tenant is closed, never used.
    // eslint-disable-next-line @typescript-eslint/no-misused-promises -- pg-pool 3.14 awaits onConnect and closes the connection when it rejects (pg-pool index.js, newClient); @types/pg types it as returning void.
    onConnect: refuseTenantPreset,
  };
}

/** The app's handle on its database: a query builder over a pool of connections. */
export type Database<Schema = unknown> = Kysely<Schema>;

/**
 * A query builder over a pool of connections. Tenant data is reached only
 * through `withTenant`. Call `destroy()` at shutdown to close the pool.
 */
export function createDatabase<Schema = unknown>(options: DatabaseConnectionOptions, logger: Logger): Database<Schema> {
  const config = poolConfig(options);
  const pool = new pg.Pool(config);
  // A connection that drops (a restart, a failover, a timeout) reports it as
  // an 'error' event on the connection, idle or in use; with no listener, Node
  // would stop the process. So each connection gets one listener for its whole
  // life. The query that was running fails on its own, and pg-pool replaces
  // the connection.
  pool.on('connect', (client) => {
    client.on('error', (error) => {
      logger.warn('db.connection_lost', { err: error });
    });
  });
  // pg-pool also passes an idle connection's error on to the pool, which must
  // be listened for too. The connection's own listener has already logged it.
  pool.on('error', () => undefined);
  // Every idle connection could need replacing, and then one new one.
  const attempts = config.max + 1;
  return new Kysely<Schema>({ dialect: new PostgresDialect({ pool: tenantCheckedPool(pool, logger, attempts) }) });
}
