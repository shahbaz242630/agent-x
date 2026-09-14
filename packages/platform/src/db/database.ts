// The app's connection to Postgres (ADR-001: Kysely on pg; ADR-002: password
// auth, with TLS in every deployed environment). Only this folder may import
// the driver (ADR-004 §8), so every connection is made here, with the checks
// below, and nothing else in the product can open one.
import { Kysely, PostgresDialect } from 'kysely';
import pg, { type PoolConfig } from 'pg';

import { refuseTenantPreset } from './tenant.ts';

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
 * pg's settings for these options. Every connection value is given
 * explicitly: pg fills a missing or empty one from the PG* environment
 * variables, which the checked config doesn't cover.
 */
export function poolConfig(options: DatabaseConnectionOptions): PoolConfig {
  for (const name of ['host', 'database', 'user', 'password'] as const) {
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
    // Set to true explicitly, so NODE_TLS_REJECT_UNAUTHORIZED=0 can't turn the check off (SEC-PTR-07).
    ssl: options.tls === 'verify-full' ? { rejectUnauthorized: true } : false,
    max,
    application_name: options.applicationName ?? 'agentx',
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
    types: typeParsers(),
    // SEC-TEN-06: a new connection that already carries a tenant is closed, never used.
    // eslint-disable-next-line @typescript-eslint/no-misused-promises -- pg-pool 3.14 awaits onConnect and closes the connection when it rejects (pg-pool index.js, newClient); @types/pg types it as returning void.
    onConnect: refuseTenantPreset,
  };
}

/**
 * A query builder over a pool of connections. Tenant data is reached only
 * through `withTenant`. Call `destroy()` at shutdown to close the pool.
 */
export function createDatabase<Schema>(options: DatabaseConnectionOptions): Kysely<Schema> {
  return new Kysely<Schema>({ dialect: new PostgresDialect({ pool: new pg.Pool(poolConfig(options)) }) });
}
