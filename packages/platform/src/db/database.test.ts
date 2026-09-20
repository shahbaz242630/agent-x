import pg from 'pg';
import { describe, expect, it } from 'vitest';

import { type DatabaseConnectionOptions, DatabaseOptionsError, PINNED_SEARCH_PATH, poolConfig } from './database.ts';
import { PINNED_SEARCH_PATH_VALUE } from './search-path.ts';
import { refuseTenantPreset } from './tenant.ts';

const OPTIONS: DatabaseConnectionOptions = {
  host: 'db.internal',
  port: 5432,
  database: 'agentx',
  user: 'agentx_app',
  password: 'plain words for a test',
  tls: 'verify-full',
};

describe('poolConfig', () => {
  it('passes every connection value explicitly, so pg fills none of them from PG* variables', () => {
    expect(poolConfig(OPTIONS)).toMatchObject({
      host: 'db.internal',
      port: 5432,
      database: 'agentx',
      user: 'agentx_app',
      password: 'plain words for a test',
      max: 10,
      application_name: 'agentx',
      connectionTimeoutMillis: 10_000,
      idleTimeoutMillis: 30_000,
    });
  });

  it('SEC-PTR-07: checks the server certificate explicitly with verify-full, so the environment cannot turn it off', () => {
    expect(poolConfig(OPTIONS).ssl).toEqual({ rejectUnauthorized: true });
    expect(poolConfig({ ...OPTIONS, tls: 'disable' }).ssl).toBe(false);
  });

  it('refuses any other TLS value, rather than falling back to no TLS', () => {
    for (const tls of ['', 'require', 'Verify-Full', 'prefer']) {
      expect(() => poolConfig({ ...OPTIONS, tls: tls as 'disable' })).toThrow(
        new DatabaseOptionsError('tls must be verify-full or disable'),
      );
    }
  });

  it('takes a pool size and an application name', () => {
    expect(poolConfig({ ...OPTIONS, maxConnections: 3, applicationName: 'agentx-worker' })).toMatchObject({
      max: 3,
      application_name: 'agentx-worker',
    });
  });

  it('SEC-TEN-06: checks every new connection for a preset tenant', () => {
    expect(poolConfig(OPTIONS).onConnect).toBe(refuseTenantPreset);
  });

  it('A3e: pins every connection, whatever the options ask for', () => {
    expect(poolConfig(OPTIONS).options).toBe(PINNED_SEARCH_PATH);
    expect(PINNED_SEARCH_PATH).toBe('-c search_path=pg_catalog,pg_temp');
    // The pin travels in the startup packet, which beats a search_path set on
    // the database or the role, and replaces PGOPTIONS rather than adding to it.
    expect(poolConfig({ ...OPTIONS, applicationName: 'agentx-worker' }).options).toBe(PINNED_SEARCH_PATH);
  });

  it('A3e: the option the pool sets and the value the connection check expects cannot drift apart', () => {
    // They are derived from one literal. Were they two hand-kept copies,
    // strengthening one and forgetting the other would make every connection
    // fail its check and refuse every query, with no unit test to show it.
    expect(PINNED_SEARCH_PATH).toBe(`-c search_path=${PINNED_SEARCH_PATH_VALUE}`);
    expect(poolConfig(OPTIONS).options).toBe(`-c search_path=${PINNED_SEARCH_PATH_VALUE}`);
  });

  it('A3e: names pg_temp, and last, so a temporary object cannot shadow a type name', () => {
    // Left out, Postgres searches the session's temporary schema for relation
    // and type names *before* pg_catalog; named last, it is searched after.
    const schemas = PINNED_SEARCH_PATH_VALUE.split(',');
    expect(schemas[0]).toBe('pg_catalog');
    expect(schemas.at(-1)).toBe('pg_temp');
  });

  it('ADR-006: reads bigint columns as BigInt, and leaves other types alone', () => {
    const { types } = poolConfig(OPTIONS);
    const parseInt8 = types?.getTypeParser(pg.types.builtins.INT8, 'text') as (value: string) => unknown;
    expect(parseInt8('9007199254740993')).toBe(9_007_199_254_740_993n);
    expect(parseInt8('-42')).toBe(-42n);
    expect(types?.getTypeParser(pg.types.builtins.INT4, 'text')).toBe(
      pg.types.getTypeParser(pg.types.builtins.INT4, 'text'),
    );
    expect(types?.getTypeParser(pg.types.builtins.NUMERIC, 'text')).toBe(
      pg.types.getTypeParser(pg.types.builtins.NUMERIC, 'text'),
    );
  });

  it('does not change pg’s global type settings', () => {
    const { types } = poolConfig(OPTIONS);
    expect(pg.types.getTypeParser(pg.types.builtins.INT8, 'text')).not.toBe(
      types?.getTypeParser(pg.types.builtins.INT8, 'text'),
    );
  });

  it.each(['host', 'database', 'user', 'password', 'applicationName'] as const)('refuses an empty %s', (name) => {
    expect(() => poolConfig({ ...OPTIONS, [name]: '' })).toThrow(new DatabaseOptionsError(`${name} is empty`));
  });

  it.each([0, -1, 65_536, 5432.5, Number.NaN])('refuses port %s', (port) => {
    expect(() => poolConfig({ ...OPTIONS, port })).toThrow(DatabaseOptionsError);
  });

  it('accepts the lowest and highest ports', () => {
    expect(poolConfig({ ...OPTIONS, port: 1 }).port).toBe(1);
    expect(poolConfig({ ...OPTIONS, port: 65_535 }).port).toBe(65_535);
  });

  it.each([0, -3, 2.5])('refuses a pool size of %s', (maxConnections) => {
    expect(() => poolConfig({ ...OPTIONS, maxConnections })).toThrow(DatabaseOptionsError);
  });

  it('names the problem, never a value', () => {
    for (const wrong of [{ port: 0 }, { maxConnections: 0 }, { database: '' }]) {
      const error = ((): unknown => {
        try {
          poolConfig({ ...OPTIONS, ...wrong });
        } catch (caught) {
          return caught;
        }
        return undefined;
      })();
      expect(error).toBeInstanceOf(DatabaseOptionsError);
      expect(String(error)).not.toMatch(/plain words|db\.internal|agentx_app/);
    }
  });
});
