import { LogCapture } from '@agentx/testing';
import type pg from 'pg';
import { describe, expect, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { TenantContextError, tenantCheckedPool } from './tenant.ts';

/** A stand-in connection that reports `tenant` and records how it was released. */
function connection(tenant: string | null | Error): { client: pg.PoolClient; released: unknown[] } {
  const released: unknown[] = [];
  const client = {
    query: () => (tenant instanceof Error ? Promise.reject(tenant) : Promise.resolve({ rows: [{ org_id: tenant }] })),
    release: (how?: unknown) => {
      released.push(how);
    },
  };
  return { client: client as unknown as pg.PoolClient, released };
}

/** A stand-in pool that hands out the given connections in turn. */
function poolOf(...clients: pg.PoolClient[]): { pool: pg.Pool; ended: () => boolean } {
  let ended = false;
  const queue = [...clients];
  const pool = {
    options: { max: 3 },
    connect: () => {
      const next = queue.shift();
      return next === undefined ? Promise.reject(new Error('no connections left')) : Promise.resolve(next);
    },
    end: () => {
      ended = true;
      return Promise.resolve();
    },
  };
  return { pool: pool as unknown as pg.Pool, ended: () => ended };
}

function logger(): { capture: LogCapture; logger: ReturnType<typeof createLogger> } {
  const capture = new LogCapture();
  return {
    capture,
    logger: createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: capture,
    }),
  };
}

const ORG = '0199a000-0000-7000-8000-00000000000a';

describe('SEC-TEN-06 tenantCheckedPool', () => {
  it('hands out a connection with no tenant, whether the setting is missing or empty', async () => {
    for (const tenant of [null, '']) {
      const clean = connection(tenant);
      const log = logger();
      expect(await tenantCheckedPool(poolOf(clean.client).pool, log.logger, 3).connect()).toBe(clean.client);
      expect(clean.released).toEqual([]);
      expect(log.capture.lines()).toEqual([]);
    }
  });

  it('closes a connection left with a tenant, logs it without the tenant, and hands out the next', async () => {
    const poisoned = connection(ORG);
    const clean = connection(null);
    const log = logger();
    const pool = tenantCheckedPool(poolOf(poisoned.client, clean.client).pool, log.logger, 3);

    expect(await pool.connect()).toBe(clean.client);
    expect(poisoned.released).toEqual([true]);
    expect(log.capture.lines()).toMatchObject([{ level: 'error', event: 'db.tenant.leftover_discarded', attempt: 1 }]);
    expect(log.capture.text).not.toContain(ORG);
  });

  it('gives up after the allowed number of tries', async () => {
    const tries = [connection(ORG), connection(ORG), connection(ORG)];
    const log = logger();
    const pool = tenantCheckedPool(poolOf(...tries.map((each) => each.client)).pool, log.logger, 2);

    await expect(pool.connect()).rejects.toThrow(
      new TenantContextError('no connection without a leftover tenant after 2 tries'),
    );
    expect(tries.map((each) => each.released)).toEqual([[true], [true], []]);
  });

  it('closes a connection whose check fails, and passes the error on', async () => {
    const failure = new Error('connection reset');
    const broken = connection(failure);
    const pool = tenantCheckedPool(poolOf(broken.client).pool, logger().logger, 3);

    await expect(pool.connect()).rejects.toBe(failure);
    expect(broken.released).toEqual([failure]);
  });

  it('closes the connection even when the check fails with something that is not an Error', async () => {
    const broken = connection(null);
    (broken.client as unknown as { query: () => Promise<never> }).query = () =>
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- The test is about a rejection that isn't an Error.
      Promise.reject('not an error');
    const pool = tenantCheckedPool(poolOf(broken.client).pool, logger().logger, 3);

    await expect(pool.connect()).rejects.toBe('not an error');
    expect(broken.released).toEqual([true]);
  });

  it('passes the pool’s options and shutdown through', async () => {
    const stand = poolOf();
    const pool = tenantCheckedPool(stand.pool, logger().logger, 1);
    expect(pool.options).toEqual({ max: 3 });
    await pool.end();
    expect(stand.ended()).toBe(true);
  });
});
