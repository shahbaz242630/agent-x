// Here, not beside the code: it stands in for a server with node's own sockets, which
// the packages may reach only through their outbound door.
// A full pool's wait run out, on a real pool (4D2e C, review; partner S161: busy,
// never a 500): told apart by pg-pool's own words, so this holds them to the pinned
// version. A database that is down must stay what it is.
import { createServer, type Socket } from 'node:net';

import { createTestDatabase, LogCapture, type TestDatabase, testLogger } from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createDatabase, type Database } from '../../packages/platform/src/db/database.ts';
import { PoolWaitRanOut } from '../../packages/platform/src/db/organisation-shares.ts';

const server = inject('postgres');
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
});

describe('a full pool', () => {
  let app: Database;
  const capture = new LogCapture();

  beforeAll(() => {
    app = createDatabase({ ...database.connection('app'), maxConnections: 1 }, testLogger(capture));
  });

  afterAll(async () => {
    await app.destroy();
  });

  it('says its wait ran out, as its own line, and the transaction never began', { timeout: 30_000 }, async () => {
    const { promise: release, resolve: letGo } = Promise.withResolvers<undefined>();
    const { promise: held, resolve: holds } = Promise.withResolvers<undefined>();
    const holder = app.connection().execute(async () => {
      holds(undefined);
      await release;
    });
    await held;
    let began = false;
    const waited = await app
      .transaction()
      .execute(() => {
        began = true;
        return Promise.resolve();
      })
      .catch((error: unknown) => error);
    letGo(undefined);
    await holder;

    expect(waited).toBeInstanceOf(PoolWaitRanOut);
    expect((waited as Error & { cause: Error }).cause.message).toBe('timeout exceeded when trying to connect');
    expect(began).toBe(false);
    expect(capture.lines().filter((line) => line.event === 'db.pool_wait_ran_out')).toEqual([
      expect.objectContaining({ level: 'warn' }),
    ]);
    // Free again, it works.
    await expect(app.connection().execute(() => Promise.resolve('ok'))).resolves.toBe('ok');
  });
});

describe('a database that is down', () => {
  const quiet = () => testLogger(new LogCapture());
  const login = () => database.connection('app');

  it('refused outright: the driver’s own failure, never busy', async () => {
    // A port just closed: nothing listens there.
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const address = closed.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    await new Promise((resolve) => closed.close(resolve));

    const app = createDatabase({ ...login(), host: '127.0.0.1', port: address.port, maxConnections: 1 }, quiet());
    try {
      const failed = await app
        .connection()
        .execute(() => Promise.resolve())
        .catch((error: unknown) => error);
      expect(failed).not.toBeInstanceOf(PoolWaitRanOut);
      expect(failed).toMatchObject({ code: 'ECONNREFUSED' });
    } finally {
      await app.destroy();
    }
  });

  it('never answering: a new connection’s own timeout, never busy', { timeout: 30_000 }, async () => {
    // Takes the connection and says nothing, as a hung server does.
    const sockets: Socket[] = [];
    const silent = createServer((socket) => sockets.push(socket));
    await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
    const address = silent.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    const app = createDatabase({ ...login(), host: '127.0.0.1', port: address.port, maxConnections: 1 }, quiet());
    try {
      const failed = await app
        .connection()
        .execute(() => Promise.resolve())
        .catch((error: unknown) => error);
      expect(failed).not.toBeInstanceOf(PoolWaitRanOut);
      expect((failed as Error).message).toBe('Connection terminated due to connection timeout');
    } finally {
      await app.destroy();
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => silent.close(resolve));
    }
  });
});
