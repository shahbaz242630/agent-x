// That statements sent together really go in one trip (4D2d P16): over a slow
// line, so a pool that lost pg's pipelining fails here and nowhere else. Here in
// tooling because it opens its own socket, which packages and apps may not.
import net from 'node:net';

import { createDatabase, sendTogether, withTenant } from '../../packages/platform/src/db/index.ts';
import { createTestDatabase, LogCapture, type TestDatabase, testLogger } from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

interface Tables {
  'probe.parents': { id: number };
}

const ORG = '0199a000-0000-7000-8000-00000000000a';
const server = inject('postgres');
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  await database.as('admin').query('create schema probe');
  await database.as('admin').query('create table probe.parents (id int primary key)');
});

afterAll(async () => {
  await database.drop();
});

describe(`one trip (4D2d P16, Postgres ${server.version})`, () => {
  it('really goes in one trip: three take about one trip’s time, over a slow line', async () => {
    const { host, port } = database.connection('admin');
    const ONE_WAY_MS = 100;
    const line = net.createServer((near) => {
      const far = net.connect(port, host);
      const delayed = (from: net.Socket, to: net.Socket) => {
        from.on('data', (data) => {
          setTimeout(() => {
            if (to.writable) to.write(data);
          }, ONE_WAY_MS);
        });
        from.on('close', () => to.destroy());
        from.on('error', () => to.destroy());
      };
      delayed(near, far);
      delayed(far, near);
    });
    await new Promise<void>((listening) => line.listen(0, '127.0.0.1', listening));
    const slow = createDatabase<Tables>(
      {
        ...database.connection('admin'),
        host: '127.0.0.1',
        port: (line.address() as net.AddressInfo).port,
        maxConnections: 1,
      },
      testLogger(new LogCapture()),
    );
    try {
      const took = await withTenant(slow, ORG, async (tx) => {
        const started = performance.now();
        await sendTogether(tx, [...[5, 6, 7].map((id) => tx.insertInto('probe.parents').values({ id }))]);
        return performance.now() - started;
      });
      // One by one is three trips, six times one way; together is two times one way.
      expect(took).toBeLessThan(4 * ONE_WAY_MS);
    } finally {
      await slow.destroy();
      line.close();
    }
  });
});
