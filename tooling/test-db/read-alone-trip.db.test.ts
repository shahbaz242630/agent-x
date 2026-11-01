// That a read alone really goes in one trip (4D2e C5): on the wire, no clock in
// it, so a pool that lost pg's pipelining fails here. The wire holds back every
// answer until the client has written the commit: with no pipelining the client
// waits for the start's answer, never writes the commit, and is never answered.
// Here in tooling because it opens its own socket, which packages and apps may not.
import net from 'node:net';

import { createDatabase, readAloneOnOneTrip } from '../../packages/platform/src/db/index.ts';
import {
  createTestDatabase,
  LogCapture,
  type TestDatabase,
  testLogger,
  within,
} from '../../packages/testing/src/index.ts';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

/** The commit's message ends so; the start's text says `read committed`, which isn't it. */
const COMMIT_MESSAGE = 'commit' + String.fromCodePoint(0);

const server = inject('postgres');
let database: TestDatabase;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
});

afterAll(async () => {
  await database.drop();
});

describe(`a read alone's one trip (4D2e C5, Postgres ${server.version})`, () => {
  it('writes the start, the read and the commit before any answer reaches it', async () => {
    const { host, port } = database.connection('app');
    const wire = { holding: false, written: '', held: [] as Buffer[] };
    const line = net.createServer((near) => {
      const far = net.connect(port, host);
      near.on('data', (data) => {
        far.write(data);
        if (!wire.holding) return;
        wire.written += data.toString('latin1');
        if (wire.written.includes(COMMIT_MESSAGE)) {
          wire.holding = false;
          near.write(Buffer.concat(wire.held));
        }
      });
      far.on('data', (data) => {
        if (wire.holding) wire.held.push(data);
        else near.write(data);
      });
      for (const [one, other] of [
        [near, far],
        [far, near],
      ] as const) {
        one.on('close', () => other.destroy());
        one.on('error', () => other.destroy());
      }
    });
    await new Promise<void>((listening) => line.listen(0, '127.0.0.1', listening));
    const held = createDatabase(
      {
        ...database.connection('app'),
        host: '127.0.0.1',
        port: (line.address() as net.AddressInfo).port,
        maxConnections: 1,
      },
      testLogger(new LogCapture()),
    );
    try {
      // The connection opened and sound, before the wire starts holding.
      const asked = held.selectNoFrom((builder) => builder.val('bound').as('answer'));
      await asked.execute();
      wire.holding = true;

      const answer = readAloneOnOneTrip(held, asked);

      await expect(within(5_000, answer, 'the read')).resolves.toEqual([{ answer: 'bound' }]);
    } finally {
      wire.holding = false;
      await held.destroy();
      line.close();
    }
  });
});
