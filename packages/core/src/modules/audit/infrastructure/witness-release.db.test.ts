// TR-3 review (S209): the leader's probe reads the hash at each held place in one statement, with no link between them,
// so the owner can put rows back beside a cut branch for just that statement. A head the probe found on the chain is
// therefore released, never let go: compact, and every later walk from the anchor held to it until one passes it. Here
// the owner tries it: the honest chain to 10, its lower heads released; the chain cut to 5 and grown again (6'-8', a
// stop among them), each of those noted at a released place (the fork alarm at once); the originals 9-10 and the head
// row put back beside them for the probe, which releases 6'-8'; then the originals restored whole. The next walk, held
// to what was released, is cut_back. Held to the heads still held alone (the outright let-go this replaced), it passes.
import { CHAIN_START, createWitnessLog, type WitnessLog } from '@agentx/platform/audit-chain';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createFakeWriteOnceStore,
  createTestDatabase,
  LogCapture,
  type OwnerTamper,
  SequentialIds,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
} from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import type { AuditEvent } from '../domain/event.ts';
import { createAuditTrail } from './audit-trail.ts';
import type { AuditTables } from './tables.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Database<AuditTables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const trail = createAuditTrail({ keys, ids: new SequentialIds(0x9e1e_0000) });
const ORG = '0199a0f0-0000-7000-8000-00000000e1e1';
const CHAIN = { kind: 'organisation', orgId: ORG } as const;
/** The owner's scripts need a table to name; this test only reads and rewrites the chain. */
const TARGET = { table: 'agents.agents', subject: 'agent' };
const USER = '0199a0f0-0000-7000-8000-0000000000aa';
/** When the copies note the heads: fixed, as nothing here waits on time. */
const AT = new Date('2026-11-22T09:00:00.000Z');

const event = (step: number): AuditEvent => ({
  actor: { type: 'user', id: USER },
  action: 'probe.stepped',
  subject: { type: 'probe', id: USER, version: step },
  details: { step },
});

const record = (...steps: number[]) =>
  withTenant(app, ORG, async (tx) => {
    for (const step of steps) await trail.record(tx, ORG, event(step));
  });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<AuditTables>({ ...database.connection('app'), maxConnections: 4 }, testLogger());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

/** The chain's events after `after` as the owner reads them: each one's place and hash, and its row as JSON text. */
const eventsAfter = (owner: OwnerTamper, after: number) =>
  owner.query<{ seq: string; hash: Buffer; json: string }>(
    'select e.seq::text as seq, e.hash, pg_catalog.row_to_json(e)::text as json from audit.events e where e.org_id = $1 and e.seq > $2::bigint order by e.seq',
    [ORG, after],
  );

/** Rows put back as the owner saved them. */
const putBack = async (owner: OwnerTamper, rows: readonly { readonly json: string }[]) => {
  for (const { json } of rows) {
    await owner.query(
      'insert into audit.events select * from pg_catalog.json_populate_record(null::audit.events, $1::json)',
      [json],
    );
  }
};

/** The leader's probe as the anchor check runs it: every head held asked, all but the highest released where it holds. */
const probeAndRelease = async (log: WitnessLog): Promise<void> => {
  const heldTo = log.pending(CHAIN);
  const answer = (await trail.probeHeads(app, [{ orgId: ORG, from: CHAIN_START, heldTo }])).get(ORG);
  expect(answer?.kind).not.toBe('failed');
  expect(answer?.kind).not.toBe('missed');
  const [, ...below] = heldTo;
  log.release(CHAIN, below);
};

describe('TR-3 heads a probe found released, never let go', () => {
  it('rows put back beside a cut branch for the probe alone: the next walk, held to the heads released, is cut_back', async () => {
    const capture = new LogCapture();
    const log = createWitnessLog({
      store: createFakeWriteOnceStore().store,
      keys,
      logger: testLogger(capture),
      now: () => AT,
      epoch: 1,
      alertAfterMs: 60_000,
      mostBytes: 1024 * 1024,
    });
    const owner = await tamperAsOwner(database, TARGET, ORG);
    try {
      await record(1, 2, 3, 4, 5);
      const atFive = await owner.saveHead();
      await record(6, 7, 8, 9, 10);
      const atTen = await owner.saveHead();
      const originals = await eventsAfter(owner, 5);
      const all = await eventsAfter(owner, 0);
      // Every head witnessed as the honest copies wrote them, and the probe finds them on the chain.
      for (const { seq, hash } of all) log.soon(CHAIN, { seq: BigInt(seq), hash });
      await probeAndRelease(log);
      expect(log.pending(CHAIN).map(({ seq }) => seq)).toEqual([10n]);

      // Cut to 5 and grown again: 6'-8', each noted at a released place, the fork alarm at once.
      await owner.windBack(atFive);
      await record(106, 107, 108);
      const branch = await eventsAfter(owner, 5);
      for (const { seq, hash } of branch) log.soon(CHAIN, { seq: BigInt(seq), hash });
      const forks = capture.lines().filter((line) => line.event === 'audit.integrity_failed' && line.reason === 'fork');
      expect(forks.map(({ seq }) => seq)).toEqual(['6', '7', '8']);

      // For the probe alone: the originals 9-10 beside 6'-8', the head row at 10. It finds every head held at its place.
      await putBack(owner, originals.slice(3));
      await owner.windBack(atTen);
      await probeAndRelease(log);
      expect(log.pending(CHAIN).map(({ seq }) => seq)).toEqual([10n]);

      // The originals restored whole: the stop's events gone.
      await owner.query('delete from audit.events where org_id = $1 and seq > 5', [ORG]);
      await putBack(owner, originals);
      await owner.windBack(atTen);

      const released = log.fingerprints(CHAIN);
      expect(released.map(({ seq }) => seq).toSorted((one, other) => (one < other ? -1 : 1))).toEqual([
        1n,
        2n,
        3n,
        4n,
        5n,
        6n,
        6n,
        7n,
        7n,
        8n,
        8n,
        9n,
      ]);
      const walk = await trail.checkFromAnchor(app, ORG, CHAIN_START, undefined, [...log.pending(CHAIN), ...released]);
      expect(walk).toMatchObject({ ok: false, problem: { reason: 'cut_back' } });
      // Would-fail: held to the heads still held alone, as when a probe let them go outright, the walk passes.
      expect(await trail.checkFromAnchor(app, ORG, CHAIN_START, undefined, log.pending(CHAIN))).toMatchObject({
        ok: true,
        seq: 10n,
      });
    } finally {
      await owner.end();
    }
  });
});
