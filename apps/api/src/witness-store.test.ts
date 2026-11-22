// The witness log as the API makes it from its config (TR-1): its stores, its lines where none is named, a web copy's
// names, and its job: writes every few seconds, reads on the copy's cadence, the leader's probe handed what was gained.
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { type Chain, createWitnessLog, WITNESS_HEAD_BYTES } from '@agentx/platform/audit-chain';
import type { Config } from '@agentx/platform/config';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { createWitnessJob, storeAt, witnessMostBytes, witnessOf } from './witness-store.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const AT = new Date('2026-11-01T09:00:00.000Z');
const CHAIN: Chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-000000000001' };

const folders: string[] = [];
afterEach(() => {
  for (const made of folders.splice(0)) rmSync(made, { recursive: true, force: true });
});
const folder = (): string => {
  const made = mkdtempSync(join(tmpdir(), 'witness-store-'));
  folders.push(made);
  return made;
};

const configWith = (
  heads: string | null,
  { environment = 'test', role = 'all', snapshots = null as string | null } = {},
): Config =>
  ({
    environment,
    role,
    witnessStore: {
      heads: { directory: heads, container: null },
      snapshots: { directory: snapshots, container: null },
    },
    audit: { anchorSeconds: 300, anchorEpoch: 1 },
  }) as Config;

const services = (capture = new LogCapture()) => ({ keys, logger: testLogger(capture), clock: { now: () => AT } });

describe('SEC-DB-20 TR-1 the witness log as the config names it', () => {
  it('none without a heads’ store: said as the error line where deployed, nothing in development and test', () => {
    const quiet = new LogCapture();
    expect(witnessOf(configWith(null), services(quiet))).toBeUndefined();
    expect(quiet.lines()).toEqual([]);
    const staging = new LogCapture();
    expect(witnessOf(configWith(null, { environment: 'staging' }), services(staging))).toBeUndefined();
    expect(staging.lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'audit.witness_store_not_set', environment: 'staging' }),
    ]);
    expect(storeAt({ directory: null, container: null })).toBeUndefined();
  });

  it('writes its heads to the folder, and the leader alone its snapshot to the snapshots’ own', async () => {
    const heads = folder();
    const snapshots = folder();
    let leads = false;
    const witness = witnessOf(configWith(heads, { snapshots }), { ...services(), leading: () => leads });
    if (witness === undefined) throw new Error('a folder is named');
    await witness.now(CHAIN, { seq: 3n, hash: Buffer.alloc(32, 3) });
    expect(readdirSync(join(heads, 'e1', 'heads'))).toHaveLength(1);
    await witness.refresh();
    await witness.flush();
    expect(readdirSync(snapshots)).toEqual([]);
    leads = true;
    await witness.flush();
    expect(readdirSync(join(snapshots, 'e1', 'snapshots'))).toHaveLength(1);
  });

  it('a web copy’s failed read is said under its own name; its writes keep theirs', async () => {
    const capture = new LogCapture();
    const missing = join(folder(), 'a-file-not-a-folder');
    const witness = witnessOf(configWith(missing, { role: 'web' }), services(capture));
    if (witness === undefined) throw new Error('a folder is named');
    // A folder store over a path that isn't there lists nothing; a file in its way fails the read.
    writeFileSync(missing, 'x');
    await witness.refresh();
    await witness.flush();
    witness.soon(CHAIN, { seq: 3n, hash: Buffer.alloc(32, 3) });
    await witness.flush();
    expect(capture.lines().map(({ event }) => event)).toEqual([
      'audit.web_witness_read_failed',
      'audit.witness_write_failed',
    ]);
  });
});

describe('TR-1 the witness log’s job', () => {
  it('writes every run, reads on its cadence, and hands what a read gained to the leader’s probe', async () => {
    const calls: string[] = [];
    let gained: readonly Chain[] = [CHAIN];
    let at = 0;
    const probed: (readonly Chain[])[] = [];
    const job = createWitnessJob({
      witness: {
        flush: () => {
          calls.push('flush');
          return Promise.resolve();
        },
        refresh: () => {
          calls.push('refresh');
          return Promise.resolve(gained);
        },
      },
      refreshEveryMs: 10_000,
      now: () => at,
      afterRefresh: (chains) => {
        probed.push(chains);
        return Promise.resolve();
      },
    });
    await job.work.run();
    at += 5_000;
    await job.work.run();
    at += 5_000;
    gained = [];
    await job.work.run();
    expect(calls).toEqual(['flush', 'refresh', 'flush', 'flush', 'refresh']);
    expect(probed).toEqual([[CHAIN]]);
  });

  it('TR-3: hands the leader’s probe the chains holding most too, each once, even where a read gained none', async () => {
    const OTHER: Chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-000000000002' };
    const probed: (readonly Chain[])[] = [];
    let gained: readonly Chain[] = [CHAIN];
    let at = 0;
    const job = createWitnessJob({
      witness: {
        flush: () => Promise.resolve(),
        refresh: () => Promise.resolve(gained),
        crowded: () => [{ kind: 'organisation', orgId: CHAIN.orgId.toUpperCase() }, OTHER],
      },
      refreshEveryMs: 10_000,
      now: () => at,
      afterRefresh: (chains) => {
        probed.push(chains);
        return Promise.resolve();
      },
    });
    await job.work.run();
    at += 10_000;
    gained = [];
    await job.work.run();
    expect(probed).toEqual([
      [CHAIN, OTHER],
      [{ kind: 'organisation', orgId: CHAIN.orgId.toUpperCase() }, OTHER],
    ]);
  });

  it('TR-3: holds an anchor interval of a burst at twice the target rate, which the heap share alone would not; never past a tenth of the heap', () => {
    const heap = 768 * 1024 * 1024;
    const burst = 2 * 170 * 300;
    expect(Math.floor((heap * 0.005) / WITNESS_HEAD_BYTES)).toBeLessThan(burst);
    expect(Math.floor(witnessMostBytes(300, heap) / WITNESS_HEAD_BYTES)).toBeGreaterThanOrEqual(burst);
    expect(witnessMostBytes(300, 64 * 1024 * 1024)).toBe(Math.floor(6.4 * 1024 * 1024));
    expect(witnessMostBytes(1, 4 * 1024 * 1024 * 1024)).toBe(Math.floor(4 * 1024 * 1024 * 1024 * 0.005));
    // The burst itself, one organisation's, into a log of that size: none let go.
    const log = createWitnessLog({
      store: createFakeWriteOnceStore().store,
      keys,
      logger: testLogger(new LogCapture()),
      now: () => AT,
      epoch: 1,
      alertAfterMs: 1,
      mostBytes: witnessMostBytes(300, heap),
    });
    for (let seq = 1; seq <= burst; seq += 1) log.soon(CHAIN, { seq: BigInt(seq), hash: Buffer.alloc(32, seq % 256) });
    expect(log.beyondMemory(CHAIN)).toBe(false);
    expect(log.pending(CHAIN, 1)[0]?.seq).toBe(BigInt(burst));
  });

  it('writes what waits once its runs stop', async () => {
    let flushed = 0;
    const job = createWitnessJob({
      witness: {
        flush: () => {
          flushed += 1;
          return Promise.resolve();
        },
        refresh: () => Promise.resolve([]),
      },
      refreshEveryMs: 10_000,
      now: () => 0,
    });
    const handle = job.schedule({ run: () => Promise.resolve() }, 60_000);
    await handle.stop();
    expect(flushed).toBe(1);
  });
});
