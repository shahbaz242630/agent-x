// The anchor log's default budget (PL-65): a fifth of the heap, each line held counted at 340 bytes, here with a heap
// so small that ten organisations, each an anchor and a finished pass, are its edge. The measurement behind the numbers
// is in anchor-log.ts, at `heapsFileBytes`.
import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it, vi } from 'vitest';

import { createKeyProvider } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { signAnchor, signPass } from './anchor.ts';
import { createAnchorLog } from './anchor-log.ts';
import type { Chain } from './chain.ts';

/** Five times the budget for 20 lines at 340 bytes: ten organisations' anchors and passes. */
const { HEAP } = vi.hoisted(() => ({ HEAP: 5 * 20 * 340 }));

vi.mock('node:v8', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:v8')>();
  return { ...real, getHeapStatistics: () => ({ ...real.getHeapStatistics(), heap_size_limit: HEAP }) };
});

const keys = createKeyProvider(
  byPurpose((purpose) => ({ current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 9)]]) })),
);
const WRITTEN = new Date('2026-11-02T09:00:00.000Z');
/** An hour on, so the reader's first write is a snapshot. */
const READ = new Date(WRITTEN.getTime() + 60 * 60_000);

const organisation = (index: number): Chain => ({
  kind: 'organisation',
  orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
});

/** A store holding a snapshot of `count` organisations, each anchored and its full pass finished. */
async function storeOf(count: number): Promise<FakeWriteOnceStore> {
  const fake = createFakeWriteOnceStore();
  const writer = createAnchorLog({
    store: fake.store,
    keys,
    logger: testLogger(new LogCapture()),
    now: () => WRITTEN,
    epoch: 1,
    alertAfterMs: 1000,
    mostFileBytes: 1_000_000,
  });
  await writer.read();
  for (let index = 0; index < count; index += 1) {
    const point = { seq: BigInt(index + 1), hash: Buffer.alloc(32, index), macKeyVersion: 2 };
    writer.keep(signAnchor(keys, organisation(index), point, WRITTEN, 1));
    writer.keepPass(signPass(keys, organisation(index), point, WRITTEN, 1));
  }
  await writer.flush();
  return fake;
}

/** A restart over that store, on the default budget. */
async function restartOver(fake: FakeWriteOnceStore) {
  const capture = new LogCapture();
  const log = createAnchorLog({
    store: fake.store,
    keys,
    logger: testLogger(capture),
    now: () => READ,
    epoch: 1,
    alertAfterMs: 1000,
  });
  await log.read();
  const said = (event: string) => capture.lines().filter((line) => line.event === event);
  return { log, said };
}

describe('the default budget: a fifth of the heap, at 340 bytes a line held (PL-65)', () => {
  it('at the edge, ten organisations, reads whole, and says it is past half', async () => {
    const { log, said } = await restartOver(await storeOf(10));
    expect(log.state()).toBe('read');
    expect(log.organisations()).toHaveLength(10);
    expect(said('audit.anchor_store_beyond_memory')).toEqual([]);

    log.keep(signAnchor(keys, { kind: 'platform' }, { seq: 1n, hash: Buffer.alloc(32), macKeyVersion: 2 }, READ, 1));
    await log.flush();
    expect(said('audit.anchor_store_near_memory')).toEqual([
      expect.objectContaining({ mostBytes: HEAP / 5, organisations: 10, edgeOrganisations: 10 }),
    ]);
  });

  it('one past it refuses, clean and with the true reason, and payments wait', async () => {
    const { log, said } = await restartOver(await storeOf(11));
    expect(log.state()).toBe('unreadable');
    expect(log.organisations()).toEqual([]);
    expect(said('audit.anchor_store_beyond_memory')).toEqual([
      expect.objectContaining({ level: 'error', kind: 'snapshots', mostBytes: HEAP / 5 }),
    ]);
  });

  it('half of the edge says nothing yet', async () => {
    const { log, said } = await restartOver(await storeOf(5));
    log.keep(signAnchor(keys, organisation(0), { seq: 9n, hash: Buffer.alloc(32), macKeyVersion: 2 }, READ, 1));
    await log.flush();
    expect(said('audit.anchor_store_near_memory')).toEqual([]);
  });
});
