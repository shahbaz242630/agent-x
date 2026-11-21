import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import type { Chain } from './chain.ts';
import { fileName, type FileKind, signedFile } from './signed-files.ts';
import {
  createWitnessLog,
  WITNESS_HEAD_BYTES,
  type WitnessAnchors,
  type WitnessSigner,
  WitnessUnconfirmed,
} from './witness-log.ts';

const keyMaterial = (fill: number): KeyMaterial =>
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + fill)]]),
  })) satisfies KeyMaterial;
const keys = createKeyProvider(keyMaterial(1));
/** Someone else's keys: their files read as ours, signed wrongly. */
const otherKeys = createKeyProvider(keyMaterial(50));

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const CHAIN: Chain = { kind: 'organisation', orgId: ORG };
const OTHER: Chain = { kind: 'organisation', orgId: OTHER_ORG };
const PLATFORM: Chain = { kind: 'platform' };
const START = new Date('2026-11-20T09:00:00.000Z');
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const hash = (fill: number): Buffer => Buffer.alloc(32, fill);
const head = (seq: bigint, fill: number) => ({ seq, hash: hash(fill) });

function clock(at = START.getTime()) {
  const held = { at };
  return { now: () => new Date(held.at), held };
}

/** The anchors' log as the witness asks it: rebases and latest anchors by chain name. */
function anchorsWith(rebases = new Map<string, Date>(), latest = new Map<string, bigint>()): WitnessAnchors {
  const name = (chain: Chain) => (chain.kind === 'platform' ? 'platform' : chain.orgId);
  return {
    rebasedAfter: (chain, at) => {
      const rebase = rebases.get(name(chain));
      return rebase !== undefined && rebase > at;
    },
    latest: (chain) => {
      const seq = latest.get(name(chain));
      return seq === undefined ? undefined : { seq };
    },
  };
}

/** How a test's witness log is made. */
interface WitnessOptions {
  readonly snapshots?: ReturnType<typeof createFakeWriteOnceStore>;
  /** False: no snapshots' store at all. */
  readonly withSnapshots?: boolean;
  readonly time?: ReturnType<typeof clock>;
  readonly capture?: LogCapture;
  readonly signer?: WitnessSigner;
  readonly leads?: boolean;
  readonly mostBytes?: number;
  readonly waitMs?: number;
}

function witnessOn(
  heads = createFakeWriteOnceStore(),
  {
    snapshots = createFakeWriteOnceStore(),
    withSnapshots = true,
    time = clock(),
    capture = new LogCapture(),
    signer = 'app',
    leads = false,
    mostBytes = 1024 * 1024,
    waitMs = 200,
  }: WitnessOptions = {},
) {
  const log = createWitnessLog({
    store: heads.store,
    snapshots: withSnapshots ? snapshots.store : undefined,
    keys,
    logger: testLogger(capture),
    now: time.now,
    epoch: 1,
    signer,
    writes: () => leads,
    alertAfterMs: 15 * MINUTE,
    mostBytes,
    waitMs,
  });
  return { log, heads, snapshots, time, capture };
}

const namesUnder = (files: ReadonlyMap<string, Buffer>, folder: string): string[] =>
  [...files.keys()].filter((name) => name.startsWith(`e1/${folder}/`)).toSorted();

const line = (chain: string, seq: bigint, fill: number, at = START) =>
  JSON.stringify({ c: chain, s: seq.toString(), h: hash(fill).toString('hex'), t: at.toISOString() });

/** A file of `kind` written straight into a store, named in `folder` at `at`. */
async function planted(
  files: Map<string, Buffer>,
  folder: string,
  kind: FileKind,
  lines: readonly string[],
  { at = START.getTime(), signing = keys } = {},
): Promise<string> {
  const name = fileName(`e1/${folder}/`, at);
  files.set(name, await signedFile(signing, kind, name, 1, lines));
  return name;
}

const HEADS: FileKind = { label: 'audit-witness-file', purpose: 'audit-anchor' };
const OPERATOR: FileKind = { label: 'audit-witness-file', purpose: 'operator-signing' };
const SNAPSHOT: FileKind = { label: 'audit-witness-snapshot', purpose: 'audit-anchor' };

const integrity = (capture: LogCapture) =>
  capture.lines().filter((one) => one.event === 'audit.integrity_failed' && one.check === 'witness_store');

const seqs = (heads: readonly { readonly seq: bigint }[]) => heads.map(({ seq }) => seq);

describe('the witness log: writing', () => {
  it('writes a `now` head at once and resolves once its Put holding it succeeded; one Put in flight takes all waiting', async () => {
    const { log, heads } = witnessOn();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let first = true;
    let putStarted: () => void = () => undefined;
    const started = new Promise<void>((resolve) => {
      putStarted = resolve;
    });
    heads.instead.put = async (name, bytes) => {
      if (first) {
        first = false;
        putStarted();
        await gate;
      }
      return heads.real.put(name, bytes);
    };
    const one = log.now(CHAIN, head(5n, 1));
    await started;
    // Two more while the first Put is in flight: one Put takes both after it.
    const two = log.now(CHAIN, head(6n, 2));
    const three = log.now(OTHER, head(1n, 3));
    let oneDone = false;
    void one.then(() => (oneDone = true));
    await Promise.resolve();
    expect(oneDone).toBe(false);
    release();
    await Promise.all([one, two, three]);
    expect(heads.calls.puts).toBe(2);
    expect(namesUnder(heads.files, 'heads')).toHaveLength(2);
  });

  it('keeps a `soon` head until the flush, then writes it; a flush with nothing waiting writes nothing', async () => {
    const { log, heads } = witnessOn();
    log.soon(CHAIN, head(5n, 1));
    log.soon(CHAIN, head(6n, 2));
    await Promise.resolve();
    expect(heads.calls.puts).toBe(0);
    // Its own heads are held at once, before they go out.
    expect(seqs(log.pending(CHAIN))).toEqual([6n, 5n]);
    await log.flush();
    expect(heads.calls.puts).toBe(1);
    await log.flush();
    expect(heads.calls.puts).toBe(1);
  });

  it('a Put that fails: the waiter is told WitnessUnconfirmed, the head stays queued, a later wait on the chain waits for it', async () => {
    const { log, heads, capture, time } = witnessOn(undefined, { waitMs: 50 });
    let failing = true;
    heads.instead.put = (name, bytes) =>
      failing ? Promise.reject(new Error('store down')) : heads.real.put(name, bytes);
    await expect(log.now(CHAIN, head(5n, 1))).rejects.toBeInstanceOf(WitnessUnconfirmed);
    expect(capture.lines().map(({ event }) => event)).toEqual(
      expect.arrayContaining(['audit.witness_write_failed', 'audit.witness_unconfirmed']),
    );
    // Another chain has nothing waiting: it is never held up by this one.
    await expect(log.settled([OTHER])).resolves.toBeUndefined();
    // The same chain's next wait waits for the head still queued; the store back, the retry writes it.
    failing = false;
    time.held.at += 1000;
    const later = log.settled([CHAIN]);
    await expect(later).resolves.toBeUndefined();
    expect(namesUnder(heads.files, 'heads')).toHaveLength(1);
  });

  it('the operator writes under its own folder and key, and the API copies take its file only so', async () => {
    const store = createFakeWriteOnceStore();
    const operator = witnessOn(store, { signer: 'operator' });
    await operator.log.now(PLATFORM, head(9n, 4));
    expect(namesUnder(store.files, 'operator')).toHaveLength(1);
    expect(namesUnder(store.files, 'heads')).toHaveLength(0);
    const reader = witnessOn(store);
    await reader.log.refresh();
    expect(seqs(reader.log.pending(PLATFORM))).toEqual([9n]);
    expect(integrity(reader.capture)).toEqual([]);
  });
});

describe('the witness log: reading', () => {
  it('keeps both copies’ heads, the honest one and a stale copy’s on a cut branch: a list, never only the highest', async () => {
    const store = createFakeWriteOnceStore();
    const copyA = witnessOn(store);
    const copyB = witnessOn(store);
    await copyA.log.now(CHAIN, head(105n, 1));
    await copyB.log.now(CHAIN, head(106n, 2));
    const jobs = witnessOn(store);
    const gained = await jobs.log.refresh();
    expect(gained).toEqual([CHAIN]);
    expect(jobs.log.pending(CHAIN).map(({ seq, hash: h }) => [seq, h[0]])).toEqual([
      [106n, 2],
      [105n, 1],
    ]);
    expect(jobs.log.freshAt()).toEqual(START);
  });

  it('a file signed with another key, or not one of ours, is the alarm and counts nothing; a sound one beside it counts (control)', async () => {
    const store = createFakeWriteOnceStore();
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 7n, 1)], { signing: otherKeys });
    await planted(store.files, 'heads', HEADS, ['{"not":"ours"}']);
    await planted(store.files, 'heads', HEADS, [line(`organisation:${OTHER_ORG}`, 3n, 2)]);
    const { log, capture } = witnessOn(store);
    await log.refresh();
    expect(log.pending(CHAIN)).toEqual([]);
    expect(seqs(log.pending(OTHER))).toEqual([3n]);
    expect(integrity(capture).map(({ reason }) => reason)).toEqual(['spoiled', 'spoiled']);
  });

  it('takes each file only under the key its folder allows: an app-signed file in the operator’s folder, an operator-signed one in the heads’', async () => {
    const store = createFakeWriteOnceStore();
    await planted(store.files, 'operator', HEADS, [line('platform', 7n, 1)]);
    await planted(store.files, 'heads', OPERATOR, [line('platform', 8n, 1)]);
    const { log, capture } = witnessOn(store);
    await log.refresh();
    expect(log.pending(PLATFORM)).toEqual([]);
    expect(integrity(capture)).toHaveLength(2);
  });

  it('a snapshot is taken from the snapshots’ store alone: one signed as a snapshot under the heads’ folder counts nothing', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    await planted(store.files, 'heads', SNAPSHOT, [line(`organisation:${ORG}`, 7n, 1)]);
    // Nor in a snapshots folder of the heads' store, which a web copy could add to: never listed.
    await planted(store.files, 'snapshots', SNAPSHOT, [line(`organisation:${ORG}`, 8n, 1)]);
    await planted(snapshots.files, 'snapshots', SNAPSHOT, [line(`organisation:${OTHER_ORG}`, 4n, 1)]);
    const { log, capture } = witnessOn(store, { snapshots });
    await log.refresh();
    expect(log.pending(CHAIN)).toEqual([]);
    expect(seqs(log.pending(OTHER))).toEqual([4n]);
    expect(integrity(capture).map(({ reason }) => reason)).toEqual(['spoiled']);
  });

  it('a start reads the newest sound snapshot, then the heads files since it less the lag, none older', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const at = START.getTime();
    await planted(snapshots.files, 'snapshots', SNAPSHOT, [line(`organisation:${ORG}`, 1n, 1)], { at: at - 3 * HOUR });
    await planted(snapshots.files, 'snapshots', SNAPSHOT, [line(`organisation:${ORG}`, 2n, 1)], { at: at - HOUR });
    // A spoiled newer one is passed over, said.
    await planted(snapshots.files, 'snapshots', SNAPSHOT, [line(`organisation:${ORG}`, 3n, 1)], {
      at: at - 30 * MINUTE,
      signing: otherKeys,
    });
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 10n, 1)], { at: at - HOUR - 10 * MINUTE });
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 11n, 1)], { at: at - HOUR - 2 * MINUTE });
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 12n, 1)], { at: at - MINUTE });
    const { log, capture } = witnessOn(store, { snapshots });
    expect(log.state()).toBe('unread');
    await log.refresh();
    expect(log.state()).toBe('read');
    expect(seqs(log.pending(CHAIN))).toEqual([12n, 11n, 2n]);
    expect(integrity(capture)).toHaveLength(1);
    // A later refresh lists only what is newer than it read, less the lag: a file landing late within it is read.
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 13n, 1)], { at: at - 2 * MINUTE });
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([13n, 12n, 11n, 2n]);
  });

  it('with no sound snapshot, a start reads a day of heads files back', async () => {
    const store = createFakeWriteOnceStore();
    const at = START.getTime();
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 1n, 1)], { at: at - 25 * HOUR });
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 2n, 1)], { at: at - 23 * HOUR });
    const { log } = witnessOn(store, { withSnapshots: false });
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([2n]);
  });

  it('a name dated past the clock is the alarm and passed over', async () => {
    const store = createFakeWriteOnceStore();
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 7n, 1)], {
      at: START.getTime() + 10 * MINUTE,
    });
    const { log, capture } = witnessOn(store);
    await log.refresh();
    expect(log.pending(CHAIN)).toEqual([]);
    expect(integrity(capture).map(({ reason }) => reason)).toEqual(['future']);
  });

  it('a rebase dated after a head sets it aside; one dated before leaves it', () => {
    const { log } = witnessOn();
    log.soon(CHAIN, head(5n, 1));
    log.soon(OTHER, head(5n, 1));
    log.useAnchors(
      anchorsWith(
        new Map([
          [ORG, new Date(START.getTime() + 1)],
          [OTHER_ORG, new Date(START.getTime() - 1)],
        ]),
      ),
    );
    expect(log.pending(CHAIN)).toEqual([]);
    expect(seqs(log.pending(OTHER))).toEqual([5n]);
  });

  it('holds only heads above the chain’s anchor; prune lets go those at or below a place', () => {
    const { log } = witnessOn();
    for (const seq of [3n, 5n, 8n]) log.soon(CHAIN, head(seq, 1));
    log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 5n]])));
    expect(seqs(log.pending(CHAIN))).toEqual([8n]);
    log.soon(OTHER, head(2n, 1));
    log.soon(OTHER, head(4n, 1));
    log.prune(OTHER, 2n);
    expect(seqs(log.pending(OTHER))).toEqual([4n]);
  });

  it('a read failing is a warning, and past alertAfterMs of failing the alert; freshAt moves only on a whole read', async () => {
    const store = createFakeWriteOnceStore();
    const { log, capture, time } = witnessOn(store);
    store.instead.list = () => Promise.reject(new Error('store away'));
    expect(await log.refresh()).toEqual([]);
    expect(log.freshAt()).toBeUndefined();
    time.held.at += 16 * MINUTE;
    await log.refresh();
    expect(capture.lines().map(({ event }) => event)).toEqual([
      'audit.witness_read_failed',
      'audit.witness_read_failing',
    ]);
    delete store.instead.list;
    await log.refresh();
    expect(log.freshAt()).toEqual(new Date(time.held.at));
  });

  it('a refresh asked while one runs waits for the next one, shared by every caller meanwhile', async () => {
    const store = createFakeWriteOnceStore();
    const { log } = witnessOn(store);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    store.instead.list = async (start, most, after) => {
      const page = await store.real.list(start, most, after);
      await gate;
      return page;
    };
    const first = log.refresh();
    const second = log.refresh();
    const third = log.refresh();
    expect(second).toBe(third);
    // Lands after the first listed: only a refresh begun after the calls is sure to see it.
    await new Promise((resolve) => setTimeout(resolve, 5));
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 7n, 1)]);
    release();
    expect(await first).toEqual([]);
    expect(await second).toEqual([CHAIN]);
  });
});

describe('the witness log: memory and snapshots', () => {
  it('past what it may hold, the chain holding most lets its lowest head go, loudly, and reads beyondMemory until anchored past it', () => {
    const { log, capture } = witnessOn(undefined, { mostBytes: 3 * WITNESS_HEAD_BYTES });
    const anchored = new Map<string, bigint>();
    log.useAnchors(anchorsWith(new Map(), anchored));
    for (const seq of [1n, 2n, 3n]) log.soon(CHAIN, head(seq, 1));
    expect(log.beyondMemory(CHAIN)).toBe(false);
    log.soon(OTHER, head(1n, 1));
    expect(seqs(log.pending(CHAIN))).toEqual([3n, 2n]);
    expect(log.beyondMemory(CHAIN)).toBe(true);
    expect(log.beyondMemory(OTHER)).toBe(false);
    expect(capture.lines().map(({ event }) => event)).toContain('audit.witness_beyond_memory');
    anchored.set(ORG, 1n);
    expect(log.beyondMemory(CHAIN)).toBe(false);
  });

  it('the leader writes a snapshot of every head held, hourly, after a whole read; a copy that doesn’t lead never does', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const follower = witnessOn(store, { snapshots });
    follower.log.soon(CHAIN, head(5n, 1));
    await follower.log.refresh();
    await follower.log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toEqual([]);
    const time = clock();
    const leader = witnessOn(store, { snapshots, leads: true, time });
    await leader.log.flush();
    // Not before a whole read.
    expect(namesUnder(snapshots.files, 'snapshots')).toEqual([]);
    await leader.log.refresh();
    await leader.log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(1);
    leader.log.soon(OTHER, head(2n, 1));
    await leader.log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(1);
    time.held.at += HOUR;
    await leader.log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(2);
    // A start from it holds what the leader held.
    const fresh = witnessOn(createFakeWriteOnceStore(), { snapshots, time });
    await fresh.log.refresh();
    expect(seqs(fresh.log.pending(CHAIN))).toEqual([5n]);
    expect(seqs(fresh.log.pending(OTHER))).toEqual([2n]);
  });
});
