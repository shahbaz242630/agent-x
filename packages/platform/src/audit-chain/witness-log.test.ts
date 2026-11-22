import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it, vi } from 'vitest';

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

/** What a log may hold to keep `heads` heads: theirs, and the fingerprints' tenth on top (TR-3). */
const forHeads = (heads: number): number => Math.ceil((heads * WITNESS_HEAD_BYTES * 11) / 10);

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
      // Its whole hash as the anchors' log keeps it (TR-3: the base a confirming walk starts from).
      return seq === undefined ? undefined : { seq, hash: hash(Number(seq) + 100) };
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
  /** A web copy's: heads at or below the anchor let go as such. */
  readonly dropsAtAnchor?: boolean;
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
    dropsAtAnchor,
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
    // Left out unless a test says: the default is the copy that anchors.
    ...(dropsAtAnchor === undefined ? {} : { dropsAtAnchor }),
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

describe('SEC-DB-20 the witness log: writing', () => {
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

  it('drained writes every head noted, a `soon` one too, retrying a failed Put within the wait; past it, WitnessUnconfirmed', async () => {
    const { log, heads, time } = witnessOn(undefined, { waitMs: 300 });
    log.soon(CHAIN, head(5n, 1));
    let fails = 1;
    heads.instead.put = (name, bytes) => {
      if (fails > 0) {
        fails -= 1;
        time.held.at += 1000;
        return Promise.reject(new Error('store blip'));
      }
      return heads.real.put(name, bytes);
    };
    await expect(log.drained()).resolves.toBeUndefined();
    expect(namesUnder(heads.files, 'heads')).toHaveLength(1);
    // Nothing waiting: at once.
    await expect(log.drained()).resolves.toBeUndefined();
    heads.instead.put = () => Promise.reject(new Error('store down'));
    log.soon(OTHER, head(2n, 1));
    await expect(log.drained()).rejects.toBeInstanceOf(WitnessUnconfirmed);
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

  // Twenty thousand heads signed into three files: slow on a busy runner.
  it(
    'TR-11: a `now` head goes in the next Put ahead of a queued `soon` backlog, which still drains after it',
    { timeout: 30_000 },
    async () => {
      // Two files' worth of decisions and more (10,000 lines a file), so a queue taken in order would write the stop third.
      const backlog = 20_001;
      const { log, heads } = witnessOn(undefined, { waitMs: 60_000, mostBytes: forHeads(backlog + 10) });
      let release: () => void = () => undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let putStarted: () => void = () => undefined;
      const started = new Promise<void>((resolve) => {
        putStarted = resolve;
      });
      heads.instead.put = async (name, bytes) => {
        putStarted();
        await gate;
        return heads.real.put(name, bytes);
      };
      // Highest first, so each goes to the end of the chain's list (highest first) rather than shifting it all.
      for (let seq = backlog; seq >= 1; seq -= 1) log.soon(CHAIN, head(BigInt(seq), seq % 250));
      const flushed = log.flush();
      await started;
      // The first file of decisions is in flight; a stop is noted behind the rest of them.
      const stop = log.now(OTHER, head(1n, 7));
      release();
      await stop;
      expect(heads.calls.puts).toBe(2);
      await flushed;
      await log.flush();
      // Every decision went too: three files, and nothing left waiting for another.
      expect(namesUnder(heads.files, 'heads')).toHaveLength(3);
      await log.flush();
      expect(heads.calls.puts).toBe(3);
    },
  );
});

describe('SEC-DB-20 the witness log: reading', () => {
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
    // Each line dated when its file was named, as every writer dates them.
    const plant = (into: Map<string, Buffer>, folder: string, kind: FileKind, seq: bigint, fileAt: number) =>
      planted(into, folder, kind, [line(`organisation:${ORG}`, seq, 1, new Date(fileAt))], { at: fileAt });
    await plant(snapshots.files, 'snapshots', SNAPSHOT, 1n, at - 3 * HOUR);
    await plant(snapshots.files, 'snapshots', SNAPSHOT, 2n, at - HOUR);
    // A spoiled newer one is passed over, said.
    await planted(
      snapshots.files,
      'snapshots',
      SNAPSHOT,
      [line(`organisation:${ORG}`, 3n, 1, new Date(at - 30 * MINUTE))],
      {
        at: at - 30 * MINUTE,
        signing: otherKeys,
      },
    );
    await plant(store.files, 'heads', HEADS, 10n, at - HOUR - 10 * MINUTE);
    await plant(store.files, 'heads', HEADS, 11n, at - HOUR - 2 * MINUTE);
    await plant(store.files, 'heads', HEADS, 12n, at - MINUTE);
    const { log, capture } = witnessOn(store, { snapshots });
    expect(log.state()).toBe('unread');
    await log.refresh();
    expect(log.state()).toBe('read');
    expect(seqs(log.pending(CHAIN))).toEqual([12n, 11n, 2n]);
    expect(integrity(capture)).toHaveLength(1);
    // A later refresh lists only what is newer than it read, less the lag: a file landing late within it is read.
    await plant(store.files, 'heads', HEADS, 13n, at - 2 * MINUTE);
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([13n, 12n, 11n, 2n]);
  });

  it('with no sound snapshot, a start reads a day of heads files back', async () => {
    const store = createFakeWriteOnceStore();
    const at = START.getTime();
    for (const [seq, fileAt] of [
      [1n, at - 25 * HOUR],
      [2n, at - 23 * HOUR],
    ] as const) {
      await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, seq, 1, new Date(fileAt))], {
        at: fileAt,
      });
    }
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

  it('asked for the highest few, gives those that stand, however many are held; a rebase found among them sets aside all before it', () => {
    const time = clock();
    const { log } = witnessOn(undefined, { time });
    for (const seq of [1n, 2n, 3n, 4n, 5n]) {
      log.soon(CHAIN, head(seq, 1));
      time.held.at += 1000;
    }
    expect(seqs(log.pending(CHAIN, 2))).toEqual([5n, 4n]);
    // A rebase dated between the third head and the fourth: the three before it go, the two after stand.
    log.useAnchors(anchorsWith(new Map([[ORG, new Date(START.getTime() + 2500)]])));
    expect(seqs(log.pending(CHAIN, 3))).toEqual([5n, 4n]);
    expect(seqs(log.pending(CHAIN))).toEqual([5n, 4n]);
  });

  it('the copy that anchors keeps a head at or below an anchor until it confirmed it (prune, those heads alone); a web copy lets it go', () => {
    const jobs = witnessOn();
    const web = witnessOn(undefined, { dropsAtAnchor: true });
    for (const { log } of [jobs, web]) {
      for (const seq of [3n, 5n, 8n]) log.soon(CHAIN, head(seq, 1));
      log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 5n]])));
    }
    // An anchor of its own is no proof of a head read in late: held, for the probe to judge.
    expect(seqs(jobs.log.pending(CHAIN))).toEqual([8n, 5n, 3n]);
    expect(seqs(web.log.pending(CHAIN))).toEqual([8n]);
    // Let go only the very heads confirmed: one at the same place with another hash stays.
    jobs.log.prune(CHAIN, [head(5n, 1), head(3n, 9)]);
    expect(seqs(jobs.log.pending(CHAIN))).toEqual([8n, 3n]);
    jobs.log.prune(OTHER, [head(3n, 1)]);
    jobs.log.prune(CHAIN, []);
    expect(seqs(jobs.log.pending(CHAIN))).toEqual([8n, 3n]);
  });

  it('two heads witnessed at one place with different hashes prove a fork: the alarm at once, no read; the same head twice, none', async () => {
    const store = createFakeWriteOnceStore();
    await planted(store.files, 'heads', HEADS, [
      line(`organisation:${ORG}`, 7n, 1),
      line(`organisation:${ORG}`, 7n, 1),
    ]);
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 7n, 2)], { at: START.getTime() - 1000 });
    const { log, capture } = witnessOn(store);
    await log.refresh();
    expect(capture.lines().filter((one) => one.event === 'audit.integrity_failed' && one.check === 'witness')).toEqual([
      expect.objectContaining({ reason: 'fork', seq: '7', orgId: ORG, chain: 'organisation' }),
    ]);
    // Both kept: the probe finds which the chain holds.
    expect(log.pending(CHAIN).map(({ hash }) => hash[0])).toEqual([1, 2]);
  });

  it('a pass cut short never moves the next one past the older files it didn’t reach, nor does this copy’s own write', async () => {
    const store = createFakeWriteOnceStore();
    const time = clock();
    const { log } = witnessOn(store, { time });
    await log.refresh();
    const at = START.getTime();
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 1n, 1)], { at: at + MINUTE });
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 2n, 1)], { at: at + 10 * MINUTE });
    time.held.at = at + 11 * MINUTE;
    // The newest read, the older one fails: the pass ends cut short.
    store.instead.getAtMost = (name, most) =>
      name.includes(String(9_999_999_999_999 - (at + MINUTE)))
        ? Promise.reject(new Error('blip'))
        : store.real.getAtMost(name, most);
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([2n]);
    delete store.instead.getAtMost;
    // This copy's own write, newer than both, moves nothing either.
    log.soon(OTHER, head(1n, 1));
    await log.flush();
    time.held.at = at + 20 * MINUTE;
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([2n, 1n]);
  });

  it('a head another copy named early that lands after this copy’s own later write is still read', async () => {
    const store = createFakeWriteOnceStore();
    const time = clock();
    const { log } = witnessOn(store, { time });
    await log.refresh();
    const at = START.getTime();
    time.held.at = at + 10 * MINUTE;
    log.soon(OTHER, head(1n, 1));
    await log.flush();
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 4n, 1)], { at: at + MINUTE });
    time.held.at = at + 11 * MINUTE;
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([4n]);
  });

  const skews = (capture: LogCapture) => capture.lines().filter((one) => one.event === 'audit.witness_clock_skew');

  it('TR-12: copies 20 minutes slow and 20 minutes fast name by the store’s time, asked before their first file: read by the next pass, said', async () => {
    const reading = clock();
    // The store's clock is the honest reader's; its answers carry it, as Azure's Date.
    const store = createFakeWriteOnceStore({ now: () => reading.held.at });
    const reader = witnessOn(store, { time: reading });
    await reader.log.refresh();
    const slow = witnessOn(store, { time: clock(START.getTime() - 20 * MINUTE) });
    const fast = witnessOn(store, { time: clock(START.getTime() + 20 * MINUTE) });
    for (const one of [reading, slow.time, fast.time]) one.held.at += MINUTE;
    const calls: string[] = [];
    store.instead.list = (...asked) => {
      calls.push('list');
      return store.real.list(...asked);
    };
    store.instead.put = (name, bytes) => {
      calls.push('put');
      return store.real.put(name, bytes);
    };
    await slow.log.now(CHAIN, head(5n, 1));
    // The store's time asked before the first file.
    expect(calls).toEqual(['list', 'put']);
    // Noted before then, yet dated at its file's time by the store's clock, never by its slow one; here as there.
    expect(slow.log.pending(CHAIN)).toEqual([{ seq: 5n, hash: hash(1), at: START.getTime() + MINUTE + 1000 }]);
    await slow.log.now(CHAIN, head(6n, 1));
    // Noted before its clock was set: dated at its file's name, never past it, so the file stays sound.
    await fast.log.now(OTHER, head(2n, 1));
    reading.held.at += 10_000;
    await reader.log.refresh();
    expect(reader.log.pending(CHAIN)).toEqual([
      { seq: 6n, hash: hash(1), at: START.getTime() + MINUTE + 1000 },
      { seq: 5n, hash: hash(1), at: START.getTime() + MINUTE + 1000 },
    ]);
    // Each set late, never early: the latest the store's whole-second Date allows after the call left.
    expect(reader.log.pending(OTHER)).toEqual([{ seq: 2n, hash: hash(1), at: START.getTime() + MINUTE + 1000 }]);
    expect(integrity(reader.capture)).toEqual([]);
    // Each wrong clock said by its own copy, as its offset from the store's.
    expect(skews(slow.capture)).toEqual([expect.objectContaining({ level: 'error', offsetMs: 20 * MINUTE + 1000 })]);
    expect(skews(fast.capture)).toEqual([expect.objectContaining({ offsetMs: -20 * MINUTE + 1000 })]);
    expect(integrity(fast.capture).map(({ reason }) => reason)).toEqual(['clock_skew']);
    // Said at most once a minute however many Puts tell it again.
    await fast.log.now(OTHER, head(3n, 1));
    expect(skews(fast.capture)).toHaveLength(1);
    expect(skews(reader.capture)).toEqual([]);
  });

  it('TR-12: freshAt is by this copy’s own clock: a right clock against a Date in whole seconds passes a read-after-walk check, and stays fresh', async () => {
    const time = clock(START.getTime() + 999);
    // Azure's Date: whole seconds, rounded down, so the offset is nearly a second back with a right clock.
    const store = createFakeWriteOnceStore({ now: () => Math.floor(time.held.at / 1000) * 1000 });
    const { log } = witnessOn(store, { time });
    await log.refresh();
    time.held.at += 10;
    // The anchor check: a read that began after its walk began.
    const walkBegan = time.now().getTime();
    await log.refresh();
    expect(log.freshAt()?.getTime()).toBeGreaterThanOrEqual(walkBegan);
    // The hand-off: how long ago, by its own clock.
    expect(time.now().getTime() - (log.freshAt()?.getTime() ?? 0)).toBe(0);
    // A right clock is left as it stands: heads dated by it exactly, as before, so a rebase just before stays before.
    log.soon(CHAIN, head(1n, 1));
    expect(log.pending(CHAIN)[0]?.at).toBe(time.held.at);
  });

  /**
   * A copy whose clock is `off` from the store's true time, its store's Date in whole seconds rounded down, every list
   * taking 1.5 s (both clocks run on).
   */
  function offBy(off: number) {
    const truth = clock(START.getTime() + 400);
    const time = clock(truth.held.at + off);
    const store = createFakeWriteOnceStore({ now: () => Math.floor(truth.held.at / 1000) * 1000 });
    store.instead.list = (...asked) => {
      truth.held.at += 1500;
      time.held.at += 1500;
      return store.real.list(...asked);
    };
    return { truth, ...witnessOn(store, { time }) };
  }

  it.each([
    ['right', 0],
    ['59 seconds slow', -59_000],
    ['59 seconds fast', 59_000],
  ])(
    'TR-12: a clock %s, within a minute of the store’s Date, is left as it stands, however long its list took',
    async (_, off) => {
      const { log, time, capture } = offBy(off);
      await log.refresh();
      log.soon(CHAIN, head(1n, 1));
      expect(log.pending(CHAIN)[0]?.at).toBe(time.held.at);
      expect(skews(capture)).toEqual([]);
    },
  );

  it.each([
    ['slow', -20 * MINUTE],
    ['fast', 20 * MINUTE],
  ])(
    'TR-12: a clock 20 minutes %s is set late, never early: its heads dated at or after the store’s true time',
    async (_, off) => {
      const { log, truth, capture } = offBy(off);
      await log.refresh();
      log.soon(CHAIN, head(1n, 1));
      const at = log.pending(CHAIN)[0]?.at ?? 0;
      expect(at).toBeGreaterThanOrEqual(truth.held.at);
      // Late by no more than the list's trip and the Date's second.
      expect(at - truth.held.at).toBeLessThanOrEqual(1500 + 1000);
      expect(skews(capture)).toHaveLength(1);
    },
  );

  it('TR-12: a head noted before the store’s time was known is re-dated by it once known: a failed Put after, then a snapshot, carries that', async () => {
    const time = clock(START.getTime() - 10 * MINUTE);
    const heads = createFakeWriteOnceStore({ now: () => time.held.at + 10 * MINUTE });
    const { log, snapshots } = witnessOn(heads, { time, leads: true });
    log.soon(CHAIN, head(5n, 1));
    await log.refresh();
    heads.instead.put = () => Promise.reject(new Error('store away'));
    await log.flush();
    expect(heads.calls.puts).toBe(1);
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(1);
    const reader = witnessOn(createFakeWriteOnceStore(), { snapshots });
    await reader.log.refresh();
    // Noted at nine o'clock by the store's clock (set late by its Date's second), ten minutes on from this copy's.
    expect(reader.log.pending(CHAIN)).toEqual([{ seq: 5n, hash: hash(1), at: START.getTime() + 1000 }]);
  });

  it('TR-12: witnessed gives the heads on this copy’s own clock, for its own accepts to set against: a copy three minutes fast', async () => {
    const time = clock(START.getTime() + 3 * MINUTE);
    const store = createFakeWriteOnceStore({ now: () => time.held.at - 3 * MINUTE });
    const { log } = witnessOn(store, { time });
    await log.refresh();
    log.soon(CHAIN, head(5n, 1));
    expect(log.witnessed(CHAIN)).toEqual([{ seq: 5n, hash: hash(1), at: time.held.at }]);
    // heldTo's whole set, a released compact head too, each shifted the same.
    log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 2n]])));
    log.soon(CHAIN, head(6n, 6));
    log.release(CHAIN, [head(5n, 1)]);
    expect(log.witnessed(CHAIN)).toEqual(
      log.heldTo(CHAIN).map((one) => ({ ...one, at: one.at - (START.getTime() + 1000 - time.held.at) })),
    );
    expect(log.witnessed(CHAIN).map(({ seq, hash: part, at }) => [seq, part.length, at])).toEqual([
      [6n, 32, time.held.at],
      [5n, 16, time.held.at],
    ]);
    // pending's, by the store's clock (set late: the latest its whole-second Date allows).
    expect(log.pending(CHAIN)[0]?.at).toBe(START.getTime() + 1000);
  });

  it('TR-12: a copy ten minutes slow reads its newest snapshot at start by the store’s time: no `future` alarm', async () => {
    const at = START.getTime();
    const snapshots = createFakeWriteOnceStore();
    await planted(snapshots.files, 'snapshots', SNAPSHOT, [line(`organisation:${ORG}`, 7n, 1)], { at });
    const heads = createFakeWriteOnceStore({ now: () => at + MINUTE });
    const { log, capture } = witnessOn(heads, { snapshots, time: clock(at - 10 * MINUTE) });
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([7n]);
    // Its own clock said, as it is wrong; the snapshot not.
    expect(integrity(capture).map(({ reason }) => reason)).toEqual(['clock_skew']);
  });

  it('TR-12: the store’s time not to be had, no file is written and nothing is told it went; back, it goes', async () => {
    const time = clock();
    const store = createFakeWriteOnceStore({ now: () => time.held.at });
    store.instead.list = () => Promise.reject(new Error('store away'));
    const { log, capture } = witnessOn(store, { time });
    await expect(log.now(CHAIN, head(5n, 1))).rejects.toBeInstanceOf(WitnessUnconfirmed);
    expect(store.calls.puts).toBe(0);
    expect(log.writesSound()).toBe(false);
    expect(capture.lines().map(({ event }) => event)).toContain('audit.witness_write_failed');
    delete store.instead.list;
    time.held.at += 1000;
    await expect(log.settled([CHAIN])).resolves.toBeUndefined();
    expect(store.calls.puts).toBe(1);
  });

  it('TR-12: a file read whose name is past the clocks’ spread from when the store says it landed is said; one within it, not', async () => {
    const at = START.getTime();
    for (const [namedAt, said] of [
      [at + 4 * MINUTE, [6 * MINUTE]],
      [at - 8 * MINUTE, [-6 * MINUTE]],
      [at - 3 * MINUTE, []],
    ] as const) {
      const store = createFakeWriteOnceStore();
      const name = await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 4n, 1, new Date(namedAt))], {
        at: namedAt,
      });
      store.created.set(name, at - 2 * MINUTE);
      const { log, capture } = witnessOn(store);
      await log.refresh();
      expect(seqs(log.pending(CHAIN))).toEqual([4n]);
      expect(skews(capture).map(({ skewMs }) => skewMs)).toEqual(said);
    }
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
      // The heads' list alone: the set-aside list each refresh reads first (TR-14) says nothing of them.
      if (start.includes('/heads/')) await gate;
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

  it('writesSound: false once a heads Put fails, until one goes; false while a `now` head waits past its wait', async () => {
    const store = createFakeWriteOnceStore();
    const { log, time } = witnessOn(store);
    expect(log.writesSound()).toBe(true);
    store.instead.put = () => Promise.reject(new Error('store down'));
    log.soon(CHAIN, head(3n, 3));
    await log.flush();
    expect(log.writesSound()).toBe(false);
    delete store.instead.put;
    await log.flush();
    expect(log.writesSound()).toBe(true);
    // A `now` head unconfirmed: sound within its wait, not past it.
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    store.instead.put = async (name, bytes) => {
      await held;
      return store.real.put(name, bytes);
    };
    log.note(CHAIN, head(4n, 4), 'now');
    expect(log.writesSound()).toBe(true);
    time.held.at += 6_000;
    expect(log.writesSound()).toBe(false);
    release();
    await log.flush();
    expect(log.writesSound()).toBe(true);
  });

  it('refreshWhole says whether the read begun after the call ended whole (TR-1 F.6: the gate sends on no failed one)', async () => {
    const store = createFakeWriteOnceStore();
    const { log } = witnessOn(store);
    expect(await log.refreshWhole()).toBe(true);
    store.instead.list = () => Promise.reject(new Error('store away'));
    expect(await log.refreshWhole()).toBe(false);
    delete store.instead.list;
    expect(await log.refreshWhole()).toBe(true);
  });
});

describe('SEC-DB-20 the witness log: memory and snapshots', () => {
  it('a thousand heads let go write the leader’s next snapshot before the hour, at most one a quarter hour, so a restart doesn’t confirm them again', async () => {
    const snapshots = createFakeWriteOnceStore();
    const time = clock();
    const { log } = witnessOn(createFakeWriteOnceStore(), { snapshots, leads: true, time });
    await log.refresh();
    log.soon(CHAIN, head(1n, 1));
    await log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(1);
    const many = Array.from({ length: 1_000 }, (_, at) => head(BigInt(at + 2), 1));
    for (const one of many.slice(0, 999)) log.soon(CHAIN, one);
    log.prune(CHAIN, many.slice(0, 999));
    await log.flush();
    // 999 let go: not yet.
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(1);
    log.soon(CHAIN, many[999] ?? head(1_001n, 1));
    log.prune(CHAIN, [many[999] ?? head(1_001n, 1)]);
    await log.flush();
    // A thousand, within a quarter hour of the last: not yet.
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(1);
    time.held.at += 15 * MINUTE;
    log.soon(CHAIN, head(1_002n, 1));
    await log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(2);
    // Another thousand let go at once after it: the next waits its quarter hour too, the hour as ever.
    const more = Array.from({ length: 1_000 }, (_, at) => head(BigInt(at + 2_000), 1));
    for (const one of more) log.soon(CHAIN, one);
    log.prune(CHAIN, more);
    time.held.at += 15 * MINUTE - 1;
    await log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(2);
    time.held.at += 1;
    log.soon(CHAIN, head(3_002n, 1));
    await log.flush();
    expect(namesUnder(snapshots.files, 'snapshots')).toHaveLength(3);
  });

  it('past what it may hold, the chain holding most lets its lowest head go, loudly, and reads beyondMemory until a rebase: anchors and prunes clear nothing, a snapshot keeps it', async () => {
    const snapshots = createFakeWriteOnceStore();
    const time = clock();
    const { log, capture } = witnessOn(undefined, { mostBytes: forHeads(3), snapshots, leads: true, time });
    const rebases = new Map<string, Date>();
    log.useAnchors(anchorsWith(rebases, new Map([[ORG, 9n]])));
    for (const seq of [1n, 2n, 3n]) log.soon(CHAIN, head(seq, 1));
    expect(log.beyondMemory(CHAIN)).toBe(false);
    log.soon(OTHER, head(1n, 1));
    expect(seqs(log.pending(CHAIN))).toEqual([3n, 2n]);
    expect(log.beyondMemory(CHAIN)).toBe(true);
    expect(log.beyondMemory(OTHER)).toBe(false);
    expect(capture.lines().map(({ event }) => event)).toContain('audit.witness_beyond_memory');
    // Anchored past it, or every head held confirmed: still missing heads it can't check.
    log.prune(CHAIN, [head(3n, 1), head(2n, 1)]);
    expect(log.beyondMemory(CHAIN)).toBe(true);
    // The leader's snapshot carries it: a start from it holds the chain as missing heads at once.
    await log.refresh();
    await log.flush();
    const restarted = witnessOn(createFakeWriteOnceStore(), { snapshots, time });
    await restarted.log.refresh();
    expect(restarted.log.beyondMemory(CHAIN)).toBe(true);
    expect(restarted.log.beyondMemory(OTHER)).toBe(false);
    // A rebase after it (the sanctioned way back) sets it aside.
    rebases.set(ORG, new Date(time.held.at + 1));
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

describe('TR-3 the witness log: dates, memory, Puts and replays', () => {
  it('a line dated past its file’s name beyond the clocks’ spread spoils the file; one within it counts, dated at the name, so a rebase after sets it aside', async () => {
    const store = createFakeWriteOnceStore();
    const fileAt = START.getTime() - MINUTE;
    const far = new Date('2099-01-01T00:00:00Z');
    await planted(store.files, 'heads', HEADS, [line(`organisation:${ORG}`, 7n, 1, far)], { at: fileAt });
    // Control: past its name by less than the spread.
    const near = new Date(fileAt + 4 * MINUTE);
    await planted(store.files, 'heads', HEADS, [line(`organisation:${OTHER_ORG}`, 7n, 1, near)], { at: fileAt - 1 });
    const { log, capture } = witnessOn(store);
    await log.refresh();
    expect(log.pending(CHAIN)).toEqual([]);
    expect(integrity(capture).map(({ reason }) => reason)).toEqual(['spoiled']);
    expect(log.pending(OTHER).map(({ seq, at }) => [seq, at])).toEqual([[7n, fileAt - 1]]);
    log.useAnchors(anchorsWith(new Map([[OTHER_ORG, new Date(fileAt)]])));
    expect(log.pending(OTHER)).toEqual([]);
  });

  it('gives way from the organisation chain holding most, never the platform’s while one is held, its lowest above the anchor first', () => {
    const { log } = witnessOn(undefined, { mostBytes: forHeads(4) });
    log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 2n]])));
    for (const seq of [1n, 2n, 3n]) log.soon(PLATFORM, head(seq, 1));
    log.soon(CHAIN, head(1n, 1));
    log.soon(CHAIN, head(3n, 1));
    expect(seqs(log.pending(PLATFORM))).toEqual([3n, 2n, 1n]);
    expect(seqs(log.pending(CHAIN))).toEqual([1n]);
    expect(log.beyondMemory(CHAIN)).toBe(true);
    expect(log.beyondMemory(PLATFORM)).toBe(false);
    // The anchor its fingerprint went above kept, for a walk confirming it to start from.
    expect(log.baseBelow(CHAIN, 3n)).toEqual({ seq: 2n, hash: hash(102) });
    // Only the platform's held: it gives way then.
    const alone = witnessOn(undefined, { mostBytes: forHeads(2) });
    for (const seq of [1n, 2n, 3n]) alone.log.soon(PLATFORM, head(seq, 1));
    expect(alone.log.beyondMemory(PLATFORM)).toBe(true);
  });

  it('each head let go leaves a fingerprint; a walk held to them all, from below the lowest to past the highest, sets the mark aside; one short of either, or not held to one, leaves it', async () => {
    const snapshots = createFakeWriteOnceStore();
    const time = clock();
    // Room for 4 heads and 2 fingerprints.
    const { log } = witnessOn(undefined, { mostBytes: forHeads(4), snapshots, leads: true, time });
    for (const seq of [5n, 6n, 7n, 8n, 9n, 10n]) log.soon(CHAIN, head(seq, Number(seq)));
    expect(seqs(log.pending(CHAIN))).toEqual([10n, 9n, 8n, 7n]);
    const prints = log.fingerprints(CHAIN);
    expect(prints.map(({ seq, hash: prefix }) => [seq, prefix.toString('hex')])).toEqual([
      [5n, hash(5).subarray(0, 16).toString('hex')],
      [6n, hash(6).subarray(0, 16).toString('hex')],
    ]);
    expect(log.fingerprints(OTHER)).toEqual([]);
    expect(log.walkedPast(CHAIN, 5n, 10n, prints)).toBe(true);
    expect(log.walkedPast(CHAIN, 4n, 5n, prints)).toBe(true);
    expect(log.walkedPast(CHAIN, 4n, 10n, prints.slice(1))).toBe(true);
    // The leader's snapshot keeps the lowest and the fingerprints too: a start from it is set aside the same way.
    await log.refresh();
    await log.flush();
    const restarted = witnessOn(createFakeWriteOnceStore(), { snapshots, time });
    await restarted.log.refresh();
    expect(restarted.log.beyondMemory(CHAIN)).toBe(true);
    expect(restarted.log.fingerprints(CHAIN)).toEqual(prints);
    expect(restarted.log.walkedPast(CHAIN, 4n, 6n, prints)).toBe(false);
    expect(log.walkedPast(CHAIN, 4n, 6n, prints)).toBe(false);
    expect(log.beyondMemory(CHAIN)).toBe(false);
    expect(log.fingerprints(CHAIN)).toEqual([]);
  });

  it('fingerprints past their share let the chain holding most go, an organisation’s before the platform’s: said, and a rebase alone sets it aside', () => {
    const time = clock();
    const rebases = new Map<string, Date>();
    // Room for 2 heads, and one fingerprint: forHeads(2) / 11 bytes, of 32 each.
    const { log, capture } = witnessOn(undefined, { mostBytes: forHeads(2), time });
    log.useAnchors(anchorsWith(rebases));
    log.soon(PLATFORM, head(1n, 1));
    log.soon(PLATFORM, head(2n, 2));
    log.soon(PLATFORM, head(3n, 3));
    expect(log.fingerprints(PLATFORM).map(({ seq }) => seq)).toEqual([1n]);
    log.soon(CHAIN, head(1n, 1));
    log.soon(CHAIN, head(2n, 2));
    // CHAIN's head went, and its fingerprint was one too many: its fingerprints let go, the platform's kept.
    expect(log.fingerprints(CHAIN)).toEqual([]);
    expect(log.fingerprints(PLATFORM).map(({ seq }) => seq)).toEqual([1n]);
    expect(log.walkedPast(CHAIN, 0n, 100n, [])).toBe(true);
    // Said once: a head it let go after (its 2) leaves no fingerprint to overflow again.
    expect(capture.lines().filter(({ fingerprints }) => fingerprints === false)).toEqual([
      expect.objectContaining({ event: 'audit.witness_beyond_memory', chain: `organisation:${ORG}` }),
    ]);
    rebases.set(ORG, new Date(time.held.at + 1));
    expect(log.beyondMemory(CHAIN)).toBe(false);
  });

  it('a rebase after the heads let go sets their fingerprints aside too, asked first', () => {
    const time = clock();
    const rebases = new Map<string, Date>();
    const { log } = witnessOn(undefined, { mostBytes: forHeads(2), time });
    log.useAnchors(anchorsWith(rebases));
    for (const seq of [1n, 2n, 3n]) log.soon(CHAIN, head(seq, 1));
    expect(log.fingerprints(CHAIN).map(({ seq }) => seq)).toEqual([1n]);
    rebases.set(ORG, new Date(time.held.at + 1));
    expect(log.fingerprints(CHAIN)).toEqual([]);
  });

  it('holds what its share says, past ten heads too: the fingerprints’ tenth taken from it', () => {
    const { log } = witnessOn(undefined, { mostBytes: forHeads(20) });
    for (let seq = 1n; seq <= 20n; seq += 1n) log.soon(CHAIN, head(seq, 1));
    expect(log.beyondMemory(CHAIN)).toBe(false);
    log.soon(CHAIN, head(21n, 1));
    expect(log.beyondMemory(CHAIN)).toBe(true);
  });

  it('a heads file can’t carry a fingerprint: only a snapshot does', async () => {
    const store = createFakeWriteOnceStore();
    const at = START.getTime() - MINUTE;
    const print = JSON.stringify({
      c: `organisation:${ORG}`,
      s: '4',
      x: '0'.repeat(32),
      t: new Date(at).toISOString(),
    });
    const released = JSON.stringify({
      c: `organisation:${ORG}`,
      s: '3',
      r: '0'.repeat(32),
      t: new Date(at).toISOString(),
    });
    await planted(store.files, 'heads', HEADS, [print, released, line(`organisation:${ORG}`, 5n, 1, new Date(at))], {
      at,
    });
    const { log } = witnessOn(store, { mostBytes: forHeads(2) });
    await log.refresh();
    expect(seqs(log.pending(CHAIN))).toEqual([5n]);
    expect(log.fingerprints(CHAIN)).toEqual([]);
    // Its own head let go: its fingerprint alone, none from the file.
    log.soon(CHAIN, head(6n, 6));
    log.soon(CHAIN, head(7n, 7));
    expect(log.fingerprints(CHAIN).map(({ seq }) => seq)).toEqual([5n]);
  });

  it('a snapshot’s mark with no lowest is set aside by a rebase alone; one whose lowest is past its highest spoils it', async () => {
    const at = START.getTime() - MINUTE;
    const lost = (more: Record<string, string>) =>
      JSON.stringify({ c: `organisation:${ORG}`, l: '9', ...more, t: new Date(at).toISOString() });
    const snapshots = createFakeWriteOnceStore();
    await planted(snapshots.files, 'snapshots', SNAPSHOT, [lost({})], { at });
    const { log } = witnessOn(createFakeWriteOnceStore(), { snapshots });
    await log.refresh();
    expect(log.walkedPast(CHAIN, 0n, 100n, [])).toBe(true);
    const bad = createFakeWriteOnceStore();
    await planted(bad.files, 'snapshots', SNAPSHOT, [lost({ f: '10' })], { at });
    const spoiled = witnessOn(createFakeWriteOnceStore(), { snapshots: bad });
    await spoiled.log.refresh();
    expect(spoiled.log.beyondMemory(CHAIN)).toBe(false);
    expect(integrity(spoiled.capture).map(({ reason }) => reason)).toEqual(['spoiled']);
  });

  it('crowded: the organisation chains holding more than one head, the most first, never the platform’s', () => {
    const { log } = witnessOn();
    for (const seq of [1n, 2n, 3n]) log.soon(PLATFORM, head(seq, 1));
    for (const seq of [1n, 2n]) log.soon(CHAIN, head(seq, 1));
    for (const seq of [1n, 2n, 3n]) log.soon(OTHER, head(seq, 1));
    log.soon({ kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-000000000003' }, head(1n, 1));
    expect(log.crowded(5)).toEqual([OTHER, CHAIN]);
    expect(log.crowded(1)).toEqual([OTHER]);
  });

  it('a Put not answered within a minute failed: its heads go again in a file named afresh', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const { log, heads, capture } = witnessOn(undefined, { waitMs: 10 * MINUTE });
      let hung = true;
      let putStarted: () => void = () => undefined;
      const started = new Promise<void>((resolve) => {
        putStarted = resolve;
      });
      heads.instead.put = (name, bytes) => {
        putStarted();
        return hung ? new Promise<void>(() => undefined) : heads.real.put(name, bytes);
      };
      const waiting = log.now(CHAIN, head(5n, 1));
      await started;
      await vi.advanceTimersByTimeAsync(MINUTE - 1);
      expect(capture.lines().map(({ event }) => event)).not.toContain('audit.witness_write_failed');
      hung = false;
      await vi.advanceTimersByTimeAsync(1);
      expect(capture.lines().map(({ event }) => event)).toContain('audit.witness_write_failed');
      await vi.advanceTimersByTimeAsync(1_000);
      await waiting;
      expect(namesUnder(heads.files, 'heads')).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('a head this process wrote already is not queued again (a replay’s); one not yet written is', async () => {
    const { log, heads } = witnessOn();
    await log.now(CHAIN, head(5n, 1));
    expect(heads.calls.puts).toBe(1);
    await log.now(CHAIN, head(5n, 1));
    log.soon(CHAIN, head(5n, 1));
    await log.flush();
    expect(heads.calls.puts).toBe(1);
    // Control: another head goes out; one noted twice before its Put goes in it.
    log.soon(CHAIN, head(6n, 2));
    log.soon(CHAIN, head(6n, 2));
    await log.flush();
    expect(heads.calls.puts).toBe(2);
    await log.now(CHAIN, head(6n, 2));
    expect(heads.calls.puts).toBe(2);
  });
});

describe('TR-3 heads released on a probe’s finding', () => {
  it('keep the anchor they went above, in the snapshot too, as the base a confirming walk starts from; let go with them, or by a rebase', async () => {
    const snapshots = createFakeWriteOnceStore();
    const time = clock();
    const rebases = new Map<string, Date>();
    const latest = new Map([[ORG, 2n]]);
    const { log } = witnessOn(undefined, { snapshots, leads: true, time });
    log.useAnchors(anchorsWith(rebases, latest));
    for (const seq of [3n, 4n, 5n]) log.soon(CHAIN, head(seq, Number(seq)));
    log.release(CHAIN, [head(3n, 3), head(4n, 4)]);
    latest.set(ORG, 6n);
    expect(log.baseBelow(CHAIN, 3n)).toEqual({ seq: 2n, hash: hash(102) });
    expect(log.baseBelow(CHAIN, 1n)).toBeUndefined();
    expect(log.baseBelow(OTHER, 9n)).toBeUndefined();
    await log.refresh();
    await log.flush();
    const restarted = witnessOn(createFakeWriteOnceStore(), { snapshots, time });
    await restarted.log.refresh();
    expect(restarted.log.baseBelow(CHAIN, 4n)).toEqual({ seq: 2n, hash: hash(102) });
    // Passed by a walk, the released heads go, and their base with them.
    restarted.log.walkedPast(CHAIN, 2n, 6n, restarted.log.fingerprints(CHAIN));
    expect(restarted.log.fingerprints(CHAIN)).toEqual([]);
    expect(restarted.log.baseBelow(CHAIN, 4n)).toBeUndefined();
    rebases.set(ORG, new Date(time.held.at + 1));
    expect(log.baseBelow(CHAIN, 3n)).toBeUndefined();
  });

  it('a snapshot’s base line with anything else on it spoils the snapshot', async () => {
    const at = START.getTime() - MINUTE;
    const base = (more: Record<string, string>) =>
      JSON.stringify({ c: `organisation:${ORG}`, b: '2', a: 'ab'.repeat(32), ...more, t: new Date(at).toISOString() });
    const good = createFakeWriteOnceStore();
    await planted(good.files, 'snapshots', SNAPSHOT, [base({})], { at });
    const { log, capture } = witnessOn(createFakeWriteOnceStore(), { snapshots: good });
    await log.refresh();
    expect(integrity(capture)).toEqual([]);
    const bad = createFakeWriteOnceStore();
    await planted(bad.files, 'snapshots', SNAPSHOT, [base({ s: '3' })], { at });
    const spoiled = witnessOn(createFakeWriteOnceStore(), { snapshots: bad });
    await spoiled.log.refresh();
    expect(integrity(spoiled.capture).map(({ reason }) => reason)).toEqual(['spoiled']);
  });

  const forks = (capture: LogCapture) =>
    capture.lines().filter((one) => one.event === 'audit.integrity_failed' && one.reason === 'fork');

  it('leave the list as compact heads every walk is held to; the same head noted again stays released, another at its place is a fork', () => {
    const { log, capture } = witnessOn();
    for (const seq of [3n, 4n, 5n]) log.soon(CHAIN, head(seq, Number(seq)));
    // No anchor known for the chain (never anchored, or its shard let go): nothing released.
    log.release(CHAIN, [head(3n, 3), head(4n, 4)]);
    expect(seqs(log.pending(CHAIN))).toEqual([5n, 4n, 3n]);
    // Anchored at 3: those above it alone.
    log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 3n]])));
    log.release(CHAIN, [head(3n, 3), head(4n, 4)]);
    expect(seqs(log.pending(CHAIN))).toEqual([5n, 3n]);
    log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 2n]])));
    log.release(CHAIN, [head(3n, 3)]);
    expect(seqs(log.pending(CHAIN))).toEqual([5n]);
    expect(log.beyondMemory(CHAIN)).toBe(false);
    expect(log.fingerprints(CHAIN).map(({ seq, hash: prefix }) => [seq, prefix.toString('hex')])).toEqual([
      [4n, hash(4).subarray(0, 16).toString('hex')],
      [3n, hash(3).subarray(0, 16).toString('hex')],
    ]);
    log.soon(CHAIN, head(4n, 4));
    expect(seqs(log.pending(CHAIN))).toEqual([5n]);
    expect(forks(capture)).toEqual([]);
    log.soon(CHAIN, head(3n, 9));
    expect(forks(capture).map(({ seq }) => seq)).toEqual(['3']);
    // One not held is not released.
    log.release(CHAIN, [head(7n, 7)]);
    expect(log.fingerprints(CHAIN)).toHaveLength(2);
  });

  it('a walk from the anchor held to them that passes them lets them go; one that began at or above, stopped below, or wasn’t held to them, none', () => {
    const { log } = witnessOn();
    log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 2n]])));
    for (const seq of [3n, 4n, 5n]) log.soon(CHAIN, head(seq, Number(seq)));
    log.release(CHAIN, [head(3n, 3), head(4n, 4)]);
    const asked = log.fingerprints(CHAIN);
    const three = asked.filter(({ seq }) => seq === 3n);
    // Began at 3: 3 is not its to pass. Stopped at 3: 4 not passed. Not held to 4: 4 stays.
    log.walkedPast(CHAIN, 3n, 3n, asked);
    expect(log.fingerprints(CHAIN)).toHaveLength(2);
    log.walkedPast(CHAIN, 0n, 9n, three);
    expect(log.fingerprints(CHAIN).map(({ seq }) => seq)).toEqual([4n]);
    expect(log.walkedPast(CHAIN, 3n, 4n, asked)).toBe(false);
    expect(log.fingerprints(CHAIN)).toEqual([]);
  });

  it('kept in the leader’s snapshot; past the compact heads’ share a head stays held; a rebase after one sets it aside', async () => {
    const snapshots = createFakeWriteOnceStore();
    const time = clock();
    const rebases = new Map<string, Date>();
    // Room for 2 heads and 1 compact one.
    const { log } = witnessOn(undefined, { mostBytes: forHeads(2), snapshots, leads: true, time });
    log.useAnchors(anchorsWith(rebases, new Map([[ORG, 2n]])));
    log.soon(CHAIN, head(3n, 3));
    log.soon(CHAIN, head(4n, 4));
    log.release(CHAIN, [head(3n, 3), head(4n, 4)]);
    expect(seqs(log.pending(CHAIN))).toEqual([3n]);
    expect(log.fingerprints(CHAIN).map(({ seq }) => seq)).toEqual([4n]);
    await log.refresh();
    await log.flush();
    const restarted = witnessOn(createFakeWriteOnceStore(), { snapshots, time });
    await restarted.log.refresh();
    expect(restarted.log.fingerprints(CHAIN)).toEqual(log.fingerprints(CHAIN));
    expect(seqs(restarted.log.pending(CHAIN))).toEqual([3n]);
    rebases.set(ORG, new Date(time.held.at + 1));
    expect(log.fingerprints(CHAIN)).toEqual([]);
  });
});

describe('SEC-DB-20 TR-9 one held set: heldTo', () => {
  it('gives the heads held and the compact ones together, the highest first, at most `most`; a released one stays in it', () => {
    const { log } = witnessOn();
    log.useAnchors(anchorsWith(new Map(), new Map([[ORG, 2n]])));
    for (const seq of [3n, 4n, 5n, 6n]) log.soon(CHAIN, head(seq, Number(seq)));
    // Nothing compact: the heads held, as pending gives them.
    expect(log.heldTo(CHAIN)).toEqual(log.pending(CHAIN));
    log.release(CHAIN, [head(3n, 3), head(5n, 5)]);
    expect(seqs(log.pending(CHAIN))).toEqual([6n, 4n]);
    const held = log.heldTo(CHAIN);
    expect(held.map(({ seq, hash: part }) => [seq, part.length])).toEqual([
      [6n, 32],
      [5n, 16],
      [4n, 32],
      [3n, 16],
    ]);
    expect(held[1]?.hash).toEqual(hash(5).subarray(0, 16));
    expect(seqs(log.heldTo(CHAIN, 2))).toEqual([6n, 5n]);
    expect(log.heldTo(OTHER)).toEqual([]);
  });

  it('holds the fingerprints of heads let go for memory while the chain is beyond memory', () => {
    const { log } = witnessOn(undefined, { mostBytes: forHeads(2) });
    for (const seq of [1n, 2n, 3n]) log.soon(CHAIN, head(seq, Number(seq)));
    expect(log.beyondMemory(CHAIN)).toBe(true);
    expect(seqs(log.heldTo(CHAIN))).toEqual([3n, 2n, 1n]);
    expect(log.heldTo(CHAIN)[2]?.hash).toHaveLength(16);
  });

  it('a web copy lets its released heads go at or below the anchor, as it lets heads go; the copy that anchors keeps them', async () => {
    const snapshots = createFakeWriteOnceStore();
    const time = clock();
    const latest = new Map([[ORG, 2n]]);
    const leader = witnessOn(undefined, { snapshots, leads: true, time });
    leader.log.useAnchors(anchorsWith(new Map(), latest));
    for (const seq of [3n, 4n, 5n]) leader.log.soon(CHAIN, head(seq, Number(seq)));
    leader.log.release(CHAIN, [head(3n, 3), head(4n, 4)]);
    await leader.log.refresh();
    await leader.log.flush();
    const web = witnessOn(createFakeWriteOnceStore(), { snapshots, time, dropsAtAnchor: true });
    web.log.useAnchors(anchorsWith(new Map(), latest));
    await web.log.refresh();
    expect(seqs(web.log.heldTo(CHAIN))).toEqual([5n, 4n, 3n]);
    latest.set(ORG, 4n);
    expect(seqs(web.log.heldTo(CHAIN))).toEqual([5n]);
    expect(seqs(leader.log.heldTo(CHAIN))).toEqual([5n, 4n, 3n]);
  });
});
