// TR-14 (threat R-12): the witness log's writers. Every file names its writer, the operator's signed list sets a
// writer aside (its files passed over by every copy, each said), a file written in a process's own name is the alarm,
// and the fork alarm names both heads' writers.
import { gunzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import type { Chain } from './chain.ts';
import { fileName, signedFile, WRITER_ID, writerOfName } from './signed-files.ts';
import { createWitnessLog, SNAPSHOT_WRITERS, type WitnessSigner } from './witness-log.ts';

const keys = createKeyProvider(
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 7)]]),
  })) satisfies KeyMaterial,
);

const ORG = '0199a0f0-0000-7000-8000-0000000000a1';
const OTHER_ORG = '0199a0f0-0000-7000-8000-0000000000a2';
const CHAIN: Chain = { kind: 'organisation', orgId: ORG };
const OTHER: Chain = { kind: 'organisation', orgId: OTHER_ORG };
const AT = new Date('2026-11-21T10:00:00.000Z');
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const REASON = 'INC-2026-11-21';

type Store = ReturnType<typeof createFakeWriteOnceStore>;

/** A copy of the API (or the operator's command) on the shared store, its lines captured. */
function copyOn(
  store: Store,
  {
    signer = 'app',
    snapshots,
    leads = false,
    time = { at: AT.getTime() },
    snapshotWriters,
  }: {
    signer?: WitnessSigner;
    snapshots?: Store;
    leads?: boolean;
    time?: { at: number };
    snapshotWriters?: boolean | undefined;
  } = {},
) {
  const capture = new LogCapture();
  const log = createWitnessLog({
    store: store.store,
    snapshots: snapshots?.store,
    keys,
    logger: testLogger(capture),
    now: () => new Date(time.at),
    epoch: 1,
    signer,
    writes: () => leads,
    alertAfterMs: 60_000,
    mostBytes: 1024 * 1024,
    waitMs: 500,
    ...(snapshotWriters === undefined ? {} : { snapshotWriters }),
  });
  const alarms = (reason: string) =>
    capture.lines().filter((one) => one.event === 'audit.integrity_failed' && one.reason === reason);
  return { log, capture, alarms };
}

const head = (seq: bigint, fill: number) => ({ seq, hash: Buffer.alloc(32, fill) });
const seqs = (heads: readonly { readonly seq: bigint }[]) => heads.map(({ seq }) => seq);
const names = (store: Store, folder: string) =>
  [...store.files.keys()].filter((name) => name.startsWith(`e1/${folder}/`));

describe('TR-14 the witness log: every file names its writer', () => {
  it("opens each file's name with its process's writer ID, which the closing line signs, and every reader takes it", async () => {
    const store = createFakeWriteOnceStore();
    const copy = copyOn(store);
    expect(copy.log.writer()).toMatch(WRITER_ID);
    // Each process its own.
    expect(copyOn(store).log.writer()).not.toBe(copy.log.writer());
    await copy.log.now(CHAIN, head(5n, 1));
    await copy.log.now(CHAIN, head(6n, 2));
    expect(names(store, 'heads').map(writerOfName)).toEqual([copy.log.writer(), copy.log.writer()]);
    const reader = copyOn(store);
    await reader.log.refresh();
    expect(seqs(reader.log.pending(CHAIN))).toEqual([6n, 5n]);
    expect(reader.alarms('spoiled')).toEqual([]);
    // Its own files, read back, are never taken for one written in its name.
    await copy.log.refresh();
    expect(copy.alarms('impersonated')).toEqual([]);
  });

  it('the fork alarm names the writer of the head just seen and of each it meets, from a read or a note', async () => {
    const store = createFakeWriteOnceStore();
    const honest = copyOn(store);
    const forger = copyOn(store);
    await honest.log.now(CHAIN, head(7n, 1));
    await forger.log.now(CHAIN, head(7n, 2));
    const reader = copyOn(store);
    await reader.log.refresh();
    const [fork] = reader.capture.lines().filter((one) => one.reason === 'fork');
    expect([fork?.writer, ...(fork?.against as string[])].toSorted()).toEqual(
      [honest.log.writer(), forger.log.writer()].toSorted(),
    );
    // A copy's own head, noted, met by another's read after.
    await honest.log.refresh();
    expect(honest.capture.lines().filter((one) => one.reason === 'fork')).toEqual([
      expect.objectContaining({ seq: '7', writer: forger.log.writer(), against: [honest.log.writer()] }),
    ]);
  });
});

describe("TR-14 the operator's set-aside list", () => {
  it("passes over every heads file a writer set aside named until then, each said by name; another writer's still read", async () => {
    const store = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const honest = copyOn(store, { time });
    const forger = copyOn(store, { time });
    const operator = copyOn(store, { signer: 'operator', time });
    await honest.log.now(OTHER, head(3n, 1));
    await forger.log.now(CHAIN, head(9n, 9));
    await operator.log.setAside(forger.log.writer(), REASON);
    expect(names(store, 'set-aside')).toHaveLength(1);
    const reader = copyOn(store);
    await reader.log.refresh();
    expect(seqs(reader.log.pending(OTHER))).toEqual([3n]);
    expect(reader.log.pending(CHAIN)).toEqual([]);
    const [forged] = names(store, 'heads').filter((name) => writerOfName(name) === forger.log.writer());
    expect(reader.alarms('set_aside')).toEqual([
      expect.objectContaining({ level: 'error', writer: forger.log.writer(), folder: 'e1/heads/', file: forged }),
    ]);
    // What it names after the set-aside is read and held all the same (fail-closed), each file said once, as late.
    const early = copyOn(store, { time });
    await early.log.refresh();
    time.at += 1000;
    await forger.log.now(CHAIN, head(10n, 9));
    await early.log.refresh();
    await early.log.refresh();
    expect(seqs(early.log.pending(CHAIN))).toEqual([10n]);
    expect(early.alarms('set_aside')).toHaveLength(1);
    expect(early.alarms('set_aside_late')).toHaveLength(1);
  });

  it("passes over a set-aside writer's snapshot at a start, reading the heads files instead", async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const leader = copyOn(store, { snapshots, leads: true });
    await leader.log.refresh();
    await leader.log.now(CHAIN, head(4n, 4));
    await leader.log.flush();
    expect(names(snapshots, 'snapshots')).toHaveLength(1);
    await copyOn(store, { signer: 'operator' }).log.setAside(leader.log.writer(), REASON);
    const honest = copyOn(store);
    await honest.log.now(OTHER, head(2n, 2));
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    expect(starting.alarms('set_aside').map(({ folder }) => folder)).toEqual(['snapshots', 'e1/heads/']);
    expect(starting.log.pending(CHAIN)).toEqual([]);
    expect(seqs(starting.log.pending(OTHER))).toEqual([2n]);
  });

  it("takes a set-aside file only under the operator's key: one a copy of the API signed is the alarm, setting nothing aside", async () => {
    const store = createFakeWriteOnceStore();
    const honest = copyOn(store);
    await honest.log.now(CHAIN, head(5n, 1));
    // A copy broken into tries to have the honest one passed over, with the key it holds.
    const name = fileName('e1/set-aside/', AT.getTime());
    store.files.set(
      name,
      await signedFile(keys, { label: 'audit-witness-set-aside', purpose: 'audit-anchor' }, name, 1, [
        JSON.stringify({ w: honest.log.writer(), reason: REASON }),
      ]),
    );
    const reader = copyOn(store);
    await reader.log.refresh();
    expect(seqs(reader.log.pending(CHAIN))).toEqual([5n]);
    expect(reader.alarms('spoiled')).toEqual([expect.objectContaining({ folder: 'e1/set-aside/' })]);
    expect(reader.alarms('set_aside')).toEqual([]);
  });

  it("is the operator's alone, and takes only a writer's ID", async () => {
    const store = createFakeWriteOnceStore();
    await expect(copyOn(store).log.setAside('a1b2c3d4e5f6', REASON)).rejects.toThrow("only the operator's command");
    const operator = copyOn(store, { signer: 'operator' }).log;
    await expect(operator.setAside('A1B2C3D4E5F6', REASON)).rejects.toBeInstanceOf(RangeError);
    await expect(operator.setAside('a1b2c3d4e5f6', 'x')).rejects.toBeInstanceOf(RangeError);
    expect(names(store, 'set-aside')).toEqual([]);
  });

  it('a copy that finds its own ID set aside says so and writes on under a new one, which every copy still reads', async () => {
    const store = createFakeWriteOnceStore();
    const copy = copyOn(store);
    const was = copy.log.writer();
    await copyOn(store, { signer: 'operator' }).log.setAside(was, REASON);
    await copy.log.refresh();
    expect(copy.log.writer()).not.toBe(was);
    expect(copy.alarms('own_writer_set_aside')).toEqual([
      expect.objectContaining({ writer: was, renamedTo: copy.log.writer() }),
    ]);
    await copy.log.now(CHAIN, head(8n, 8));
    const reader = copyOn(store);
    await reader.log.refresh();
    expect(seqs(reader.log.pending(CHAIN))).toEqual([8n]);
  });
});

describe('TR-14 a file written in a process’s own name', () => {
  it('is the alarm, naming the writer and the file, and is read as any other: a detector, never a gate', async () => {
    const store = createFakeWriteOnceStore();
    const copy = copyOn(store);
    await copy.log.refresh();
    const name = fileName('e1/heads/', AT.getTime(), copy.log.writer());
    const line = JSON.stringify({
      c: `organisation:${ORG}`,
      s: '6',
      h: Buffer.alloc(32, 6).toString('hex'),
      t: AT.toISOString(),
    });
    store.files.set(
      name,
      await signedFile(keys, { label: 'audit-witness-file', purpose: 'audit-anchor' }, name, 1, [line]),
    );
    await copy.log.refresh();
    expect(copy.alarms('impersonated')).toEqual([
      expect.objectContaining({ level: 'error', writer: copy.log.writer(), folder: 'e1/heads/', file: name }),
    ]);
    expect(seqs(copy.log.pending(CHAIN))).toEqual([6n]);
  });
});

/** A file of `kind` planted in a store, named for `writer` at `at`: its name. */
async function plant(
  store: Store,
  folder: string,
  kind: { readonly label: string; readonly purpose: 'audit-anchor' },
  lines: readonly string[],
  at: number,
  writer?: string,
): Promise<string> {
  const name = fileName(`e1/${folder}/`, at, writer);
  store.files.set(name, await signedFile(keys, kind, name, 1, lines));
  return name;
}

const HEADS = { label: 'audit-witness-file', purpose: 'audit-anchor' } as const;
const SNAPSHOT = { label: 'audit-witness-snapshot', purpose: 'audit-anchor' } as const;
const headLine = (seq: bigint, fill: number, at: number, w?: string) =>
  JSON.stringify({
    c: `organisation:${ORG}`,
    s: seq.toString(),
    h: Buffer.alloc(32, fill).toString('hex'),
    t: new Date(at).toISOString(),
    ...(w === undefined ? {} : { w }),
  });

describe('TR-14 a set-aside is fail-closed', () => {
  it('passes over only what the writer named until the set-aside: a head it writes after is read and held, said late', async () => {
    const store = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const honest = copyOn(store, { time });
    await honest.log.now(CHAIN, head(5n, 1));
    time.at += MINUTE;
    await copyOn(store, { signer: 'operator', time }).log.setAside(honest.log.writer(), REASON);
    // Written under its old ID just after, before it has read the set-aside.
    time.at += 1000;
    await honest.log.now(CHAIN, head(6n, 2));
    const jobs = copyOn(store, { time });
    await jobs.log.refresh();
    // What the gate holds to: the late head, never dropped.
    expect(seqs(jobs.log.heldTo(CHAIN))).toEqual([6n]);
    expect(jobs.alarms('set_aside_late')).toEqual([expect.objectContaining({ writer: honest.log.writer() })]);
    // The honest copy finds itself set aside: every head it still holds goes out again under its new ID.
    await honest.log.refresh();
    await honest.log.flush();
    time.at += 1000;
    await jobs.log.refresh();
    expect(seqs(jobs.log.heldTo(CHAIN))).toEqual([6n, 5n]);
  });
});

describe('TR-14 attribution through snapshots', () => {
  it("a fork met from a snapshot names each head's own writer, never the leader that kept it; one before TR-14, `snapshot`", async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const honest = copyOn(store);
    await honest.log.now(CHAIN, head(7n, 1));
    // The next release's snapshots, which write each head's writer (SNAPSHOT_WRITERS on).
    const leader = copyOn(store, { snapshots, leads: true, snapshotWriters: true });
    await leader.log.refresh();
    leader.log.soon(OTHER, head(1n, 1));
    await leader.log.flush();
    const forger = copyOn(store);
    await forger.log.now(CHAIN, head(7n, 2));
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    const [fork] = starting.capture.lines().filter((one) => one.reason === 'fork');
    expect(fork).toEqual(expect.objectContaining({ writer: forger.log.writer(), against: [honest.log.writer()] }));
    // A snapshot line that says no writer (a build before TR-14).
    const older = createFakeWriteOnceStore();
    await plant(older, 'snapshots', SNAPSHOT, [headLine(7n, 3, AT.getTime() - MINUTE)], AT.getTime() - MINUTE);
    const late = copyOn(store, { snapshots: older });
    await late.log.refresh();
    expect(late.capture.lines().filter((one) => one.reason === 'fork')).toContainEqual(
      expect.objectContaining({ against: ['snapshot'] }),
    );
  });

  it("refuses a heads file's line that claims a writer: only a snapshot's say who wrote a head", async () => {
    const store = createFakeWriteOnceStore();
    await plant(store, 'heads', HEADS, [headLine(4n, 4, AT.getTime(), 'a1b2c3d4e5f6')], AT.getTime());
    const reader = copyOn(store);
    await reader.log.refresh();
    expect(reader.log.pending(CHAIN)).toEqual([]);
    expect(reader.alarms('spoiled')).toHaveLength(1);
  });
});

describe('TR-7 review: a start under a set-aside flood', () => {
  it('fetches a bounded number, takes no snapshot past them, holds a stop from the day’s heads files, and says so', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const leader = copyOn(store, { snapshots, leads: true, time });
    await leader.log.refresh();
    leader.log.soon(OTHER, head(1n, 1));
    await leader.log.flush();
    // A stop named before the leader's snapshot, left out of it.
    const honest = copyOn(store, { time });
    time.at -= 10 * MINUTE;
    await honest.log.now(CHAIN, head(7n, 7));
    time.at += 11 * MINUTE;
    for (let one = 0; one < 1500; one += 1) {
      const name = fileName('e1/set-aside/', time.at - 1500 + one);
      store.files.set(name, Buffer.from('junk'));
      store.created.set(name, time.at - 1500 + one);
    }
    time.at += 1000;
    const real = await setAsideFile(store, leader.log.writer(), time.at);
    store.created.set(real, time.at);
    const before = { ...store.calls };
    const starting = copyOn(store, { snapshots, time });
    expect(await starting.log.refreshWhole()).toBe(true);
    expect(starting.log.state()).toBe('read');
    // The set-asides fetched at most the start's share, and the day's few heads files.
    expect(store.calls.smallGets - before.smallGets).toBeLessThanOrEqual(1000 + 5);
    expect(snapshots.calls.smallGets).toBe(0);
    expect(seqs(starting.log.pending(CHAIN))).toEqual([7n]);
    // Said once a pass, never once a junk file.
    expect(starting.alarms('spoiled')).toEqual([expect.objectContaining({ folder: 'e1/set-aside/', files: 1000 })]);
    expect(starting.alarms('set_aside_flood')).toHaveLength(1);
    expect(starting.alarms('read_back_capped')).toHaveLength(1);
  });
});

describe('TR-7 review: a start reading set-asides further back for an old snapshot', () => {
  it('takes no snapshot that a set-aside it left unfetched could pass over', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const old = AT.getTime() - 48 * HOUR;
    await plant(snapshots, 'snapshots', SNAPSHOT, [headLine(4n, 4, old)], old);
    for (let one = 0; one < 1001; one += 1) {
      const name = fileName('e1/set-aside/', old + one);
      store.files.set(name, Buffer.from('junk'));
      store.created.set(name, old + one);
    }
    const starting = copyOn(store, { snapshots });
    expect(await starting.log.refreshWhole()).toBe(true);
    expect(snapshots.calls.smallGets).toBe(0);
    expect(starting.log.pending(CHAIN)).toEqual([]);
    expect(starting.alarms('read_back_capped')).toHaveLength(1);
  });
});

describe('TR-7 re-review: a start’s set-aside reads, failed or flooded', () => {
  it('a fetch that fails mid-way leaves the reach where it was: the retry still finds the set-aside, the snapshot passed over', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const LEADER = '0123456789ab';
    const old = AT.getTime() - 48 * HOUR;
    await plant(snapshots, 'snapshots', SNAPSHOT, [headLine(4n, 4, old)], old, LEADER);
    const real = await setAsideFile(store, LEADER, old + MINUTE);
    store.created.set(real, old + MINUTE);
    let failOnce = true;
    store.instead.getAtMost = (name, most) => {
      if (name === real && failOnce) {
        failOnce = false;
        return Promise.reject(new Error('the store answered 503'));
      }
      return store.real.getAtMost(name, most);
    };
    const starting = copyOn(store, { snapshots });
    expect(await starting.log.refreshWhole()).toBe(false);
    expect(await starting.log.refreshWhole()).toBe(true);
    // Its writer known set aside, the old snapshot is past the walk's reach: not taken, said.
    expect(starting.log.pending(CHAIN)).toEqual([]);
    expect(starting.alarms('read_back_capped')).toHaveLength(1);
  });

  it('a hundred thousand junk names in the start’s look back: the list stops at its bound, nothing held whole, the alarms', async () => {
    const store = createFakeWriteOnceStore();
    for (let one = 0; one < 100_000; one += 1) {
      const at = AT.getTime() - one * 500;
      const name = fileName('e1/set-aside/', at);
      store.files.set(name, Buffer.from('junk'));
      store.created.set(name, at);
    }
    const starting = copyOn(store);
    expect(await starting.log.refreshWhole()).toBe(true);
    expect(starting.log.state()).toBe('read');
    // Ten pages of set-aside names and the heads' few: never the whole flood listed or fetched.
    expect(store.calls.lists).toBeLessThanOrEqual(16);
    expect(store.calls.smallGets).toBe(0);
    expect(starting.alarms('set_aside_flood')).toEqual([
      expect.objectContaining({ mostRead: 1000, mostListed: 50_000 }),
    ]);
    expect(starting.alarms('read_back_capped')).toHaveLength(1);
    expect(starting.capture.lines().filter(({ event }) => event === 'audit.witness_rebase_needed')).toHaveLength(1);
  });
});

describe('TR-14 set-aside snapshots at a start', () => {
  it("goes back past a day's of a set-aside leader's snapshots, a quarter hour apart, to an older one, its state whole", async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const LEADER = '0123456789ab';
    const older = AT.getTime() - 23 * 60 * MINUTE - 50 * MINUTE;
    await plant(snapshots, 'snapshots', SNAPSHOT, [headLine(4n, 4, older)], older);
    for (let quarter = 95; quarter > 0; quarter -= 1) {
      await plant(snapshots, 'snapshots', SNAPSHOT, [], AT.getTime() - quarter * 15 * MINUTE, LEADER);
    }
    await copyOn(store, { signer: 'operator' }).log.setAside(LEADER, REASON);
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    expect(seqs(starting.log.pending(CHAIN))).toEqual([4n]);
    expect(starting.alarms('set_aside')).toEqual([
      expect.objectContaining({ writers: [LEADER], folder: 'snapshots', files: 95 }),
    ]);
    expect(starting.alarms('spoiled')).toEqual([]);
    expect(starting.alarms('read_back_capped')).toEqual([]);
  });

  it('TR-7 review: an honest snapshot older than a day under a set-aside run is taken whole; heads files read a day back, the alarm', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const LEADER = '0123456789ab';
    const older = AT.getTime() - 72 * 60 * MINUTE;
    await plant(snapshots, 'snapshots', SNAPSHOT, [headLine(4n, 4, older)], older);
    for (let hour = 20; hour > 0; hour -= 1) {
      await plant(snapshots, 'snapshots', SNAPSHOT, [], AT.getTime() - hour * 60 * MINUTE, LEADER);
    }
    await plant(store, 'heads', HEADS, [headLine(3n, 3, older + MINUTE)], older + MINUTE);
    await plant(store, 'heads', HEADS, [headLine(5n, 5, AT.getTime() - HOUR)], AT.getTime() - HOUR);
    await copyOn(store, { signer: 'operator' }).log.setAside(LEADER, REASON);
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    // The snapshot's state, and the heads files of the last day alone.
    expect(seqs(starting.log.pending(CHAIN))).toEqual([5n, 4n]);
    expect(starting.alarms('read_back_capped')).toEqual([
      expect.objectContaining({ level: 'error', snapshotAt: new Date(older).toISOString() }),
    ]);
  });

  it('TR-7 D3: with none but a set-aside one past a day, reads heads files back a day alone, and says older went unread', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const LEADER = '0123456789ab';
    const threeDays = AT.getTime() - 72 * 60 * MINUTE;
    await plant(snapshots, 'snapshots', SNAPSHOT, [], threeDays, LEADER);
    await plant(store, 'heads', HEADS, [headLine(3n, 3, threeDays + MINUTE)], threeDays + MINUTE);
    await plant(store, 'heads', HEADS, [headLine(5n, 5, AT.getTime() - HOUR)], AT.getTime() - HOUR);
    await copyOn(store, { signer: 'operator' }).log.setAside(LEADER, REASON);
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    expect(seqs(starting.log.pending(CHAIN))).toEqual([5n]);
    expect(starting.alarms('read_back_capped')).toEqual([
      expect.objectContaining({ level: 'error', folder: 'snapshots' }),
    ]);
  });

  it('TR-7 D3: a thousand set-aside snapshots and a week of heads files: a start reads a day back, in bounded calls', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const LEADER = '0123456789ab';
    // Every ten minutes for a week: never fetched, as their writer is set aside.
    for (let one = 1; one <= 1000; one += 1) {
      snapshots.files.set(fileName('e1/snapshots/', AT.getTime() - one * 10 * MINUTE, LEADER), Buffer.from('junk'));
    }
    for (let hour = 1; hour <= 7 * 24; hour += 1) {
      const at = AT.getTime() - hour * HOUR;
      await plant(store, 'heads', HEADS, [headLine(BigInt(1000 - hour), 1, at)], at);
    }
    await copyOn(store, { signer: 'operator' }).log.setAside(LEADER, REASON);
    const before = { heads: { ...store.calls }, snapshots: { ...snapshots.calls } };
    const starting = copyOn(store, { snapshots });
    expect(await starting.log.refreshWhole()).toBe(true);
    expect(starting.log.state()).toBe('read');
    // A day of heads files and the set-aside, none of the snapshots.
    expect(store.calls.smallGets - before.heads.smallGets).toBeLessThanOrEqual(26);
    expect(snapshots.calls.smallGets - before.snapshots.smallGets).toBe(0);
    expect(store.calls.lists - before.heads.lists + snapshots.calls.lists - before.snapshots.lists).toBeLessThan(40);
    expect(Math.min(...seqs(starting.log.pending(CHAIN)).map(Number))).toBeGreaterThanOrEqual(1000 - 24);
    expect(starting.alarms('read_back_capped')).toHaveLength(1);
    expect(starting.alarms('set_aside')).toContainEqual(expect.objectContaining({ folder: 'snapshots', files: 96 }));
  });
});

describe('TR-14 the set-aside folder read', () => {
  it('a flood of junk slows no refresh: at most a hundred fetched a pass, said; the rest wait for the next', async () => {
    const store = createFakeWriteOnceStore();
    const reader = copyOn(store);
    expect(await reader.log.refreshWhole()).toBe(true);
    // No landing time from the store: none can be judged misdated, so each is fetched in turn.
    for (let one = 0; one < 10_000; one += 1)
      store.files.set(fileName('e1/set-aside/', AT.getTime() - one), Buffer.from('junk'));
    const started = performance.now();
    expect(await reader.log.refreshWhole()).toBe(true);
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(store.calls.smallGets).toBeLessThanOrEqual(100);
    expect(reader.alarms('set_aside_flood')).toHaveLength(1);
    expect(reader.alarms('set_aside_misdated')).toEqual([]);
    const fetched = store.calls.smallGets;
    expect(await reader.log.refreshWhole()).toBe(true);
    expect(store.calls.smallGets - fetched).toBeLessThanOrEqual(100);
  });

  it('TR-7 review: a start fetches every set-aside, so a flood ahead of the real one never lets it take the set-aside leader’s snapshot', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const leader = copyOn(store, { snapshots, leads: true, time });
    await leader.log.refresh();
    leader.log.soon(OTHER, head(1n, 1));
    await leader.log.flush();
    // A stop the leader leaves out of its snapshot: another copy's, which it (broken into) claims never to have read.
    const honest = copyOn(store, { time });
    time.at -= 10 * MINUTE;
    await honest.log.now(CHAIN, head(7n, 7));
    time.at += 10 * MINUTE + MINUTE;
    // Well-dated junk planted before the real set-aside, more than a pass fetches.
    for (let one = 0; one < 150; one += 1) {
      const name = fileName('e1/set-aside/', time.at - 150 + one);
      store.files.set(name, Buffer.from('junk'));
      store.created.set(name, time.at - 150 + one);
    }
    time.at += 1000;
    const real = await setAsideFile(store, leader.log.writer(), time.at);
    store.created.set(real, time.at);
    // A day on, past every heads file's look back from the leader's snapshot but the stop's own.
    const starting = copyOn(store, { snapshots, time });
    expect(await starting.log.refreshWhole()).toBe(true);
    expect(starting.alarms('set_aside')).toContainEqual(expect.objectContaining({ folder: 'snapshots', files: 1 }));
    expect(seqs(starting.log.pending(CHAIN))).toEqual([7n]);
  });

  it('a set-aside file listed and then gone fails the read: never a pass that missed one', async () => {
    const store = createFakeWriteOnceStore();
    await copyOn(store, { signer: 'operator' }).log.setAside('a1b2c3d4e5f6', REASON);
    store.instead.getAtMost = (name, most) =>
      name.startsWith('e1/set-aside/') ? Promise.resolve('missing') : store.real.getAtMost(name, most);
    const reader = copyOn(store);
    expect(await reader.log.refreshWhole()).toBe(false);
    expect(reader.capture.lines().map(({ event }) => event)).toContain('audit.witness_read_failed');
  });

  it('after a whole pass, reads only what landed since, less the look back', async () => {
    const store = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    await copyOn(store, { signer: 'operator', time }).log.setAside('a1b2c3d4e5f6', REASON);
    const reader = copyOn(store, { time });
    await reader.log.refresh();
    const fetched = store.calls.smallGets;
    // An old one planted after: older than the look back, so a later pass never lists that far.
    store.files.set(fileName('e1/set-aside/', AT.getTime() - 60 * MINUTE), Buffer.from('junk'));
    time.at += 20 * MINUTE;
    await reader.log.refresh();
    expect(store.calls.smallGets).toBe(fetched);
  });
});

/** A set-aside of `writer` signed with the operator's key, named at `at` (as the operator's command writes it). */
async function setAsideFile(store: Store, writer: string, at: number): Promise<string> {
  const name = fileName('e1/set-aside/', at);
  store.files.set(
    name,
    await signedFile(keys, { label: 'audit-witness-set-aside', purpose: 'operator-signing' }, name, 1, [
      JSON.stringify({ w: writer, reason: REASON }),
    ]),
  );
  return name;
}

describe('TR-7 D1 lists bounded to the time window', () => {
  it('a hundred thousand names dated in 2200 and as many back-dated set-asides cost a start and a refresh a few calls, one line', async () => {
    const store = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const forger = copyOn(store, { time });
    await forger.log.now(CHAIN, head(9n, 9));
    const honest = copyOn(store, { time });
    await honest.log.now(OTHER, head(3n, 1));
    time.at += MINUTE;
    await setAsideFile(store, forger.log.writer(), time.at);
    for (let one = 0; one < 100_000; one += 1) {
      store.files.set(fileName('e1/heads/', Date.UTC(2200, 0, 1) + one), Buffer.from('junk'));
      store.files.set(fileName('e1/set-aside/', AT.getTime() - 48 * 60 * MINUTE - one * 20_000), Buffer.from('junk'));
    }
    // A few dated just past the clocks' spread: listed, and said once, with their count.
    for (const ahead of [20, 21, 22])
      store.files.set(fileName('e1/heads/', time.at + ahead * MINUTE), Buffer.from('junk'));
    const reader = copyOn(store, { time });
    const before = { ...store.calls };
    expect(await reader.log.refreshWhole()).toBe(true);
    expect(store.calls.lists - before.lists).toBeLessThanOrEqual(10);
    // The set-aside and the honest file alone: the forger's passed over by name, no junk fetched.
    expect(store.calls.smallGets - before.smallGets).toBe(2);
    expect(seqs(reader.log.pending(OTHER))).toEqual([3n]);
    expect(reader.log.pending(CHAIN)).toEqual([]);
    expect(reader.alarms('set_aside')).toHaveLength(1);
    expect(reader.alarms('future')).toEqual([
      expect.objectContaining({ folders: [expect.objectContaining({ folder: 'e1/heads/', files: 3 })] }),
    ]);
    time.at += 10_000;
    const later = store.calls.lists;
    expect(await reader.log.refreshWhole()).toBe(true);
    expect(store.calls.lists - later).toBeLessThanOrEqual(6);
    expect(reader.alarms('future').length).toBeLessThanOrEqual(2);
  });
});

describe('TR-7 D6 a set-aside flood', () => {
  it('never keeps a real set-aside unread: read oldest first, and names far from when they landed passed over, said', async () => {
    const store = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const reader = copyOn(store, { time });
    expect(await reader.log.refreshWhole()).toBe(true);
    time.at += 1000;
    const forger = copyOn(store, { time });
    await forger.log.now(CHAIN, head(9n, 9));
    time.at += 3 * MINUTE;
    const real = await setAsideFile(store, forger.log.writer(), time.at);
    store.created.set(real, time.at);
    // Junk the flooder names after the real one, landing as named, more each pass than a pass fetches; and junk named
    // before it (inside the look back) that landed only now.
    const flood = (count: number) => {
      for (let one = 0; one < count; one += 1) {
        const name = fileName('e1/set-aside/', time.at + 1 + one);
        store.files.set(name, Buffer.from('junk'));
        store.created.set(name, time.at + 1 + one);
        const early = fileName('e1/set-aside/', AT.getTime() - 4 * MINUTE - one);
        store.files.set(early, Buffer.from('junk'));
        store.created.set(early, time.at);
      }
    };
    flood(300);
    time.at += 1000;
    await forger.log.now(CHAIN, head(10n, 8));
    expect(await reader.log.refreshWhole()).toBe(true);
    flood(300);
    expect(await reader.log.refreshWhole()).toBe(true);
    // The forger's file named before the set-aside passed over from the first pass after it landed; its later one held.
    expect(reader.alarms('set_aside')).toHaveLength(1);
    expect(seqs(reader.log.pending(CHAIN))).toEqual([10n]);
    expect(reader.alarms('set_aside_late')).toHaveLength(1);
    expect(reader.alarms('set_aside_misdated').map(({ files }) => files)).toEqual([300, 300]);
    expect(reader.alarms('set_aside_flood')).toHaveLength(1);
  });
});

describe('TR-14 review: a writer set aside twice, snapshots this release, a copy set aside rewriting', () => {
  it("holds a writer's earliest set-aside: a second line for it never passes over more; the command writes no second", async () => {
    const store = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const honest = copyOn(store, { time });
    const writer = honest.log.writer();
    const sign = async (at: number) => {
      const name = fileName('e1/set-aside/', at);
      store.files.set(
        name,
        await signedFile(keys, { label: 'audit-witness-set-aside', purpose: 'operator-signing' }, name, 1, [
          JSON.stringify({ w: writer, reason: REASON }),
        ]),
      );
    };
    await sign(AT.getTime());
    time.at += MINUTE;
    // Named between the two set-asides: after the earlier, so read and held.
    await honest.log.now(CHAIN, head(5n, 5));
    time.at += MINUTE;
    await sign(time.at);
    const reader = copyOn(store, { time });
    await reader.log.refresh();
    expect(seqs(reader.log.heldTo(CHAIN))).toEqual([5n]);
    expect(reader.alarms('set_aside_late')).toHaveLength(1);
    const operator = copyOn(store, { signer: 'operator', time }).log;
    await expect(operator.setAside(writer, REASON)).resolves.toBe('before');
    expect(names(store, 'set-aside')).toHaveLength(2);
  });

  it('this release writes no writer into a snapshot (SNAPSHOT_WRITERS off); the next release does', async () => {
    expect(SNAPSHOT_WRITERS).toBe(false);
    for (const snapshotWriters of [undefined, true]) {
      const store = createFakeWriteOnceStore();
      const snapshots = createFakeWriteOnceStore();
      const leader = copyOn(store, { snapshots, leads: true, snapshotWriters });
      await leader.log.refresh();
      leader.log.soon(CHAIN, head(2n, 2));
      await leader.log.flush();
      const [name = ''] = names(snapshots, 'snapshots');
      const text = gunzipSync(snapshots.files.get(name) ?? Buffer.alloc(0)).toString();
      expect({ snapshotWriters, written: text.includes(`"w":"${leader.log.writer()}"`) }).toEqual({
        snapshotWriters,
        written: snapshotWriters === true,
      });
    }
  });

  it('a copy set aside writes again every head it still holds, one in flight across the set-aside too: a fresh reader holds them', async () => {
    const store = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const copy = copyOn(store, { time });
    await copy.log.now(CHAIN, head(5n, 5));
    // A Put named before the set-aside, landing after it.
    let land: () => void = () => undefined;
    const landing = new Promise<void>((resolve) => {
      land = resolve;
    });
    let named: () => void = () => undefined;
    const sent = new Promise<void>((resolve) => {
      named = resolve;
    });
    store.instead.put = async (name, bytes) => {
      if (name.startsWith('e1/heads/')) {
        named();
        await landing;
      }
      return store.real.put(name, bytes);
    };
    const inFlight = copy.log.now(CHAIN, head(6n, 6));
    await sent;
    time.at += MINUTE;
    await copyOn(store, { signer: 'operator', time }).log.setAside(copy.log.writer(), REASON);
    land();
    await inFlight;
    delete store.instead.put;
    const before = copyOn(store, { time });
    await before.log.refresh();
    expect(before.log.heldTo(CHAIN)).toEqual([]);
    // The copy finds itself set aside, and writes both again under its new ID.
    time.at += 1000;
    await copy.log.refresh();
    await copy.log.flush();
    const fresh = copyOn(store, { time });
    await fresh.log.refresh();
    expect(seqs(fresh.log.heldTo(CHAIN))).toEqual([6n, 5n]);
    // Held as the new ID's: a set-aside of that one writes them again too.
    time.at += MINUTE;
    await copyOn(store, { signer: 'operator', time }).log.setAside(copy.log.writer(), REASON);
    time.at += 1000;
    await copy.log.refresh();
    await copy.log.flush();
    const third = copyOn(store, { time });
    await third.log.refresh();
    expect(seqs(third.log.heldTo(CHAIN))).toEqual([6n, 5n]);
  });
});

describe('SEC-DB-20 S210 R1-1 a heads file misdated by its writer', () => {
  it('a start from an hour-old snapshot reads one named ten minutes back in another ID and created now: the alarm names it', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    await plant(snapshots, 'snapshots', SNAPSHOT, [headLine(3n, 3, AT.getTime() - HOUR)], AT.getTime() - HOUR);
    // The jobs leader's ID, as a copy broken into would claim it: named back past the leader's own look back.
    const leader = 'a1b2c3d4e5f6';
    const namedAt = AT.getTime() - 10 * MINUTE;
    const name = await plant(store, 'heads', HEADS, [headLine(4n, 4, namedAt)], namedAt, leader);
    store.created.set(name, AT.getTime());
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    expect(starting.alarms('misdated_heads')).toEqual([
      expect.objectContaining({ level: 'error', writer: leader, file: name, skewMs: -10 * MINUTE }),
    ]);
    // A detector, never a gate: read and held as any other; no clock of this copy's said.
    expect(seqs(starting.log.pending(CHAIN))).toEqual([4n, 3n]);
    expect(starting.alarms('clock_skew')).toEqual([]);
  });
});

describe('SEC-DB-20 S210 R1-3 a leader that finds its own ID set aside', () => {
  it('writes a snapshot under its new ID at its next flush after a whole read, not an hour on', async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const time = { at: AT.getTime() };
    const leader = copyOn(store, { snapshots, leads: true, time });
    await leader.log.refresh();
    leader.log.soon(CHAIN, head(2n, 2));
    await leader.log.flush();
    const was = leader.log.writer();
    expect(names(snapshots, 'snapshots').map(writerOfName)).toEqual([was]);
    time.at += MINUTE;
    await copyOn(store, { signer: 'operator', time }).log.setAside(was, REASON);
    time.at += 1000;
    await leader.log.refresh();
    expect(leader.log.writer()).not.toBe(was);
    await leader.log.refresh();
    await leader.log.flush();
    expect(names(snapshots, 'snapshots').map(writerOfName).toSorted()).toEqual([was, leader.log.writer()].toSorted());
  });
});
