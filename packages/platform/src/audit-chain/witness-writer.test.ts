// TR-14 (threat R-12): the witness log's writers. Every file names its writer, the operator's signed list sets a
// writer aside (its files passed over by every copy, each said), a file written in a process's own name is the alarm,
// and the fork alarm names both heads' writers.
import { createFakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import type { Chain } from './chain.ts';
import { fileName, signedFile, WRITER_ID, writerOfName } from './signed-files.ts';
import { createWitnessLog, type WitnessSigner } from './witness-log.ts';

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
  }: { signer?: WitnessSigner; snapshots?: Store; leads?: boolean; time?: { at: number } } = {},
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
    const leader = copyOn(store, { snapshots, leads: true });
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

describe('TR-14 set-aside snapshots at a start', () => {
  it("goes back past more than a day's of a set-aside leader's snapshots to an older one, its state whole", async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const LEADER = '0123456789ab';
    await plant(
      snapshots,
      'snapshots',
      SNAPSHOT,
      [headLine(4n, 4, AT.getTime() - 40 * 60 * MINUTE)],
      AT.getTime() - 40 * 60 * MINUTE,
    );
    for (let hour = 30; hour > 0; hour -= 1) {
      await plant(snapshots, 'snapshots', SNAPSHOT, [], AT.getTime() - hour * 60 * MINUTE, LEADER);
    }
    await copyOn(store, { signer: 'operator' }).log.setAside(LEADER, REASON);
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    expect(seqs(starting.log.pending(CHAIN))).toEqual([4n]);
    expect(starting.alarms('set_aside')).toEqual([
      expect.objectContaining({ writers: [LEADER], folder: 'snapshots', files: 30 }),
    ]);
    expect(starting.alarms('spoiled')).toEqual([]);
  });

  it("with no other snapshot, reads heads files back from the oldest set-aside one's time, past a day", async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const LEADER = '0123456789ab';
    const threeDays = AT.getTime() - 72 * 60 * MINUTE;
    await plant(snapshots, 'snapshots', SNAPSHOT, [], threeDays, LEADER);
    await plant(store, 'heads', HEADS, [headLine(3n, 3, threeDays + MINUTE)], threeDays + MINUTE);
    await copyOn(store, { signer: 'operator' }).log.setAside(LEADER, REASON);
    const starting = copyOn(store, { snapshots });
    await starting.log.refresh();
    expect(seqs(starting.log.pending(CHAIN))).toEqual([3n]);
  });
});

describe('TR-14 the set-aside folder read', () => {
  it('a flood of junk slows no refresh: at most a hundred fetched a pass, said; the rest wait for the next', async () => {
    const store = createFakeWriteOnceStore();
    for (let one = 0; one < 10_000; one += 1)
      store.files.set(fileName('e1/set-aside/', AT.getTime() - one), Buffer.from('junk'));
    const reader = copyOn(store);
    const started = performance.now();
    expect(await reader.log.refreshWhole()).toBe(true);
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(store.calls.smallGets).toBeLessThanOrEqual(100);
    expect(reader.alarms('set_aside_flood')).toHaveLength(1);
    const fetched = store.calls.smallGets;
    expect(await reader.log.refreshWhole()).toBe(true);
    expect(store.calls.smallGets - fetched).toBeLessThanOrEqual(100);
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
