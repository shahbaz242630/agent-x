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

type Store = ReturnType<typeof createFakeWriteOnceStore>;

/** A copy of the API (or the operator's command) on the shared store, its lines captured. */
function copyOn(
  store: Store,
  { signer = 'app', snapshots, leads = false }: { signer?: WitnessSigner; snapshots?: Store; leads?: boolean } = {},
) {
  const capture = new LogCapture();
  const log = createWitnessLog({
    store: store.store,
    snapshots: snapshots?.store,
    keys,
    logger: testLogger(capture),
    now: () => AT,
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
  it("passes over every heads file of a writer set aside, each said by name; another writer's still read", async () => {
    const store = createFakeWriteOnceStore();
    const honest = copyOn(store);
    const forger = copyOn(store);
    const operator = copyOn(store, { signer: 'operator' });
    await honest.log.now(OTHER, head(3n, 1));
    await forger.log.now(CHAIN, head(9n, 9));
    await operator.log.setAside(forger.log.writer());
    expect(names(store, 'set-aside')).toHaveLength(1);
    const reader = copyOn(store);
    await reader.log.refresh();
    expect(seqs(reader.log.pending(OTHER))).toEqual([3n]);
    expect(reader.log.pending(CHAIN)).toEqual([]);
    const [forged] = names(store, 'heads').filter((name) => writerOfName(name) === forger.log.writer());
    expect(reader.alarms('set_aside')).toEqual([
      expect.objectContaining({ level: 'error', writer: forger.log.writer(), folder: 'e1/heads/', file: forged }),
    ]);
    // A copy reading already passes over what that writer writes from its next read; said once a file.
    const early = copyOn(store);
    await early.log.refresh();
    await forger.log.now(CHAIN, head(10n, 9));
    await early.log.refresh();
    await early.log.refresh();
    expect(early.log.pending(CHAIN)).toEqual([]);
    expect(early.alarms('set_aside')).toHaveLength(2);
  });

  it("passes over a set-aside writer's snapshot at a start, reading the heads files instead", async () => {
    const store = createFakeWriteOnceStore();
    const snapshots = createFakeWriteOnceStore();
    const leader = copyOn(store, { snapshots, leads: true });
    await leader.log.refresh();
    await leader.log.now(CHAIN, head(4n, 4));
    await leader.log.flush();
    expect(names(snapshots, 'snapshots')).toHaveLength(1);
    await copyOn(store, { signer: 'operator' }).log.setAside(leader.log.writer());
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
        JSON.stringify({ w: honest.log.writer() }),
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
    await expect(copyOn(store).log.setAside('a1b2c3d4e5f6')).rejects.toThrow("only the operator's command");
    await expect(copyOn(store, { signer: 'operator' }).log.setAside('A1B2C3D4E5F6')).rejects.toBeInstanceOf(RangeError);
    expect(names(store, 'set-aside')).toEqual([]);
  });

  it('a copy that finds its own ID set aside says so and writes on under a new one, which every copy still reads', async () => {
    const store = createFakeWriteOnceStore();
    const copy = copyOn(store);
    const was = copy.log.writer();
    await copyOn(store, { signer: 'operator' }).log.setAside(was);
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
