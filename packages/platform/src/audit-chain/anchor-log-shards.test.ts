// The anchors' store moved on to its shards (PL-65 PR2): the migration's order, the version 2 closing line, the old
// files standing under the shards until the migration is done, and every file fetched no further than can be held.
import { createHash } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { type Anchor, signAnchor } from './anchor.ts';
import { createAnchorLog } from './anchor-log.ts';
import { type Chain, chainName } from './chain.ts';
import { cutoverFile, shardsDoneFile } from './cutover.ts';
import { changesFile, closingV2Message, shardHex, shardOf } from './shards.ts';
import { OverwriteRefused } from '../storage/write-once.ts';

const keyMaterial = (fill: number): KeyMaterial =>
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + fill)]]),
  })) satisfies KeyMaterial;
const keys = createKeyProvider(keyMaterial(1));
const otherKeys = createKeyProvider(keyMaterial(50));

const organisation = (index: number): Chain => ({
  kind: 'organisation',
  orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
});
const CHAIN = organisation(1);
const OTHER_CHAIN = organisation(2);
const PLATFORM: Chain = { kind: 'platform' };
/** A chain in another shard than CHAIN's. */
const ELSEWHERE = defined(
  [organisation(3), organisation(4), organisation(5)].find(
    (chain) => shardOf(chainName(chain)) !== shardOf(chainName(CHAIN)),
  ),
);
const START = new Date('2026-11-02T09:00:00.000Z');
const MINUTE = 60_000;
const LAST_MS = 9_999_999_999_999;

const anchorAt = (chain: Chain, seq: bigint, signing = keys): Anchor =>
  signAnchor(signing, chain, { seq, hash: Buffer.alloc(32, Number(seq % 256n)), macKeyVersion: 2 }, START, 1);

const lineOf = (anchor: Anchor): string =>
  JSON.stringify({
    k: 'a',
    chain: anchor.chain,
    seq: anchor.seq.toString(),
    hash: anchor.hash.toString('hex'),
    mk: anchor.macKeyVersion,
    at: anchor.at.toISOString(),
    kv: anchor.keyVersion,
    sig: anchor.signature.toString('base64'),
  });

const countdown = (minutes: number): string => String(LAST_MS - (START.getTime() + minutes * MINUTE));
const idOf = (id: number): string => `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`;

/** An old file's name, `minutes` after START. */
const oldName = (kind: 'deltas' | 'snapshots', minutes: number, id = 1): string =>
  `e1/${kind}/${countdown(minutes)}-${idOf(id)}`;

/** A shard file's name: the shard of `chain` (or a shard by number), `minutes` after START. */
const shardName = (of: Chain | number, kind: 's' | 'd', minutes: number, id = 1): string => {
  const shard = typeof of === 'number' ? of : shardOf(chainName(of));
  return `e1/shards/${shardHex(shard)}/${countdown(minutes)}-${idOf(id)}-${kind}`;
};

/** An old file: its lines, closed by a version 1 line for its name. */
const oldFile = (name: string, ...anchors: readonly Anchor[]): Buffer => {
  const { signature, keyVersion } = keys.sign('audit-anchor', ['audit-anchor-file', name, '1', String(anchors.length)]);
  const closing = JSON.stringify({
    k: 'c',
    name,
    epoch: 1,
    lines: anchors.length,
    kv: keyVersion,
    sig: signature.toString('base64'),
  });
  return gzipSync(`${[...anchors.map(lineOf), closing].join('\n')}\n`);
};

/** A shard's file, as the log writes one: its lines, closed by a version 2 line over the hash of them. */
const shardFile = (name: string, anchors: readonly Anchor[], { signing = keys, body = '' } = {}): Buffer => {
  const lines = anchors.map(lineOf);
  const text = lines.map((line) => `${line}\n`).join('');
  const hash = body === '' ? createHash('sha256').update(text).digest('hex') : body;
  const { signature, keyVersion } = signing.sign('audit-anchor', closingV2Message(name, 1, lines.length, hash));
  const closing = JSON.stringify({
    k: 'c',
    v: 2,
    name,
    epoch: 1,
    lines: lines.length,
    body: hash,
    kv: keyVersion,
    sig: signature.toString('base64'),
  });
  return gzipSync(`${text}${closing}\n`);
};

const linesOf = (bytes: Buffer | undefined): Record<string, unknown>[] =>
  gunzipSync(bytes ?? Buffer.alloc(0))
    .toString('utf8')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as Record<string, unknown>);

const put = (fake: FakeWriteOnceStore, file: { name: string; bytes: Buffer }): void => {
  fake.files.set(file.name, file.bytes);
};
const MARKER = 'e1/cutover/shards-v1';
/** A file in a shard's own folder, not the list of changes. */
const SHARD_FILE_NAME = /^e1\/shards\/[0-9a-f]{2}\//;
/** A list of changes' name, `minutes` after START. */
const changesName = (minutes: number, id = 1): string => `e1/shards/changes/${countdown(minutes)}-${idOf(id)}`;
const DONE = 'e1/shards/done-shards-v1';

/** A store an older version wrote: one snapshot, CHAIN at 5 and the platform at 1. */
const oldStore = (): FakeWriteOnceStore => {
  const fake = createFakeWriteOnceStore();
  fake.files.set(
    oldName('snapshots', 0),
    oldFile(oldName('snapshots', 0), anchorAt(CHAIN, 5n), anchorAt(PLATFORM, 1n)),
  );
  return fake;
};

/** A store moved on: the marker, and with `done`, the record that the migration is done. */
const movedStore = ({ done }: { done: boolean }): FakeWriteOnceStore => {
  const fake = oldStore();
  put(fake, cutoverFile(keys, { epoch: 1, at: START }));
  if (done) put(fake, shardsDoneFile(keys, { epoch: 1, at: new Date(START.getTime() + 61 * MINUTE) }));
  return fake;
};

const logOver = (
  fake: FakeWriteOnceStore,
  {
    cutOver = false,
    at = new Date(START.getTime() + 10 * MINUTE),
    holding = keys,
    mostFileBytes = 0,
  }: { cutOver?: boolean; at?: Date; holding?: KeyProvider; mostFileBytes?: number } = {},
) => {
  const capture = new LogCapture();
  const clock = { at };
  const log = createAnchorLog({
    store: fake.store,
    keys: holding,
    logger: testLogger(capture),
    now: () => clock.at,
    epoch: 1,
    alertAfterMs: 15 * MINUTE,
    cutOver,
    ...(mostFileBytes > 0 ? { mostFileBytes } : {}),
  });
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  const alarms = () => lines('audit.integrity_failed');
  const advance = (minutes: number): void => {
    clock.at = new Date(clock.at.getTime() + minutes * MINUTE);
  };
  return { log, lines, alarms, advance };
};

const shardFiles = (fake: FakeWriteOnceStore): string[] =>
  [...fake.files.keys()].filter((name) => /^e1\/shards\/[0-9a-f]{2}\//.test(name));

/** Signature checks made, by what each signs: its message's first word. */
const counting = (): { keys: KeyProvider; checks: string[] } => {
  const checks: string[] = [];
  return {
    checks,
    keys: {
      ...keys,
      verifySignature(purpose, version, message: Message, signature) {
        checks.push(String(message[0]));
        return keys.verifySignature(purpose, version, message, signature);
      },
    },
  };
};

describe('SEC-ANC-04 the anchors’ store moved on to its shards (PL-65 PR2)', () => {
  describe('the migration', () => {
    it('writes the marker first, then a snapshot of each shard holding chains, each closed over its whole body', async () => {
      const fake = oldStore();
      const order: string[] = [];
      fake.instead.put = (name, bytes) => {
        order.push(name);
        return fake.real.put(name, bytes);
      };
      const { log, lines, alarms } = logOver(fake, { cutOver: true });
      await log.read();
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();

      expect(order[0]).toBe(MARKER);
      // Then the shard files, and only after them the list naming each: no name known before its file is there.
      const shards = new Set([CHAIN, OTHER_CHAIN, PLATFORM].map((chain) => shardOf(chainName(chain))));
      const made = order.slice(1, -1);
      expect(made).toHaveLength(shards.size);
      expect(made.every((name) => /^e1\/shards\/[0-9a-f]{2}\/\d{13}-[0-9a-f-]{36}-s$/.test(name))).toBe(true);
      expect(order.at(-1)).toMatch(/^e1\/shards\/changes\/\d{13}-[0-9a-f-]{36}$/);
      const listed = linesOf(fake.files.get(defined(order.at(-1))))[0];
      expect(listed).toMatchObject({
        k: 'changes',
        files: made.map((name) => name.slice('e1/shards/'.length)),
      });
      // Nothing more in the old folders.
      expect([...fake.files.keys()].filter((name) => /^e1\/(?:deltas|snapshots)\//.test(name))).toHaveLength(1);
      const mine = defined(order.find((name) => name.includes(`/${shardHex(shardOf(chainName(CHAIN)))}/`)));
      const all = linesOf(fake.files.get(mine));
      const closing = defined(all.at(-1));
      expect(all.slice(0, -1)).toEqual([expect.objectContaining({ k: 'a', chain: chainName(CHAIN), seq: '5' })]);
      const body = gunzipSync(defined(fake.files.get(mine)))
        .toString('utf8')
        .split('\n')[0];
      expect(closing).toMatchObject({
        k: 'c',
        v: 2,
        name: mine,
        epoch: 1,
        lines: 1,
        body: createHash('sha256')
          .update(`${String(body)}\n`)
          .digest('hex'),
      });
      expect(lines('audit.anchor_store_cutover')).toEqual([expect.objectContaining({ level: 'info', file: MARKER })]);
      expect(lines('audit.anchors_written')).toEqual([
        expect.objectContaining({ kind: 'shards', files: shards.size, snapshots: shards.size, lines: 3 }),
      ]);
      expect(alarms()).toEqual([]);
    });

    it('a process not set to move it on writes the old files, as before', async () => {
      const fake = oldStore();
      const { log } = logOver(fake);
      await log.read();
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      expect(fake.files.has(MARKER)).toBe(false);
      expect(shardFiles(fake)).toEqual([]);
    });

    it('moves nothing on before a whole read', async () => {
      const fake = oldStore();
      fake.instead.list = () => Promise.reject(new Error('the store is away'));
      const { log } = logOver(fake, { cutOver: true });
      await log.read();
      delete fake.instead.list;
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      expect(fake.files.has(MARKER)).toBe(false);
    });

    it('a restart while moving reads the old files and the shards together, the highest place winning', async () => {
      const fake = oldStore();
      const first = logOver(fake, { cutOver: true });
      await first.log.read();
      first.log.keep(anchorAt(OTHER_CHAIN, 1n));
      await first.log.flush();
      // An older version, not yet seeing the marker, writes an old delta.
      fake.files.set(oldName('deltas', 11), oldFile(oldName('deltas', 11), anchorAt(CHAIN, 7n)));

      const { log, lines, alarms } = logOver(fake, { at: new Date(START.getTime() + 12 * MINUTE) });
      await log.read();
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)?.seq).toBe(7n);
      expect(log.latest(OTHER_CHAIN)?.seq).toBe(1n);
      expect(log.latest(PLATFORM)?.seq).toBe(1n);
      expect(lines('audit.anchors_read')).toEqual([
        expect.objectContaining({ layout: 'moving', chains: 3, snapshot: true, deltas: 1, shardSnapshots: 3 }),
      ]);
      expect(alarms()).toEqual([]);
    });

    it('no record while a shard’s snapshot does not stand for it (its new one’s name taken)', async () => {
      const fake = oldStore();
      const { log, advance, alarms } = logOver(fake, { cutOver: true });
      await log.read();
      await log.flush();
      advance(61);
      // An old line read: CHAIN's shard must be snapshotted again before the record.
      fake.files.set(oldName('deltas', 65), oldFile(oldName('deltas', 65), anchorAt(CHAIN, 9n)));
      await log.read();
      fake.instead.put = async (name, bytes) => {
        if (SHARD_FILE_NAME.test(name)) await fake.real.put(name, Buffer.from('someone else'));
        return fake.real.put(name, bytes);
      };
      await log.flush();
      expect(alarms()).toEqual([expect.objectContaining({ reason: 'overwrite' })]);
      expect(fake.files.has(DONE)).toBe(false);
      delete fake.instead.put;
      advance(1);
      await log.flush();
      expect(fake.files.has(DONE)).toBe(true);
    });

    it('writes the record once, and never while a read is in flight', async () => {
      const fake = oldStore();
      let donePuts = 0;
      fake.instead.put = (name, bytes) => {
        if (name === DONE) donePuts += 1;
        return fake.real.put(name, bytes);
      };
      const { log, advance } = logOver(fake, { cutOver: true });
      await log.read();
      await log.flush();
      advance(61);
      await log.read();
      // A read under way, held on the old snapshot it fetches: no record while it may still take an old file's line.
      const { promise: held, resolve: letGo } = Promise.withResolvers<undefined>();
      fake.instead.getAtMost = async (name, most) => {
        if (name.startsWith('e1/deltas/') || name.startsWith('e1/snapshots/') || name.includes('/changes/')) await held;
        return fake.real.getAtMost(name, most);
      };
      fake.files.set(oldName('deltas', 65), oldFile(oldName('deltas', 65), anchorAt(OTHER_CHAIN, 1n)));
      const reading = log.read();
      await new Promise((resolve) => setTimeout(resolve, 20));
      await log.flush();
      expect(fake.files.has(DONE)).toBe(false);
      letGo(undefined);
      await reading;
      delete fake.instead.getAtMost;
      advance(1);
      await log.flush();
      await log.flush();
      advance(1);
      await log.read();
      await log.flush();
      expect(fake.files.has(DONE)).toBe(true);
      expect(donePuts).toBe(1);
    });

    it('ends an hour after the marker, once a read begun then finds every shard’s snapshot standing', async () => {
      const fake = oldStore();
      const { log, lines, advance } = logOver(fake, { cutOver: true });
      await log.read();
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      advance(30);
      await log.read();
      await log.flush();
      expect(fake.files.has(DONE)).toBe(false);

      advance(31);
      await log.read();
      await log.flush();
      expect(fake.files.has(DONE)).toBe(true);
      expect(lines('audit.anchor_store_sharded')).toEqual([expect.objectContaining({ level: 'info', file: DONE })]);

      // From then on the old files are read no more: an old delta added after is never fetched.
      fake.files.set(oldName('deltas', 70), oldFile(oldName('deltas', 70), anchorAt(CHAIN, 99n)));
      const listed: string[] = [];
      fake.instead.list = (start, most, after) => {
        listed.push(start);
        return fake.real.list(start, most, after);
      };
      const fresh = logOver(fake, { at: new Date(START.getTime() + 80 * MINUTE) });
      await fresh.log.read();
      expect(fresh.log.state()).toBe('read');
      expect(fresh.log.latest(CHAIN)?.seq).toBe(5n);
      expect(fresh.log.latest(OTHER_CHAIN)?.seq).toBe(1n);
      expect(listed.filter((start) => /^e1\/(?:deltas|snapshots)\//.test(start))).toEqual([]);
      expect(fresh.lines('audit.anchors_read')).toEqual([
        expect.objectContaining({ layout: 'sharded', snapshot: false, deltas: 0 }),
      ]);
    });

    it('an old file’s line read while moving: its shard’s snapshot is made again before the record', async () => {
      const fake = oldStore();
      const order: string[] = [];
      fake.instead.put = (name, bytes) => {
        order.push(name);
        return fake.real.put(name, bytes);
      };
      const { log, advance } = logOver(fake, { cutOver: true });
      await log.read();
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      order.length = 0;
      fake.files.set(oldName('deltas', 11), oldFile(oldName('deltas', 11), anchorAt(CHAIN, 9n)));
      advance(61);
      await log.read();
      await log.flush();

      const shard = `/${shardHex(shardOf(chainName(CHAIN)))}/`;
      expect(order).toEqual([expect.stringContaining(shard), expect.stringContaining('/changes/'), DONE]);
      expect(linesOf(fake.files.get(defined(order[0])))[0]).toMatchObject({ chain: chainName(CHAIN), seq: '9' });
    });

    it('a snapshot taken while a read takes an old file’s line in does not stand for its shard', async () => {
      // Organisation 7 is in CHAIN's shard, new to this process: its line waits for the whole read before it is held.
      const NEIGHBOUR = organisation(7);
      expect(shardOf(chainName(NEIGHBOUR))).toBe(shardOf(chainName(CHAIN)));
      const fake = oldStore();
      const { log, advance } = logOver(fake, { cutOver: true });
      await log.read();
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      advance(61);
      // An older version's last two deltas: the newer read first, then the read waits on the older.
      fake.files.set(oldName('deltas', 72), oldFile(oldName('deltas', 72), anchorAt(NEIGHBOUR, 1n)));
      fake.files.set(oldName('deltas', 71), oldFile(oldName('deltas', 71), anchorAt(PLATFORM, 2n)));
      const { promise: waiting, resolve: reached } = Promise.withResolvers<undefined>();
      const { promise: held, resolve: letGo } = Promise.withResolvers<undefined>();
      fake.instead.getAtMost = async (name, most) => {
        if (name === oldName('deltas', 71)) {
          reached(undefined);
          await held;
        }
        return fake.real.getAtMost(name, most);
      };
      const reading = log.read();
      await waiting;
      // Mid-read, an hour past its snapshot: CHAIN's shard is snapshotted again, without the neighbour, still staged.
      log.keep(anchorAt(CHAIN, 7n));
      await log.flush();
      letGo(undefined);
      await reading;
      delete fake.instead.getAtMost;
      expect(fake.files.has(DONE)).toBe(false);

      // A minute on, so the snapshot made now is named newer than the one made mid-read.
      advance(1);
      await log.flush();
      expect(fake.files.has(DONE)).toBe(true);
      const shard = `/${shardHex(shardOf(chainName(CHAIN)))}/`;
      const newest = shardFiles(fake)
        .filter((name) => name.includes(shard) && name.endsWith('-s'))
        .toSorted()
        .at(0);
      expect(linesOf(fake.files.get(defined(newest))).map((line) => line.chain)).toContain(chainName(NEIGHBOUR));
    });

    it('a marker found already there, signed, is taken: the shards are written', async () => {
      const fake = oldStore();
      const { log, alarms } = logOver(fake, { cutOver: true });
      await log.read();
      put(fake, cutoverFile(keys, { epoch: 1, at: START }));
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      expect(shardFiles(fake).length).toBeGreaterThan(0);
      expect(alarms()).toEqual([]);
    });

    it('the marker’s name held by something else: the alarm once, the migration stops, the old files written on', async () => {
      const fake = oldStore();
      const { log, alarms } = logOver(fake, { cutOver: true });
      await log.read();
      fake.files.set(MARKER, gzipSync('someone else'));
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      log.keep(anchorAt(OTHER_CHAIN, 2n));
      await log.flush();
      await log.read();

      expect(alarms()).toEqual([
        expect.objectContaining({ check: 'anchor_store', reason: 'cutover', problem: 'file', file: MARKER }),
      ]);
      expect(shardFiles(fake)).toEqual([]);
      expect([...fake.files.keys()].filter((name) => name.startsWith('e1/deltas/'))).toHaveLength(2);
    });

    it('the record’s name held by something else: the alarm once, and the old files are read on', async () => {
      const fake = oldStore();
      const { log, alarms, advance } = logOver(fake, { cutOver: true });
      await log.read();
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      fake.files.set(DONE, gzipSync('someone else'));
      let donePuts = 0;
      fake.instead.put = (name, bytes) => {
        if (name === DONE) donePuts += 1;
        return fake.real.put(name, bytes);
      };
      advance(61);
      await log.read();
      await log.flush();
      await log.read();
      await log.flush();
      await log.flush();

      // Tried once, then the migration goes no further in this process.
      expect(donePuts).toBe(1);
      expect(alarms()).toEqual([
        expect.objectContaining({ check: 'anchor_store', reason: 'cutover', problem: 'file', file: DONE }),
      ]);
      fake.files.set(oldName('deltas', 75), oldFile(oldName('deltas', 75), anchorAt(CHAIN, 8n)));
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(8n);
    });

    it('a put that fails otherwise is a failed write, tried again', async () => {
      const fake = oldStore();
      const { log, lines } = logOver(fake, { cutOver: true });
      await log.read();
      fake.instead.put = () => Promise.reject(new Error('the store is away'));
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      expect(lines('audit.anchor_store_write_failed')).toHaveLength(1);
      delete fake.instead.put;
      await log.flush();
      expect(fake.files.has(MARKER)).toBe(true);
    });

    it.each([
      ['the marker', () => true],
      ['a shard’s file', (name: string) => SHARD_FILE_NAME.test(name)],
    ])('%s’s name refused as taken and then not there is a failed write, tried again', async (_, refused) => {
      const fake = oldStore();
      const { log, lines, alarms } = logOver(fake, { cutOver: true });
      await log.read();
      fake.instead.put = (name, bytes) =>
        refused(name) ? Promise.reject(new OverwriteRefused()) : fake.real.put(name, bytes);
      log.keep(anchorAt(OTHER_CHAIN, 1n));
      await log.flush();
      expect(lines('audit.anchor_store_write_failed')).toHaveLength(1);
      expect(alarms()).toEqual([]);
      delete fake.instead.put;
      await log.flush();
      expect(fake.files.has(MARKER)).toBe(true);
      expect(shardFiles(fake).length).toBeGreaterThan(0);
    });
  });

  describe('a shard’s file', () => {
    it('sound, costs one signature check, not one a line', async () => {
      const fake = movedStore({ done: true });
      const many = Array.from({ length: 5 }, (_, index) => anchorAt(CHAIN, BigInt(10 + index)));
      const name = shardName(CHAIN, 's', 61);
      fake.files.set(name, shardFile(name, many));
      const { keys: holding, checks } = counting();
      const { log, alarms } = logOver(fake, { holding, at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(14n);
      expect(checks.filter((label) => label === 'audit-anchor')).toEqual([]);
      expect(checks.filter((label) => label === 'audit-anchor-file-v2')).toEqual(['audit-anchor-file-v2']);
      expect(alarms()).toEqual([]);
    });

    it.each([
      [
        'its body changed after it was closed',
        (name: string) => shardFile(name, [anchorAt(CHAIN, 10n)], { body: 'ab' }),
      ],
      ['closed by another key', (name: string) => shardFile(name, [anchorAt(CHAIN, 10n)], { signing: otherKeys })],
      ['closed by a version 1 line for another name', () => oldFile(oldName('snapshots', 61), anchorAt(CHAIN, 10n))],
      ['closed by a line of another kind', () => gzipSync(`${lineOf(anchorAt(CHAIN, 10n))}\n{"k":"c","v":3}\n`)],
      ['with nothing after its lines', () => gzipSync(`${lineOf(anchorAt(CHAIN, 10n))}\n`)],
    ])('%s: read a line at a time, its signed lines counting, `unclosed`', async (_, made) => {
      const fake = movedStore({ done: true });
      const name = shardName(CHAIN, 's', 61);
      fake.files.set(name, made(name));
      const { keys: holding, checks } = counting();
      const { log, alarms } = logOver(fake, { holding, at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(10n);
      // Its one line, then, as it stands for nothing, the old snapshot's two under the shard.
      expect(checks.filter((label) => label === 'audit-anchor')).toHaveLength(3);
      expect(alarms()).toEqual([
        expect.objectContaining({ reason: 'unclosed', kind: 'snapshots', shard: shardHex(shardOf(chainName(CHAIN))) }),
      ]);
    });

    it('not gzip: the alarm, and it stands for nothing', async () => {
      const fake = movedStore({ done: true });
      const name = shardName(CHAIN, 'd', 61);
      fake.files.set(name, Buffer.from('not gzip'));
      const { log, alarms } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(alarms()).toEqual([expect.objectContaining({ reason: 'file', kind: 'deltas' })]);
    });

    it('a line of another shard’s chain is skipped, `misplaced`, and the file stands for nothing', async () => {
      const fake = movedStore({ done: true });
      const name = shardName(CHAIN, 's', 61);
      fake.files.set(name, shardFile(name, [anchorAt(CHAIN, 10n), anchorAt(ELSEWHERE, 3n)]));
      const { log, alarms } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(10n);
      expect(log.latest(ELSEWHERE)).toBeUndefined();
      expect(alarms()).toEqual([
        expect.objectContaining({
          check: 'anchor_store',
          reason: 'misplaced',
          shard: shardHex(shardOf(chainName(CHAIN))),
          lines: 1,
        }),
      ]);
      // Standing for nothing, the shard reached its first file with no sound snapshot: the old files stand under it.
      expect(log.latest(PLATFORM)?.seq).toBe(1n);
    });

    it('dated past the clock is passed over with the alarm, naming its shard, and hides nothing', async () => {
      const fake = movedStore({ done: true });
      const ahead = shardName(CHAIN, 'd', 200);
      fake.files.set(ahead, shardFile(ahead, [anchorAt(CHAIN, 50n)]));
      const name = shardName(CHAIN, 's', 61);
      fake.files.set(name, shardFile(name, [anchorAt(CHAIN, 10n)]));
      const { log, alarms, lines } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(10n);
      expect(alarms()).toEqual([
        expect.objectContaining({ reason: 'future', kind: 'deltas', shard: shardHex(shardOf(chainName(CHAIN))) }),
      ]);
      expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ files: 1 })]);
    });

    it('a name in a shard’s folder it would never write is foreign, never read', async () => {
      const fake = movedStore({ done: true });
      const odd = `e1/shards/${shardHex(shardOf(chainName(CHAIN)))}/${countdown(61)}-${idOf(1)}-x`;
      fake.files.set(odd, Buffer.from('anything'));
      const { log, lines, alarms } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.state()).toBe('read');
      expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ files: 1 })]);
      expect(alarms()).toEqual([]);
    });
  });

  describe('once moved', () => {
    it('reads a shard from its newest sound snapshot and the deltas since, and later only what is newer', async () => {
      const fake = movedStore({ done: true });
      const old = shardName(CHAIN, 'd', 59);
      fake.files.set(old, shardFile(old, [anchorAt(CHAIN, 99n)]));
      const snapshot = shardName(CHAIN, 's', 60);
      fake.files.set(snapshot, shardFile(snapshot, [anchorAt(CHAIN, 10n)]));
      const delta = shardName(CHAIN, 'd', 61);
      fake.files.set(delta, shardFile(delta, [anchorAt(CHAIN, 11n)]));
      const { log } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(11n);
      expect(log.lastFileAt()).toEqual(new Date(START.getTime() + 61 * MINUTE));

      // Another process's write: its list of changes first, then the file. A file no list names is not looked for.
      const later = shardName(CHAIN, 'd', 65);
      const unlisted = shardName(CHAIN, 'd', 66);
      fake.files.set(later, shardFile(later, [anchorAt(CHAIN, 12n)]));
      fake.files.set(unlisted, shardFile(unlisted, [anchorAt(CHAIN, 13n)]));
      const changes = changesName(65);
      put(fake, { name: changes, bytes: changesFile(keys, changes, 1, [later.slice('e1/shards/'.length)]) });
      const fetched: string[] = [];
      fake.instead.getAtMost = (name, most) => {
        fetched.push(name);
        return fake.real.getAtMost(name, most);
      };
      const lists = fake.calls.lists;
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(12n);
      expect(fetched).toEqual([changes, later]);
      // `cutover/`, the rebases and the one folder of changes: no shard's folder listed.
      expect(fake.calls.lists - lists).toBe(3);
    });

    it('a shard whose snapshots are all spoiled stands on the old files under it', async () => {
      const fake = movedStore({ done: true });
      const spoiled = shardName(CHAIN, 's', 61);
      fake.files.set(spoiled, shardFile(spoiled, [anchorAt(CHAIN, 3n, otherKeys)], { signing: otherKeys }));
      const { log, alarms } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)?.seq).toBe(5n);
      expect(alarms().map((line) => line.reason)).toEqual(['signature', 'unclosed']);
    });

    it('with every shard sound, the old files are not read', async () => {
      const fake = movedStore({ done: true });
      const snapshot = shardName(CHAIN, 's', 61);
      fake.files.set(snapshot, shardFile(snapshot, [anchorAt(CHAIN, 3n)]));
      const { log } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      // The old snapshot's 5 is never read: the shard's own snapshot stands for it.
      expect(log.latest(CHAIN)?.seq).toBe(3n);
      expect(log.latest(PLATFORM)).toBeUndefined();
    });

    it('goes back a day of a shard’s spoiled snapshots, and no further: past that the store reads as unreadable', async () => {
      const fake = movedStore({ done: true });
      for (let hour = 0; hour < 26; hour += 1) {
        const name = shardName(CHAIN, 's', 61 + hour * 60);
        fake.files.set(name, shardFile(name, [anchorAt(CHAIN, 3n, otherKeys)], { signing: otherKeys }));
      }
      const { log, lines } = logOver(fake, { at: new Date(START.getTime() + 27 * 60 * MINUTE) });
      await log.read();
      expect(log.state()).toBe('unreadable');
      expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
    });

    it('writes what moved as a shard’s delta, and its snapshot once its hour is up', async () => {
      const fake = movedStore({ done: true });
      const { log, advance } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      advance(5);
      log.keep(anchorAt(CHAIN, 7n));
      await log.flush();
      advance(60);
      log.keep(anchorAt(CHAIN, 8n));
      await log.flush();
      const kinds = shardFiles(fake)
        .toSorted()
        .toReversed()
        .map((name) => name.slice(-1));
      expect(kinds).toEqual(['s', 'd', 's']);
      // A restart holds the newest, the wound-back history caught across it.
      const fresh = logOver(fake, { at: new Date(START.getTime() + 140 * MINUTE) });
      await fresh.log.read();
      expect(fresh.log.latest(CHAIN)?.seq).toBe(8n);
      fresh.log.keep(anchorAt(CHAIN, 7n));
      expect(fresh.alarms()).toEqual([expect.objectContaining({ reason: 'behind' })]);
    });

    it('a snapshot of its own is where a later read of the shard stops: spoiled files older than it cost nothing', async () => {
      const fake = movedStore({ done: true });
      const { log, alarms, advance } = logOver(fake, { at: new Date(START.getTime() + 95 * MINUTE) });
      await log.read();
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      // More than a day's spoiled snapshots, named older than its own: a walk past its own would refuse the read.
      for (let minute = 0; minute < 30; minute += 1) {
        fake.files.set(shardName(CHAIN, 's', 61 + minute), gzipSync('planted'));
      }
      advance(1);
      await log.read();
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)?.seq).toBe(6n);
      expect(alarms()).toEqual([]);
    });

    it('says how near the edge it holds at most hourly, however the shards’ snapshots fall due', async () => {
      const fake = movedStore({ done: true });
      const { log, lines, advance } = logOver(fake, {
        at: new Date(START.getTime() + 70 * MINUTE),
        mostFileBytes: 500,
      });
      await log.read();
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      advance(5);
      log.keep(anchorAt(ELSEWHERE, 1n));
      await log.flush();
      advance(60);
      log.keep(anchorAt(CHAIN, 7n));
      await log.flush();
      expect(lines('audit.anchor_store_near_memory')).toHaveLength(2);
    });

    it('a shard file’s name held by other bytes: the alarm naming its shard, its lines again under a new name', async () => {
      const fake = movedStore({ done: true });
      const { log, alarms } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      fake.instead.put = async (name, bytes) => {
        if (SHARD_FILE_NAME.test(name)) await fake.real.put(name, Buffer.from('someone else'));
        return fake.real.put(name, bytes);
      };
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      delete fake.instead.put;
      await log.flush();
      expect(alarms()).toEqual([
        expect.objectContaining({ reason: 'overwrite', shard: shardHex(shardOf(chainName(CHAIN))) }),
      ]);
      const sound = shardFiles(fake).filter((name) => fake.files.get(name)?.toString() !== 'someone else');
      expect(sound.flatMap((name) => linesOf(fake.files.get(name)).filter((line) => line.k === 'a'))).toEqual([
        expect.objectContaining({ seq: '6' }),
      ]);
    });
  });

  describe('the lists of changes: one list call a run, after the first read (PL-65 PR2)', () => {
    /** A moved store read once by a process of its own, at 70 minutes. */
    const readOnce = async () => {
      const fake = movedStore({ done: true });
      const made = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await made.log.read();
      return { fake, ...made };
    };
    const listed = (fake: FakeWriteOnceStore, minutes: number, files: readonly string[], signing = keys): string => {
      const name = changesName(minutes);
      fake.files.set(
        name,
        changesFile(
          signing,
          name,
          1,
          files.map((file) => file.slice('e1/shards/'.length)),
        ),
      );
      return name;
    };

    it('a file a list names and not there yet is looked for at each read, then read once it lands', async () => {
      const { fake, log } = await readOnce();
      const later = shardName(CHAIN, 'd', 71);
      listed(fake, 71, [later]);
      await log.read();
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)).toBeUndefined();
      fake.files.set(later, shardFile(later, [anchorAt(CHAIN, 12n)]));
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(12n);
      // Read, it is looked for no more.
      const gets = fake.calls.smallGets;
      await log.read();
      expect(fake.calls.smallGets).toBe(gets);
    });

    it('two lists named in the same millisecond: the one listed after the other, read later, is still read', async () => {
      const { fake, log } = await readOnce();
      const [first, second] = [shardName(CHAIN, 'd', 71, 1), shardName(CHAIN, 'd', 71, 2)];
      fake.files.set(first, shardFile(first, [anchorAt(CHAIN, 12n)]));
      fake.files.set(changesName(71, 1), changesFile(keys, changesName(71, 1), 1, [first.slice('e1/shards/'.length)]));
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(12n);
      // The same moment, an ID sorting after: by name alone it would read as older than the one read.
      fake.files.set(second, shardFile(second, [anchorAt(CHAIN, 13n)]));
      fake.files.set(changesName(71, 2), changesFile(keys, changesName(71, 2), 1, [second.slice('e1/shards/'.length)]));
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(13n);
      const gets = fake.calls.smallGets;
      await log.read();
      expect(fake.calls.smallGets).toBe(gets);
    });

    it('a file named and never landing is given up after an hour', async () => {
      const { fake, log, advance } = await readOnce();
      listed(fake, 71, [shardName(CHAIN, 'd', 71)]);
      await log.read();
      advance(62);
      await log.read();
      const gets = fake.calls.smallGets;
      await log.read();
      expect(fake.calls.smallGets).toBe(gets);
      expect(log.state()).toBe('read');
    });

    it.each([
      ['signed by another key', (fake: FakeWriteOnceStore) => listed(fake, 71, [shardName(CHAIN, 'd', 71)], otherKeys)],
      [
        'not one',
        (fake: FakeWriteOnceStore) => {
          fake.files.set(changesName(71), gzipSync('anything'));
          return changesName(71);
        },
      ],
      [
        'naming a file of another form',
        (fake: FakeWriteOnceStore) => {
          const name = changesName(71);
          const { signature, keyVersion } = keys.sign('audit-anchor', ['audit-anchor-changes', name, '1', 'x']);
          const line = JSON.stringify({
            k: 'changes',
            name,
            epoch: 1,
            files: ['x'],
            kv: keyVersion,
            sig: signature.toString('base64'),
          });
          fake.files.set(name, gzipSync(`${line}\n`));
          return name;
        },
      ],
    ])('a list %s is the alarm, and names nothing', async (_, made) => {
      const { fake, log, alarms } = await readOnce();
      const file = shardName(CHAIN, 'd', 71);
      fake.files.set(file, shardFile(file, [anchorAt(CHAIN, 12n)]));
      const name = made(fake);
      await log.read();
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)).toBeUndefined();
      expect(alarms()).toEqual([expect.objectContaining({ check: 'anchor_store', reason: 'changes', file: name })]);
    });

    it('a list too large to be one is the alarm, never fetched past its bound', async () => {
      const { fake, log, alarms } = await readOnce();
      const name = changesName(71);
      fake.files.set(name, Buffer.alloc(40_000));
      await log.read();
      expect(alarms()).toEqual([expect.objectContaining({ reason: 'changes', file: name, problem: 'too-large' })]);
    });

    it('a list dated past the clock is passed over with the alarm; a name of another form is foreign', async () => {
      const { fake, log, alarms, lines } = await readOnce();
      listed(fake, 200, [shardName(CHAIN, 'd', 71)]);
      fake.files.set('e1/shards/changes/odd', gzipSync('anything'));
      await log.read();
      expect(alarms()).toEqual([expect.objectContaining({ reason: 'future', kind: 'changes' })]);
      expect(lines('audit.anchor_store_foreign')).toEqual([expect.objectContaining({ files: 2 })]);
    });

    it('a list listed and then not there is a failed read', async () => {
      const { fake, log, lines } = await readOnce();
      const name = listed(fake, 71, [shardName(CHAIN, 'd', 71)]);
      fake.instead.getAtMost = (got, most) =>
        got === name ? Promise.resolve('missing') : fake.real.getAtMost(got, most);
      await log.read();
      expect(lines('audit.anchor_store_read_failed')).toHaveLength(1);
    });

    it('at the first read, lists from the last few minutes are read after the walk; older ones not', async () => {
      const fake = movedStore({ done: true });
      const recent = shardName(CHAIN, 'd', 68);
      listed(fake, 68, [recent]);
      const older = changesName(50, 2);
      fake.files.set(older, gzipSync('never fetched'));
      const fetched: string[] = [];
      fake.instead.getAtMost = (name, most) => {
        fetched.push(name);
        return fake.real.getAtMost(name, most);
      };
      const { log, alarms } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      // The recent list's file is not there yet: the walk can't have seen it, and the list keeps it looked for.
      expect(fetched).toContain(changesName(68));
      expect(fetched).not.toContain(older);
      expect(alarms()).toEqual([]);
      fake.files.set(recent, shardFile(recent, [anchorAt(CHAIN, 12n)]));
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(12n);
    });

    it.each([
      ['its name taken first (the alarm)', () => Promise.reject(new OverwriteRefused())],
      ['the store away', () => Promise.reject(new Error('the store is away'))],
    ])('a list that fails, %s: the files written all the same, and named in the next list', async (_, failing) => {
      const fake = movedStore({ done: true });
      const { log, lines } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      const other = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await other.log.read();
      fake.instead.put = (name, bytes) => (name.includes('/changes/') ? failing() : fake.real.put(name, bytes));
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      delete fake.instead.put;
      const [file] = shardFiles(fake).filter((name) => SHARD_FILE_NAME.test(name));
      expect(file).toBeDefined();
      await other.log.read();
      expect(other.log.latest(CHAIN)).toBeUndefined();
      // The next write, with nothing of its own to write, lists what no list named yet.
      await log.flush();
      const listsMade = [...fake.files.keys()].filter((name) => name.includes('/changes/'));
      expect(listsMade).toHaveLength(1);
      expect(linesOf(fake.files.get(defined(listsMade[0])))[0]?.files).toEqual([
        defined(file).slice('e1/shards/'.length),
      ]);
      await other.log.read();
      expect(other.log.latest(CHAIN)?.seq).toBe(6n);
      expect(lines('audit.integrity_failed').length + lines('audit.anchor_store_write_failed').length).toBe(1);
    });

    /** Reads, a minute apart, until `done` says so: how many it took, and the lists each asked. */
    const readsUntil = async (made: ReturnType<typeof logOver>, fake: FakeWriteOnceStore, done: () => boolean) => {
      const lists: number[] = [];
      for (let read = 1; read <= 9; read += 1) {
        const before = fake.calls.lists;
        await made.log.read();
        lists.push(fake.calls.lists - before);
        if (done()) return { reads: read, lists };
        made.advance(1);
      }
      return { reads: Number.POSITIVE_INFINITY, lists };
    };

    it('files written and their list never (the writer stopped): the hourly walk finds them, 32 shards a read', async () => {
      const fake = movedStore({ done: true });
      const made = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await made.log.read();
      // Another process's file, as it wrote it before it stopped: no list names it.
      const delta = shardName(CHAIN, 'd', 75);
      fake.files.set(delta, shardFile(delta, [anchorAt(CHAIN, 12n)]));
      made.advance(10);
      await made.log.read();
      expect(made.log.latest(CHAIN)).toBeUndefined();
      made.advance(51);
      const { reads, lists } = await readsUntil(made, fake, () => made.log.latest(CHAIN)?.seq === 12n);
      // Shard 150 among the fifth 32 walked; each read lists 32 folders, `cutover/`, the rebases and the changes'.
      expect(reads).toBe(Math.floor(shardOf(chainName(CHAIN)) / 32) + 1);
      expect(new Set(lists)).toEqual(new Set([32 + 3]));
    });

    it('a walk passes over every file read since the last, fetching nothing again', async () => {
      const { fake, log, advance } = await readOnce();
      const file = shardName(CHAIN, 'd', 71);
      fake.files.set(file, shardFile(file, [anchorAt(CHAIN, 12n)]));
      listed(fake, 71, [file]);
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(12n);
      const fetched: string[] = [];
      fake.instead.getAtMost = (name, most) => {
        fetched.push(name);
        return fake.real.getAtMost(name, most);
      };
      advance(61);
      for (let read = 0; read < 8; read += 1) {
        await log.read();
        advance(1);
      }
      expect(fetched).toEqual([]);
    });

    it('a read that fails mid-walk keeps no shard walked; the next takes the same ones and moves on', async () => {
      const { fake, log, advance } = await readOnce();
      advance(61);
      const walked: string[] = [];
      let failing = true;
      fake.instead.list = (start, most, after) => {
        if (/^e1\/shards\/[0-9a-f]{2}\/$/.test(start)) walked.push(start);
        if (failing && start === 'e1/shards/10/') return Promise.reject(new Error('the store is away'));
        return fake.real.list(start, most, after);
      };
      await log.read();
      failing = false;
      expect(walked.at(-1)).toBe('e1/shards/10/');
      walked.length = 0;
      await log.read();
      expect(walked[0]).toBe('e1/shards/00/');
      expect(walked).toHaveLength(32);
      walked.length = 0;
      await log.read();
      expect(walked[0]).toBe('e1/shards/20/');
    });

    it('a walk reaches back a little before the last began: a file named minutes before it, landing after, is found', async () => {
      const { fake, log, advance } = await readOnce();
      // Named three minutes before the first walk (at 70), landing after it, in no list: within the 5 minutes' margin.
      const late = shardName(CHAIN, 'd', 67);
      fake.files.set(late, shardFile(late, [anchorAt(CHAIN, 12n)]));
      advance(61);
      const made = { log, advance } as unknown as ReturnType<typeof logOver>;
      const { reads } = await readsUntil(made, fake, () => log.latest(CHAIN)?.seq === 12n);
      expect(reads).toBeLessThanOrEqual(8);
    });

    it('a walk reaches back past the oldest file of its own no list has named yet', async () => {
      const fake = movedStore({ done: true });
      const made = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await made.log.read();
      // Its own file at 75, every list after failing, for hours.
      fake.instead.put = (name, bytes) =>
        name.includes('/changes/') ? Promise.reject(new Error('the store is away')) : fake.real.put(name, bytes);
      made.advance(5);
      made.log.keep(anchorAt(OTHER_CHAIN, 1n));
      await made.log.flush();
      made.advance(61);
      await readsUntil(made, fake, () => false);
      // Another's file named at 80, landing only now, after every shard's last walk began.
      const late = shardName(CHAIN, 'd', 80);
      fake.files.set(late, shardFile(late, [anchorAt(CHAIN, 12n)]));
      made.advance(61);
      const { reads } = await readsUntil(made, fake, () => made.log.latest(CHAIN)?.seq === 12n);
      expect(reads).toBeLessThanOrEqual(8);
    });

    it('a forged list named minutes ahead hides no real list after it (review probe)', async () => {
      const { fake, log, alarms } = await readOnce();
      const junk = changesName(74, 9);
      fake.files.set(junk, gzipSync('junk'));
      const real = shardName(CHAIN, 'd', 71);
      fake.files.set(real, shardFile(real, [anchorAt(CHAIN, 12n)]));
      listed(fake, 71, [real]);
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(12n);
      // A later real list, still before the forged one's time, is read too; the forged one fetched and said once.
      const next = shardName(CHAIN, 'd', 72);
      fake.files.set(next, shardFile(next, [anchorAt(CHAIN, 13n)]));
      fake.files.set(changesName(72), changesFile(keys, changesName(72), 1, [next.slice('e1/shards/'.length)]));
      const fetched: string[] = [];
      fake.instead.getAtMost = (name, most) => {
        fetched.push(name);
        return fake.real.getAtMost(name, most);
      };
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(13n);
      expect(fetched).not.toContain(junk);
      expect(alarms()).toEqual([expect.objectContaining({ reason: 'changes', file: junk })]);
    });

    it('an unsent shard file is named in the list of the write that lands it', async () => {
      const fake = movedStore({ done: true });
      const { log } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      fake.instead.put = (name, bytes) =>
        SHARD_FILE_NAME.test(name) ? Promise.reject(new Error('the store is away')) : fake.real.put(name, bytes);
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      expect([...fake.files.keys()].filter((name) => name.includes('/changes/'))).toEqual([]);
      delete fake.instead.put;
      await log.flush();
      const [file] = shardFiles(fake).filter((name) => SHARD_FILE_NAME.test(name));
      const lists = [...fake.files.keys()].filter((name) => name.includes('/changes/'));
      expect(lists).toHaveLength(1);
      expect(linesOf(fake.files.get(defined(lists[0])))[0]?.files).toEqual([defined(file).slice('e1/shards/'.length)]);
    });

    it('a file a walk listed and then not there fails the read; only a file a list names is waited for', async () => {
      const fake = movedStore({ done: true });
      const name = shardName(CHAIN, 's', 61);
      fake.files.set(name, shardFile(name, [anchorAt(CHAIN, 3n)]));
      fake.instead.getAtMost = (got, most) =>
        got === name ? Promise.resolve('missing') : fake.real.getAtMost(got, most);
      const { log, lines } = logOver(fake, { at: new Date(START.getTime() + 70 * MINUTE) });
      await log.read();
      expect(log.state()).toBe('unreadable');
      expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
    });
  });

  describe('every file fetched no further than this process can hold (PL-65)', () => {
    it.each([
      ['too large', 'too-large'],
      ['beyond a plain read', 'unreadable'],
    ] as const)('a delta %s is a spoiled file: the alarm, and the read goes on', async (_, problem) => {
      const fake = oldStore();
      const delta = oldName('deltas', 5);
      fake.files.set(delta, oldFile(delta, anchorAt(CHAIN, 9n)));
      const asked: number[] = [];
      fake.instead.getAtMost = (name, most) => {
        if (name !== delta) return fake.real.getAtMost(name, most);
        asked.push(most);
        return Promise.resolve(problem);
      };
      const { log, alarms } = logOver(fake, { mostFileBytes: 50_000 });
      await log.read();
      expect(asked).toEqual([50_000]);
      expect(log.state()).toBe('read');
      expect(log.latest(CHAIN)?.seq).toBe(5n);
      expect(alarms()).toEqual([
        expect.objectContaining({ reason: 'file', kind: 'deltas', problem, mostBytes: 50_000 }),
      ]);
    });

    it('a file listed and then not there is a failed read', async () => {
      const fake = oldStore();
      fake.instead.getAtMost = (name, most) =>
        name.includes('/snapshots/') ? Promise.resolve('missing') : fake.real.getAtMost(name, most);
      const { log, lines } = logOver(fake);
      await log.read();
      expect(log.state()).toBe('unreadable');
      expect(lines('audit.anchor_store_unreadable')).toHaveLength(1);
    });

    it('a name taken by bytes too large to compare is other bytes: the alarm', async () => {
      const fake = oldStore();
      const { log, alarms } = logOver(fake);
      await log.read();
      fake.instead.put = async (name, bytes) => {
        await fake.real.put(name, Buffer.alloc(bytes.length + 1));
        return fake.real.put(name, bytes);
      };
      const asked: number[] = [];
      fake.instead.getAtMost = (name, most) => {
        asked.push(most);
        return fake.real.getAtMost(name, most);
      };
      log.keep(anchorAt(CHAIN, 6n));
      await log.flush();
      expect(asked).toHaveLength(1);
      expect(alarms()).toEqual([expect.objectContaining({ reason: 'overwrite', kind: 'deltas' })]);
    });
  });
});

/** A value the test knows is there, or the test fails saying so. */
function defined<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('the test expected a value here');
  return value;
}
