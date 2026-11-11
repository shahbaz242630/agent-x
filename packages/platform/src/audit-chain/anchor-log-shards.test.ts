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
import { closingV2Message, shardHex, shardOf } from './shards.ts';
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
      const shards = new Set([CHAIN, OTHER_CHAIN, PLATFORM].map((chain) => shardOf(chainName(chain))));
      expect(order.slice(1)).toHaveLength(shards.size);
      expect(order.slice(1).every((name) => /^e1\/shards\/[0-9a-f]{2}\/\d{13}-[0-9a-f-]{36}-s$/.test(name))).toBe(true);
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
      expect(order).toEqual([expect.stringContaining(shard), DONE]);
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
      advance(61);
      await log.read();
      await log.flush();
      await log.read();
      await log.flush();

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
      ['a shard’s file', (name: string) => name.startsWith('e1/shards/')],
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

      const later = shardName(CHAIN, 'd', 65);
      fake.files.set(later, shardFile(later, [anchorAt(CHAIN, 12n)]));
      const fetched: string[] = [];
      fake.instead.getAtMost = (name, most) => {
        fetched.push(name);
        return fake.real.getAtMost(name, most);
      };
      await log.read();
      expect(log.latest(CHAIN)?.seq).toBe(12n);
      expect(fetched).toEqual([later]);
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
        if (name.startsWith('e1/shards/')) await fake.real.put(name, Buffer.from('someone else'));
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
