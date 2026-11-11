// Shards in and out of memory (PL-65 PR3): past what a process can hold, the least recently used shard goes, never one
// with lines waiting, unsent or pinned, and one let go is read again, every signature checked, as a first read reads it.
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider, type KeyMaterial, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { type Anchor, signAnchor, signPass, signProgress } from './anchor.ts';
import { type AnchorLog, createAnchorLog } from './anchor-log.ts';
import { type Chain, chainName } from './chain.ts';
import { cutoverFile, shardsDoneFile } from './cutover.ts';
import { rebaseFile, rebaseFileName, signRebase } from './rebase.ts';
import { closingV2Message, shardHex, shardOf } from './shards.ts';

const keyMaterial = (fill: number): KeyMaterial =>
  byPurpose((purpose) => ({
    current: 1,
    versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + fill)]]),
  })) satisfies KeyMaterial;
const keys = createKeyProvider(keyMaterial(1));
const otherKeys = createKeyProvider(keyMaterial(50));

const START = new Date('2026-11-02T09:00:00.000Z');
const MINUTE = 60_000;
const PLATFORM: Chain = { kind: 'platform' };
const organisation = (index: number): Chain => ({
  kind: 'organisation',
  orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
});
const shardOfChain = (chain: Chain): number => shardOf(chainName(chain));
const LAST_MS = 9_999_999_999_999;
const ID = '00000000-0000-4000-8000-000000000009';

/** An old file: its lines, closed by a version 1 line for its name. */
const oldFile = (name: string, ...anchors: readonly Anchor[]): Buffer => {
  const { signature, keyVersion } = keys.sign('audit-anchor', ['audit-anchor-file', name, '1', String(anchors.length)]);
  const closing = { k: 'c', name, epoch: 1, lines: anchors.length, kv: keyVersion, sig: signature.toString('base64') };
  return gzipSync(`${[...anchors.map(lineOf), JSON.stringify(closing)].join('\n')}\n`);
};

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

/** A shard's file as the log writes one, signed with `signing`: its lines, closed by a version 2 line over them. */
const shardFile = (name: string, anchors: readonly Anchor[], signing: KeyProvider): Buffer => {
  const text = anchors.map((anchor) => `${lineOf(anchor)}\n`).join('');
  const body = createHash('sha256').update(text).digest('hex');
  const { signature, keyVersion } = signing.sign('audit-anchor', closingV2Message(name, 1, anchors.length, body));
  const closing = { k: 'c', v: 2, name, epoch: 1, lines: anchors.length, body, kv: keyVersion };
  return gzipSync(`${text}${JSON.stringify({ ...closing, sig: signature.toString('base64') })}\n`);
};
/** One organisation in each of `count` shards, none the platform's: so each shard holds one chain. */
const oneAShard = (count: number): Chain[] => {
  const found = new Map<number, Chain>();
  for (let index = 1; found.size < count; index += 1) {
    const chain = organisation(index);
    const shard = shardOfChain(chain);
    if (shard !== shardOfChain(PLATFORM) && !found.has(shard)) found.set(shard, chain);
  }
  return [...found.values()];
};
const CHAINS = oneAShard(40);

const anchorOf = (chain: Chain, seq: bigint, at: Date, signing = keys): Anchor =>
  signAnchor(signing, chain, { seq, hash: Buffer.alloc(32, Number(seq % 256n)), macKeyVersion: 2 }, at, 1);

/** A store moved on and the migration done: the shards alone. */
const shardedStore = (): FakeWriteOnceStore => {
  const fake = createFakeWriteOnceStore();
  for (const file of [
    cutoverFile(keys, { epoch: 1, at: START }),
    shardsDoneFile(keys, { epoch: 1, at: new Date(START.getTime() + 61 * MINUTE) }),
  ])
    fake.files.set(file.name, file.bytes);
  return fake;
};

interface Made {
  readonly fake: FakeWriteOnceStore;
  readonly clock: { at: Date };
  readonly logs: LogCapture;
}

const logOf = (
  { fake, clock, logs }: Made,
  {
    evicts = false,
    mostFileBytes = 50_000_000,
    holding = keys,
  }: { evicts?: boolean; mostFileBytes?: number; holding?: KeyProvider } = {},
): AnchorLog =>
  createAnchorLog({
    store: fake.store,
    keys: holding,
    logger: testLogger(logs),
    now: () => clock.at,
    epoch: 1,
    alertAfterMs: 15 * MINUTE,
    mostFileBytes,
    evicts,
  });

/**
 * A sharded store a writer filled: every chain of `chains` anchored at 5, the platform at 1, each shard's first file a
 * snapshot; then each anchored again at 6, a delta. Ten minutes later, a reader to read it.
 */
async function world(chains: readonly Chain[] = CHAINS) {
  const made: Made = {
    fake: shardedStore(),
    clock: { at: new Date(START.getTime() + 62 * MINUTE) },
    logs: new LogCapture(),
  };
  const writer = logOf(made);
  await writer.read();
  for (const chain of [PLATFORM, ...chains]) writer.keep(anchorOf(chain, chain === PLATFORM ? 1n : 5n, made.clock.at));
  await writer.flush();
  made.clock.at = new Date(made.clock.at.getTime() + MINUTE);
  for (const chain of chains) writer.keep(anchorOf(chain, 6n, made.clock.at));
  await writer.flush();
  made.clock.at = new Date(made.clock.at.getTime() + 10 * MINUTE);
  const lines = (event: string) => made.logs.lines().filter((line) => line.event === event);
  return { ...made, writer, lines, alarms: () => lines('audit.integrity_failed') };
}

/** A reader that lets shards go, at a budget that holds the platform's shard and about `shards` others of one chain. */
const tight = (made: Made, shards = 8, holding = keys): AnchorLog =>
  logOf(made, { evicts: true, mostFileBytes: budgetFor(shards), holding });

/** Each organisation seen counts 100, each chain held 340, each name read 160: `shards` of these, with room to spare. */
const budgetFor = (shards: number): number => Math.ceil((CHAINS.length * 100 + (shards + 1) * 500) / 0.8);

const held = (log: AnchorLog, chains: readonly Chain[] = CHAINS): Chain[] => chains.filter((chain) => log.holds(chain));
const letGo = (log: AnchorLog, chains: readonly Chain[] = CHAINS): Chain[] =>
  chains.filter((chain) => !log.holds(chain));

/** Pins and releases other shards' chains, the least recently used first, until `chain`'s shard is let go. */
async function evicted(log: AnchorLog, chain: Chain): Promise<void> {
  for (const other of CHAINS) {
    if (!log.holds(chain)) return;
    if (other === chain) continue;
    const release = await log.pin(other);
    release?.();
  }
  expect(log.holds(chain)).toBe(false);
}

const plain = (line: Anchor | undefined) =>
  line === undefined ? undefined : { seq: line.seq, hash: line.hash.toString('hex'), at: line.at.toISOString() };

/** A deferred step: the call waits until `open` is called. */
const gate = () => {
  let open = (): void => undefined;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
};

describe('SEC-ANC-05 shards in and out of memory (PL-65 PR3)', () => {
  describe('the budget', () => {
    it('a store within what can be held: every shard held, nothing let go, as before', async () => {
      const made = await world();
      const log = logOf(made, { evicts: true });
      await log.read();
      expect(log.state()).toBe('read');
      expect(held(log)).toHaveLength(CHAINS.length);
      expect(made.logs.lines().filter((line) => line.event === 'audit.anchor_shards_evicted')).toHaveLength(0);
      for (const chain of CHAINS) expect(log.latest(chain)?.seq).toBe(6n);
    });

    it('a store past it: read all the same, the least recently used let go, what is held under the budget', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      expect(log.state()).toBe('read');
      const memory = log.memoryHeld();
      expect(memory.bytes).toBeLessThanOrEqual(memory.mostBytes);
      expect(held(log).length).toBeGreaterThan(0);
      expect(letGo(log).length).toBeGreaterThan(0);
      expect(made.lines('audit.anchor_shards_evicted').length).toBeGreaterThan(0);
      // A chain let go says nothing: Tx A waits (anchor_pending), it is never compared with nothing.
      const away = letGo(log)[0] ?? PLATFORM;
      expect(log.latest(away)).toBeUndefined();
      expect(log.lastPass(away)).toBeUndefined();
      expect(log.lastProgress(away)).toBeUndefined();
      // Seen all the same: an organisation taken off the list is still missed.
      expect(log.organisations().toSorted()).toEqual(
        CHAINS.map((chain) => (chain.kind === 'organisation' ? chain.orgId : '')).toSorted(),
      );
      expect(made.alarms()).toEqual([]);
    });

    it('the same store read whole by a log that never lets go, past the budget: refused, as before (the operator’s)', async () => {
      const made = await world();
      const log = logOf(made, { mostFileBytes: budgetFor(8) });
      await log.read();
      expect(log.state()).toBe('unreadable');
      expect(made.lines('audit.anchor_store_beyond_memory')).toHaveLength(1);
      // It never lets go, so it holds every shard, and pins at once.
      expect(log.holds(CHAINS[0] ?? PLATFORM)).toBe(true);
      const release = await log.pin(CHAINS[0] ?? PLATFORM);
      expect(release).toBeDefined();
      release?.();
    });

    it('the platform chain’s shard is never let go', async () => {
      const made = await world();
      const log = tight(made, 1);
      await log.read();
      for (const chain of CHAINS) (await log.pin(chain))?.();
      expect(log.holds(PLATFORM)).toBe(true);
      expect(log.latest(PLATFORM)?.seq).toBe(1n);
    });

    it('a shard over the budget alone holds only its own chains: it stays let go, said, and the others are held', async () => {
      // Twenty chains in one shard, past a budget the others fit in.
      const crowd: Chain[] = [];
      const shard = shardOfChain(CHAINS[0] ?? PLATFORM);
      for (let index = 1; crowd.length < 60; index += 1) {
        const chain = organisation(index);
        if (shardOfChain(chain) === shard) crowd.push(chain);
      }
      const made = await world([...CHAINS.slice(1, 6), ...crowd]);
      const log = logOf(made, { evicts: true, mostFileBytes: 12_000 });
      await log.read();
      expect(log.state()).toBe('read');
      expect(log.holds(crowd[0] ?? PLATFORM)).toBe(false);
      expect(await log.pin(crowd[0] ?? PLATFORM)).toBeUndefined();
      expect(made.lines('audit.anchor_shard_unreadable').at(-1)).toMatchObject({
        level: 'error',
        shard: shardHex(shard),
        reason: 'memory',
      });
      // Every other organisation is held, or read again when asked for.
      for (const chain of CHAINS.slice(1, 6)) {
        const release = await log.pin(chain);
        expect(log.latest(chain)?.seq).toBe(6n);
        release?.();
      }
      expect(log.memoryHeld().bytes).toBeLessThanOrEqual(log.memoryHeld().mostBytes);
    });
  });

  describe('read again', () => {
    it('a pin reads a shard let go again, as a first read: every line the same as one never let go', async () => {
      const made = await world();
      const log = tight(made);
      const whole = logOf(made);
      await log.read();
      await whole.read();
      for (const chain of letGo(log)) {
        const release = await log.pin(chain);
        expect(release).toBeDefined();
        expect(log.holds(chain)).toBe(true);
        expect(plain(log.latest(chain))).toEqual(plain(whole.latest(chain)));
        release?.();
        expect(log.memoryHeld().bytes).toBeLessThanOrEqual(log.memoryHeld().mostBytes);
      }
      expect(made.alarms()).toEqual([]);
    });

    it('every signature checked again: the closing line of each of its files, as at a first read', async () => {
      const made = await world();
      const checks: string[] = [];
      const counting: KeyProvider = {
        ...keys,
        verifySignature(purpose, version, message: Message, signature) {
          checks.push(String(message[0]));
          return keys.verifySignature(purpose, version, message, signature);
        },
      };
      const log = tight(made, 8, counting);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      checks.length = 0;
      (await log.pin(away))?.();
      // Its snapshot and its delta, each closed over its whole body.
      expect(checks.filter((check) => check === 'audit-anchor-file-v2')).toHaveLength(2);
    });

    it('a delta of a shard let go spoiled meanwhile: the alarm on its read again, and its chain as a fresh read says', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      const folder = `e1/shards/${shardHex(shardOfChain(away))}/`;
      const delta = [...made.fake.files.keys()].find((name) => name.startsWith(folder) && name.endsWith('-d')) ?? '';
      // Its line signed with a key not ours, put back under the same name.
      made.fake.files.set(delta, gzipSync(`${JSON.stringify({ k: 'a', chain: chainName(away), seq: '9' })}\n`));
      const release = await log.pin(away);
      expect(made.alarms().map((alarm) => alarm.reason)).toContain('unclosed');
      const fresh = logOf(made);
      await fresh.read();
      expect(plain(log.latest(away))).toEqual(plain(fresh.latest(away)));
      expect(log.latest(away)?.seq).toBe(5n);
      release?.();
    });

    it('a file added to a shard let go, signed with another key: the alarm, and the chain never moves on', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      made.clock.at = new Date(made.clock.at.getTime() + MINUTE);
      const name = `e1/shards/${shardHex(shardOfChain(away))}/${String(LAST_MS - made.clock.at.getTime())}-${ID}-d`;
      made.fake.files.set(name, shardFile(name, [anchorOf(away, 50n, made.clock.at, otherKeys)], otherKeys));
      const release = await log.pin(away);
      expect(made.alarms().map((alarm) => alarm.reason)).toEqual(['signature', 'unclosed']);
      expect(log.latest(away)?.seq).toBe(6n);
      release?.();
    });

    it('a shard let go whose every snapshot is spoiled: read again on the old files under it, as a fresh read is', async () => {
      const made = await world();
      // An old snapshot holding every chain further on, as one from before the migration might; and one shard's own
      // snapshot spoiled before the first read, so that read reads the old files too, and marks them read.
      const old = `e1/snapshots/${String(LAST_MS - START.getTime())}-${ID}`;
      const inOld = CHAINS.slice(0, 15);
      made.fake.files.set(old, oldFile(old, ...inOld.map((chain) => anchorOf(chain, 9n, START))));
      const first = CHAINS.at(-1) ?? PLATFORM;
      const firstFolder = `e1/shards/${shardHex(shardOfChain(first))}/`;
      for (const name of made.fake.files.keys())
        if (name.startsWith(firstFolder) && name.endsWith('-s')) made.fake.files.set(name, gzipSync('spoiled'));
      // Room for the old snapshot's lines as it is opened, and not for every shard.
      const log = tight(made, 12);
      await log.read();
      expect(log.state()).toBe('read');
      const [away = PLATFORM, steady = PLATFORM] = held(log, inOld);
      expect(log.latest(away)?.seq).toBe(9n);
      // `steady` held throughout, with what the first read took from the old files.
      const steadyRelease = await log.pin(steady);
      await evicted(log, away);
      expect(log.latest(steady)?.seq).toBe(9n);
      // An old delta since, moving the held chain on: read again for `away` alone, it moves nothing held.
      const delta = `e1/deltas/${String(LAST_MS - START.getTime() - MINUTE)}-${ID}`;
      made.fake.files.set(delta, oldFile(delta, anchorOf(steady, 12n, START)));
      const folder = `e1/shards/${shardHex(shardOfChain(away))}/`;
      for (const name of made.fake.files.keys())
        if (name.startsWith(folder) && name.endsWith('-s')) made.fake.files.set(name, gzipSync('spoiled'));
      const release = await log.pin(away);
      expect(release).toBeDefined();
      expect(made.alarms().map((alarm) => alarm.reason)).toContain('unclosed');
      const fresh = logOf(made);
      await fresh.read();
      expect(log.latest(away)?.seq).toBe(9n);
      expect(plain(log.latest(away))).toEqual(plain(fresh.latest(away)));
      // Only its own lines taken from the old files: a held shard's chain there moves nothing.
      expect(log.latest(steady)?.seq).toBe(9n);
      release?.();
      steadyRelease?.();
      // Never let go again: reading it back means the old files whole.
      for (const other of CHAINS) (await log.pin(other))?.();
      expect(log.holds(away)).toBe(true);
    });

    it('a store call failing: the shard stays let go, said, and is read again when next asked for', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      made.fake.instead.list = () => Promise.reject(new Error('the store is away'));
      expect(await log.pin(away)).toBeUndefined();
      expect(made.lines('audit.anchor_shard_unreadable').at(-1)).toMatchObject({ reason: 'store' });
      delete made.fake.instead.list;
      const release = await log.pin(away);
      expect(log.latest(away)?.seq).toBe(6n);
      release?.();
    });

    it('a shard’s rebase read before it was let go stands again when it is read again', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const chain = held(log)[0] ?? PLATFORM;
      const rebase = signRebase(keys, 1, {
        id: '00000000-0000-4000-8000-000000000001',
        chain: chainName(chain),
        seq: 8n,
        hash: Buffer.alloc(32, 200),
        macKeyVersion: 2,
        at: made.clock.at,
        reason: 'repaired',
        evidence: 'INC-2026-11-11',
        from: null,
      });
      made.fake.files.set(rebaseFileName(1, rebase.id), rebaseFile(rebase));
      await log.read();
      expect(log.latest(chain)?.seq).toBe(8n);
      await evicted(log, chain);
      const release = await log.pin(chain);
      expect(log.latest(chain)?.seq).toBe(8n);
      expect(log.latest(chain)?.hash).toEqual(Buffer.alloc(32, 200));
      release?.();
    });

    it('nothing read again before the store is read whole: a first read that let shards go, then failed', async () => {
      const made = await world();
      const log = tight(made);
      // The walks read, shards let go, then the lists of changes fail: not read whole.
      made.fake.instead.list = (start, most, after) =>
        start === 'e1/shards/changes/'
          ? Promise.reject(new Error('the store is away'))
          : made.fake.real.list(start, most, after);
      await log.read();
      expect(log.state()).toBe('unreadable');
      const away = letGo(log)[0] ?? PLATFORM;
      const lists = made.fake.calls.lists;
      expect(await log.pin(away)).toBeUndefined();
      expect(made.fake.calls.lists).toBe(lists);
      delete made.fake.instead.list;
      await log.read();
      expect(log.state()).toBe('read');
      const release = await log.pin(away);
      expect(log.latest(away)?.seq).toBe(6n);
      release?.();
    });
  });

  describe('never let go', () => {
    it('a shard with a line waiting to be written: kept until it is in the store, then it may go', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const chain = held(log)[0] ?? PLATFORM;
      log.keep(anchorOf(chain, 7n, made.clock.at));
      for (const other of CHAINS) (await log.pin(other))?.();
      expect(log.holds(chain)).toBe(true);
      expect(log.latest(chain)?.seq).toBe(7n);
      await log.flush();
      await evicted(log, chain);
      const release = await log.pin(chain);
      expect(log.latest(chain)?.seq).toBe(7n);
      release?.();
    });

    it('a shard with a pass or a place waiting: kept too', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const [passed, placed] = held(log);
      const point = { seq: 6n, hash: Buffer.alloc(32, 6), macKeyVersion: 2 };
      log.keepPass(signPass(keys, passed ?? PLATFORM, point, made.clock.at, 1));
      log.keepProgress(signProgress(keys, placed ?? PLATFORM, point, { at: made.clock.at, began: made.clock.at }, 1));
      for (const other of CHAINS) (await log.pin(other))?.();
      expect(log.holds(passed ?? PLATFORM)).toBe(true);
      expect(log.holds(placed ?? PLATFORM)).toBe(true);
    });

    it('a shard whose file is unsent: kept until it lands', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const chain = held(log)[0] ?? PLATFORM;
      log.keep(anchorOf(chain, 7n, made.clock.at));
      made.fake.instead.put = () => Promise.reject(new Error('the store is away'));
      await log.flush();
      for (const other of CHAINS) (await log.pin(other))?.();
      expect(log.holds(chain)).toBe(true);
      delete made.fake.instead.put;
      await log.flush();
      await evicted(log, chain);
    });

    it('a shard whose file is being made: kept while its lines are taken and sent', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const chain = held(log)[0] ?? PLATFORM;
      log.keep(anchorOf(chain, 7n, made.clock.at));
      const sending = gate();
      const putting = gate();
      made.fake.instead.put = async (name, bytes) => {
        putting.open();
        await sending.opened;
        return made.fake.real.put(name, bytes);
      };
      const flushing = log.flush();
      await putting.opened;
      // Its lines taken, no longer waiting, and not unsent yet: still kept.
      for (const other of CHAINS) (await log.pin(other))?.();
      expect(log.holds(chain)).toBe(true);
      delete made.fake.instead.put;
      sending.open();
      await flushing;
    });

    it('a pinned shard, until released', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const chain = held(log)[0] ?? PLATFORM;
      const release = await log.pin(chain);
      for (const other of CHAINS) (await log.pin(other))?.();
      expect(log.holds(chain)).toBe(true);
      release?.();
      // Released twice is released once.
      release?.();
      await evicted(log, chain);
    });
  });

  describe('a shard let go', () => {
    it('keeps nothing: an anchor, a pass and a place refused, said, and no file of it written', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      const point = { seq: 1n, hash: Buffer.alloc(32, 1), macKeyVersion: 2 };
      const before = [...made.fake.files.keys()];
      log.keep(anchorOf(away, 1n, made.clock.at));
      log.keepPass(signPass(keys, away, point, made.clock.at, 1));
      log.keepProgress(signProgress(keys, away, point, { at: made.clock.at, began: made.clock.at }, 1));
      expect(made.lines('audit.anchor_shard_not_held').map((line) => line.kind)).toEqual(['a', 'p', 'u']);
      expect(made.lines('audit.anchor_shard_not_held')[0]).toMatchObject({
        level: 'warn',
        orgId: away.kind === 'organisation' ? away.orgId : '',
        shard: shardHex(shardOfChain(away)),
      });
      await log.flush();
      const folder = `e1/shards/${shardHex(shardOfChain(away))}/`;
      expect([...made.fake.files.keys()].filter((name) => !before.includes(name) && name.startsWith(folder))).toEqual(
        [],
      );
      const release = await log.pin(away);
      expect(log.latest(away)?.seq).toBe(6n);
      release?.();
    });

    it('its files named in a list of changes are left for its read again, which takes them', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      const before = made.fake.calls.smallGets;
      made.writer.keep(anchorOf(away, 9n, made.clock.at));
      await made.writer.flush();
      made.clock.at = new Date(made.clock.at.getTime() + MINUTE);
      await log.read();
      // The list fetched, the file it names not.
      expect(made.fake.calls.smallGets - before).toBe(1);
      expect(log.holds(away)).toBe(false);
      const release = await log.pin(away);
      expect(log.latest(away)?.seq).toBe(9n);
      release?.();
    });
  });

  describe('a pin and a read letting shards go, in a forced order', () => {
    /** A reader holding every shard but the least used, and a read that will need room, held at its list of changes. */
    async function readHeld(pinFirst: boolean) {
      const made = await world();
      const log = tight(made, 8);
      await log.read();
      const holding = held(log);
      const oldest = holding[0] ?? PLATFORM;
      // New chains in shards never written, so the read stages lines and needs room.
      const fresh = oneAShard(80)
        .filter((chain) => !CHAINS.some((one) => chainName(one) === chainName(chain)))
        .slice(0, 20);
      // Every other shard used since, those new ones too: `oldest` is the least recently used.
      for (const chain of [...holding.slice(1), ...fresh]) log.latest(chain);
      for (const chain of fresh) made.writer.keep(anchorOf(chain, 1n, made.clock.at));
      await made.writer.flush();
      made.clock.at = new Date(made.clock.at.getTime() + MINUTE);
      const listing = gate();
      const listed = gate();
      made.fake.instead.list = async (start, most, after) => {
        if (start === 'e1/shards/changes/') {
          listed.open();
          await listing.opened;
        }
        return made.fake.real.list(start, most, after);
      };
      const evictions = made.lines('audit.anchor_shards_evicted').length;
      const reading = log.read();
      await listed.opened;
      const release = pinFirst ? await log.pin(oldest) : undefined;
      listing.open();
      await reading;
      const evictedNow = made.lines('audit.anchor_shards_evicted').length - evictions;
      return { made, log, oldest, release, evictedNow };
    }

    it('without the pin, the read lets the least recently used go: the order below is a real one', async () => {
      const { log, oldest, evictedNow } = await readHeld(false);
      expect(evictedNow).toBeGreaterThan(0);
      expect(log.holds(oldest)).toBe(false);
    });

    it('a pin taken while the read is under way: the read lets others go, never the pinned one', async () => {
      const { log, oldest, release, evictedNow } = await readHeld(true);
      expect(evictedNow).toBeGreaterThan(0);
      expect(log.holds(oldest)).toBe(true);
      expect(log.latest(oldest)?.seq).toBe(6n);
      expect(log.memoryHeld().bytes).toBeLessThanOrEqual(log.memoryHeld().mostBytes);
      release?.();
    });

    it('a pin of a shard let go, asked while a read is under way: read again only once that read is done', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      const folder = `e1/shards/${shardHex(shardOfChain(away))}/`;
      const order: string[] = [];
      const listing = gate();
      const listed = gate();
      made.fake.instead.list = async (start, most, after) => {
        if (start === 'e1/shards/changes/') {
          listed.open();
          await listing.opened;
          order.push('read');
        }
        if (start === folder) order.push('pin');
        return made.fake.real.list(start, most, after);
      };
      made.clock.at = new Date(made.clock.at.getTime() + MINUTE);
      const reading = log.read();
      await listed.opened;
      const pinning = log.pin(away);
      // Two asks of the same shard read it once.
      const again = log.pin(away);
      await Promise.resolve();
      expect(order).toEqual([]);
      listing.open();
      await reading;
      const [release, second] = await Promise.all([pinning, again]);
      expect(order).toEqual(['read', 'pin']);
      expect(log.latest(away)?.seq).toBe(6n);
      release?.();
      second?.();
    });
  });

  describe('while a shard is read again, and before the migration is done', () => {
    it('a shard being read again says nothing until all of it is read, its rebase taken in first included', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const away = letGo(log)[0] ?? PLATFORM;
      const rebase = signRebase(keys, 1, {
        id: '00000000-0000-4000-8000-000000000002',
        chain: chainName(away),
        seq: 8n,
        hash: Buffer.alloc(32, 200),
        macKeyVersion: 2,
        at: made.clock.at,
        reason: 'repaired',
        evidence: 'INC-2026-11-11',
        from: null,
      });
      made.fake.files.set(rebaseFileName(1, rebase.id), rebaseFile(rebase));
      await log.read();
      const folder = `e1/shards/${shardHex(shardOfChain(away))}/`;
      const listing = gate();
      const listed = gate();
      made.fake.instead.list = async (start, most, after) => {
        if (start === folder) {
          listed.open();
          await listing.opened;
        }
        return made.fake.real.list(start, most, after);
      };
      const pinning = log.pin(away);
      await listed.opened;
      expect(log.holds(away)).toBe(false);
      expect(log.latest(away)).toBeUndefined();
      expect(log.lastPass(away)).toBeUndefined();
      expect(log.lastProgress(away)).toBeUndefined();
      listing.open();
      const release = await pinning;
      expect(log.latest(away)?.seq).toBe(8n);
      release?.();
    });

    it('a pin of a held shard counts before it is given: a release meanwhile lets others go, never it', async () => {
      const made = await world();
      const log = tight(made);
      await log.read();
      const [oldest, ...rest] = held(log);
      // `oldest` the least recently used; then lines waiting in shards never written, past what can be held.
      for (const chain of rest) log.latest(chain);
      const other = rest[0] ?? PLATFORM;
      const releaseOther = await log.pin(other);
      for (const chain of oneAShard(80).slice(40, 70)) log.keep(anchorOf(chain, 1n, made.clock.at));
      expect(log.memoryHeld().bytes).toBeGreaterThan(log.memoryHeld().mostBytes);
      const pinning = log.pin(oldest ?? PLATFORM);
      // Before the pin is given, another released: what is past the budget is let go now.
      releaseOther?.();
      const release = await pinning;
      expect(release).toBeDefined();
      expect(log.holds(oldest ?? PLATFORM)).toBe(true);
      expect(log.holds(other)).toBe(false);
      release?.();
    });

    it('moved on but the migration not done: nothing let go, a store past the budget refused as before', async () => {
      const fake = createFakeWriteOnceStore();
      const marker = cutoverFile(keys, { epoch: 1, at: START });
      fake.files.set(marker.name, marker.bytes);
      const old = `e1/snapshots/${String(LAST_MS - START.getTime())}-${ID}`;
      fake.files.set(old, oldFile(old, ...CHAINS.slice(0, 20).map((chain) => anchorOf(chain, 5n, START))));
      // Each file within what can be opened; the lines of both past what can be held.
      const delta = `e1/deltas/${String(LAST_MS - START.getTime() - MINUTE)}-${ID}`;
      fake.files.set(delta, oldFile(delta, ...CHAINS.slice(20).map((chain) => anchorOf(chain, 5n, START))));
      const made: Made = { fake, clock: { at: new Date(START.getTime() + 10 * MINUTE) }, logs: new LogCapture() };
      const log = tight(made);
      await log.read();
      expect(log.state()).toBe('unreadable');
      expect(made.logs.lines().filter((line) => line.event === 'audit.anchor_shards_evicted')).toEqual([]);
      expect(made.logs.lines().filter((line) => line.event === 'audit.anchor_store_beyond_memory')).toHaveLength(1);
      expect(held(log)).toHaveLength(CHAINS.length);
    });
  });

  describe('memory bounded, measured', () => {
    it('every chain pinned in turn, three times over: under the budget throughout, its records and buffers never growing', async () => {
      const many = Array.from({ length: 1100 }, (_, index) => organisation(index + 1));
      const made = await world(many);
      const whole = logOf(made);
      await whole.read();
      // Every organisation seen, and about 300 lines' worth besides: under a third of the store.
      const budget = Math.ceil((many.length * 100 + 300 * 340) / 0.8);
      const log = logOf(made, { evicts: true, mostFileBytes: budget });
      await log.read();
      expect(log.state()).toBe('read');
      let peak = { records: 0, allocated: 0 };
      for (let round = 0; round < 3; round += 1) {
        for (const chain of many) {
          const release = await log.pin(chain);
          expect(release).toBeDefined();
          expect(plain(log.latest(chain))).toEqual(plain(whole.latest(chain)));
          release?.();
          const memory = log.memoryHeld();
          expect(memory.bytes).toBeLessThanOrEqual(budget);
          // The records really in use: one a line held, never more than the budget's count of lines.
          expect(memory.records).toBeLessThanOrEqual(Math.floor(budget / 340));
          if (round === 0) {
            peak = {
              records: Math.max(peak.records, memory.records),
              allocated: Math.max(peak.allocated, memory.allocated),
            };
          } else {
            // Shards come and go thousands of times: their records are reused, the buffers never grow.
            expect(memory.allocated).toBeLessThanOrEqual(peak.allocated);
          }
        }
      }
      expect(log.memoryHeld().shards).toBeLessThan(256);
      // Over 3,300 pins, most a shard read again: a record leaked a line would be past a buffer of 1,024 by now.
      expect(peak.allocated).toBeLessThanOrEqual(3 * 1024 * 146);
      expect(made.alarms()).toEqual([]);
    }, 120_000);
  });
});
