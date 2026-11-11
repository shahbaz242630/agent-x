// The sharded store against today's (PL-65 PR2, the design's differential test): the same random steps, from the same
// seed, run once by processes that keep the old files and once by processes that move the store on to its shards part
// way, each over a store of its own: many chains across the shards, hourly snapshots and deltas, restarts, spoiled files,
// rebases. A process reading each store afresh at the end, and the writers themselves, must say the same of every
// chain: its anchor, its last finished pass and the place a pass under way has reached.
import { gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { type Anchor, signAnchor, signPass, signProgress } from './anchor.ts';
import { type AnchorLog, createAnchorLog } from './anchor-log.ts';
import { type Chain, chainName } from './chain.ts';
import { rebaseFile, rebaseFileName, signRebase } from './rebase.ts';
import { shardHex, shardOf } from './shards.ts';

const keys = createKeyProvider(
  byPurpose((purpose) => ({ current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 7)]]) })),
);
const START = new Date('2026-11-02T09:00:00.000Z');
const MINUTE = 60_000;
const LAST_MS = 9_999_999_999_999;
const SEEDS = 24;
const STEPS = 90;
const CHAINS: readonly Chain[] = [
  { kind: 'platform' },
  ...Array.from({ length: 40 }, (_, index): Chain => ({
    kind: 'organisation',
    orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
  })),
];

/** A small, seeded random source, so a failing seed can be run again. */
function randomFrom(seed: number) {
  let state = seed >>> 0;
  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4_294_967_296;
  };
  return { below: (count: number): number => Math.floor(next() * count), chance: (odds: number) => next() < odds };
}

/** The same steps, on the old files' side or the shards' side: a store, and the process writing it now. */
function side(clock: { at: Date }, sharded: boolean) {
  const fake = createFakeWriteOnceStore();
  const made = (cutOver: boolean): AnchorLog =>
    createAnchorLog({
      store: fake.store,
      keys,
      logger: testLogger(new LogCapture()),
      now: () => clock.at,
      epoch: 1,
      alertAfterMs: 15 * MINUTE,
      cutOver,
    });
  const state = { log: made(false), cutOver: false };
  // A second process beside the writer, never restarted and never writing: it reads what the writer wrote, each run.
  const watcher = made(false);
  return {
    fake,
    watcher,
    get log() {
      return state.log;
    },
    /** A restart, set from now on to move the store on, on the shards' side, once `cutOver` says. */
    restart(cutOver: boolean) {
      state.cutOver = sharded && (state.cutOver || cutOver);
      state.log = made(state.cutOver);
    },
    reader: () => made(false),
  };
}

const countdown = (at: Date): string => String(LAST_MS - at.getTime()).padStart(13, '0');
const idOf = (id: number): string => `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`;

/** What a log says of a chain, as plain values. */
const said = (log: AnchorLog, chain: Chain) => {
  const plain = (line: Anchor | undefined) =>
    line === undefined
      ? undefined
      : {
          seq: line.seq,
          hash: line.hash.toString('hex'),
          at: line.at.toISOString(),
          mk: line.macKeyVersion,
          kv: line.keyVersion,
          ...('began' in line && line.began instanceof Date ? { began: line.began.toISOString() } : {}),
        };
  return { latest: plain(log.latest(chain)), pass: plain(log.lastPass(chain)), place: plain(log.lastProgress(chain)) };
};

/** One step's chain, its next place, and what both sides share. */
interface Step {
  readonly chain: Chain;
  readonly name: string;
  readonly seq: bigint;
  readonly point: { seq: bigint; hash: Buffer; macKeyVersion: number };
  readonly clock: { at: Date };
  readonly both: readonly [ReturnType<typeof side>, ReturnType<typeof side>];
  readonly seqs: Map<string, bigint>;
  readonly random: ReturnType<typeof randomFrom>;
  readonly id: number;
}

const each = async (step: Step, act: (log: AnchorLog) => unknown): Promise<void> => {
  for (const one of step.both) await act(one.log);
};

/** What a step does, by a roll below 100: each up to its bound. */
const ACTIONS: readonly (readonly [number, (step: Step) => Promise<void>])[] = [
  [
    40,
    async (step) => {
      step.seqs.set(step.name, step.seq);
      const anchor = signAnchor(keys, step.chain, step.point, step.clock.at, 1);
      await each(step, (log) => {
        log.keep(anchor);
      });
    },
  ],
  [
    46,
    async (step) => {
      const pass = signPass(keys, step.chain, step.point, step.clock.at, 1);
      await each(step, (log) => {
        log.keepPass(pass);
      });
    },
  ],
  [
    52,
    async (step) => {
      const began = new Date(step.clock.at.getTime() - MINUTE);
      const place = signProgress(keys, step.chain, step.point, { at: step.clock.at, began }, 1);
      await each(step, (log) => {
        log.keepProgress(place);
      });
    },
  ],
  [70, (step) => each(step, (log) => log.flush())],
  [
    80,
    async (step) => {
      await each(step, (log) => log.read());
      for (const one of step.both) await one.watcher.read();
    },
  ],
  [
    90,
    (step) => {
      step.clock.at = new Date(step.clock.at.getTime() + (1 + step.random.below(70)) * MINUTE);
      return Promise.resolve();
    },
  ],
  [
    93,
    async (step) => {
      for (const one of step.both) one.restart(false);
      await each(step, (log) => log.read());
    },
  ],
  [
    96,
    async (step) => {
      const rebase = signRebase(keys, 1, {
        id: idOf(step.id),
        chain: step.name,
        seq: step.seq,
        hash: Buffer.alloc(32, 200),
        macKeyVersion: 2,
        at: step.clock.at,
        reason: 'repaired',
        evidence: 'INC-2026-11-11',
        from: null,
      });
      step.seqs.set(step.name, step.seq);
      for (const one of step.both) one.fake.files.set(rebaseFileName(1, rebase.id), rebaseFile(rebase));
      await each(step, (log) => log.read());
    },
  ],
  [
    100,
    (step) => {
      // Spoiled files, the same in the old folders of both, and in a shard's folder of the shards' store.
      const named = `${countdown(step.clock.at)}-${idOf(step.id)}`;
      for (const one of step.both) one.fake.files.set(`e1/deltas/${named}`, gzipSync('spoiled'));
      step.both[1].fake.files.set(`e1/shards/${shardHex(shardOf(step.name))}/${named}-d`, gzipSync('spoiled'));
      return Promise.resolve();
    },
  ],
];

async function run(seed: number) {
  const random = randomFrom(seed);
  const clock = { at: START };
  const both = [side(clock, false), side(clock, true)] as const;
  const cutoverAt = 5 + random.below(STEPS - 30);
  const seqs = new Map<string, bigint>();
  for (const one of both) await one.log.read();
  for (let at = 0; at < STEPS; at += 1) {
    // A second a step, as runs are apart: the old files' reader can't order two named in one millisecond (the lists of
    // changes can, and are run without it in anchor-log-shards.test.ts).
    clock.at = new Date(clock.at.getTime() + 1000);
    if (at === cutoverAt) {
      for (const one of both) one.restart(true);
      for (const one of both) await one.log.read();
    }
    const chain = CHAINS[random.below(CHAINS.length)] ?? { kind: 'platform' };
    const name = chainName(chain);
    const seq = (seqs.get(name) ?? 0n) + BigInt(1 + random.below(3));
    const point = { seq, hash: Buffer.alloc(32, Number(seq % 251n) + seed), macKeyVersion: 2 };
    const step: Step = { chain, name, seq, point, clock, both, seqs, random, id: at + 1 };
    const roll = random.below(100);
    const action = ACTIONS.find(([upTo]) => roll < upTo);
    await action?.[1](step);
  }
  for (const one of both) await one.log.flush();
  clock.at = new Date(clock.at.getTime() + MINUTE);
  for (const one of both) await one.watcher.read();
  return { old: both[0], shards: both[1], clock };
}

const files = (fake: FakeWriteOnceStore, start: string): number =>
  [...fake.files.keys()].filter((name) => name.startsWith(start)).length;

describe('SEC-ANC-04 the sharded store reads as the old one did (PL-65 PR2, differential)', () => {
  it.each(Array.from({ length: SEEDS }, (_, index) => index + 1))(
    'seed %i: every chain’s anchor, pass and place the same, read afresh and as written',
    async (seed) => {
      const { old, shards } = await run(seed);
      const [fromOld, fromShards] = [old.reader(), shards.reader()];
      await fromOld.read();
      await fromShards.read();
      expect(fromOld.state()).toBe('read');
      expect(fromShards.state()).toBe('read');
      expect(shards.watcher.state()).toBe('read');
      // The shards' side did move on: its marker and files are there.
      expect(shards.fake.files.has('e1/cutover/shards-v1')).toBe(true);
      expect(files(shards.fake, 'e1/shards/changes/')).toBeGreaterThan(0);
      expect(fromShards.organisations().toSorted()).toEqual(fromOld.organisations().toSorted());
      for (const chain of CHAINS) {
        expect(said(fromShards, chain), chainName(chain)).toEqual(said(fromOld, chain));
        expect(said(shards.log, chain), chainName(chain)).toEqual(said(old.log, chain));
        expect(said(shards.watcher, chain), chainName(chain)).toEqual(said(old.watcher, chain));
      }
    },
  );
});
