// Shards let go and read again against shards always held (PL-65 PR3, the design's differential test): the same random
// steps, from the same seed, run on two sharded stores, one written by a process that holds every shard and one by a
// process whose budget holds a few, which pins a chain's shard before it keeps a line of it, as the anchor check does.
// Restarts, hourly snapshots, rebases, spoiled files and forged lists of changes on both. Beside each, a reader as tight,
// pinning chains at random, so shards go and come back over and over. At the end every chain, its shard pinned, says
// the same on both sides: its anchor, its last finished pass and the place a pass under way has reached.
import { gzipSync } from 'node:zlib';

import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createKeyProvider } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { type Anchor, signAnchor, signPass, signProgress } from './anchor.ts';
import { type AnchorLog, createAnchorLog } from './anchor-log.ts';
import { type Chain, chainName } from './chain.ts';
import { cutoverFile, shardsDoneFile } from './cutover.ts';
import { rebaseFile, rebaseFileName, signRebase } from './rebase.ts';
import { shardHex, shardOf } from './shards.ts';

const keys = createKeyProvider(
  byPurpose((purpose) => ({ current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 9)]]) })),
);
const START = new Date('2026-11-02T09:00:00.000Z');
const MINUTE = 60_000;
const LAST_MS = 9_999_999_999_999;
const SEEDS = 16;
const STEPS = 120;
const CHAINS: readonly Chain[] = [
  { kind: 'platform' },
  ...Array.from({ length: 60 }, (_, index): Chain => ({
    kind: 'organisation',
    orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`,
  })),
];
/** Every organisation seen, and about six shards' lines: a few of the fifty-odd the chains fall in. */
const TIGHT_BYTES = Math.ceil((60 * 160 + 3 * 700) / 0.8);

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

/** One side: a sharded store, the process writing it (holding all, or tight), and a tight reader beside it. */
function side(clock: { at: Date }, tightWriter: boolean) {
  const fake = createFakeWriteOnceStore();
  // The side's writers say into one place, its readers into another: what each let go is counted there.
  const logs = { writers: new LogCapture(), readers: new LogCapture() };
  for (const file of [
    cutoverFile(keys, { epoch: 1, at: START }),
    shardsDoneFile(keys, { epoch: 1, at: new Date(START.getTime() + 61 * MINUTE) }),
  ])
    fake.files.set(file.name, file.bytes);
  const made = (tight: boolean, said = logs.readers): AnchorLog =>
    createAnchorLog({
      store: fake.store,
      keys,
      logger: testLogger(said),
      now: () => clock.at,
      epoch: 1,
      alertAfterMs: 15 * MINUTE,
      ...(tight ? { evicts: true, mostFileBytes: TIGHT_BYTES } : {}),
    });
  const state = { writer: made(tightWriter, logs.writers), reader: made(true) };
  return {
    fake,
    tightWriter,
    evictions: (by: keyof typeof logs) =>
      logs[by].lines().filter((line) => line.event === 'audit.anchor_shards_evicted').length,
    get writer() {
      return state.writer;
    },
    get reader() {
      return state.reader;
    },
    restart() {
      state.writer = made(tightWriter, logs.writers);
      state.reader = made(true);
    },
    fresh: (tight: boolean) => made(tight),
  };
}

const countdown = (at: Date): string => String(LAST_MS - at.getTime()).padStart(13, '0');
const idOf = (id: number): string => `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`;

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

/** What a log says of a chain, its shard pinned (read again first if it was let go), as plain values. */
const said = async (log: AnchorLog, chain: Chain) => {
  const release = await log.pin(chain);
  try {
    return {
      held: release !== undefined,
      latest: plain(log.latest(chain)),
      pass: plain(log.lastPass(chain)),
      place: plain(log.lastProgress(chain)),
    };
  } finally {
    release?.();
  }
};

/**
 * A line kept by a side's writer: its shard pinned first, as production keeps every line: the anchor check pins a chain's
 * shard while it compares it and keeps its anchor, the rotation while it keeps a pass or a place.
 */
const kept = async (one: ReturnType<typeof side>, chain: Chain, keep: (log: AnchorLog) => void): Promise<void> => {
  const release = await one.writer.pin(chain);
  if (release === undefined) throw new Error('a shard the writer could not hold');
  try {
    keep(one.writer);
  } finally {
    release();
  }
};

/** One step: its chain, its next place, and what both sides share. */
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

/** Each side's writer keeps a line made once for both. */
const keptOnBoth = async (step: Step, keep: (log: AnchorLog) => void): Promise<void> => {
  for (const one of step.both) await kept(one, step.chain, keep);
};

/** Each side's writer and reader read. */
const readBoth = async (step: Step): Promise<void> => {
  for (const one of step.both) {
    await one.writer.read();
    await one.reader.read();
  }
};

/** What a step does, by a roll below 100: each up to its bound. A table, so each action stays short. */
const ACTIONS: readonly (readonly [number, (step: Step) => Promise<void>])[] = [
  [
    35,
    (step) => {
      step.seqs.set(step.name, step.seq);
      const anchor = signAnchor(keys, step.chain, step.point, step.clock.at, 1);
      return keptOnBoth(step, (log) => {
        log.keep(anchor);
      });
    },
  ],
  [
    42,
    (step) => {
      const pass = signPass(keys, step.chain, step.point, step.clock.at, 1);
      return keptOnBoth(step, (log) => {
        log.keepPass(pass);
      });
    },
  ],
  [
    48,
    (step) => {
      const began = new Date(step.clock.at.getTime() - MINUTE);
      const place = signProgress(keys, step.chain, step.point, { at: step.clock.at, began }, 1);
      return keptOnBoth(step, (log) => {
        log.keepProgress(place);
      });
    },
  ],
  [
    62,
    async (step) => {
      for (const one of step.both) await one.writer.flush();
    },
  ],
  [72, readBoth],
  [
    82,
    async (step) => {
      // The readers pin a few chains at random: shards go and come back.
      for (const _pin of [1, 2, 3, 4, 5]) {
        const other = CHAINS[step.random.below(CHAINS.length)] ?? { kind: 'platform' };
        for (const one of step.both) (await one.reader.pin(other))?.();
      }
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
      for (const one of step.both) await one.writer.flush();
      for (const one of step.both) one.restart();
      await readBoth(step);
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
      for (const one of step.both) {
        one.fake.files.set(rebaseFileName(1, rebase.id), rebaseFile(rebase));
        await one.writer.read();
      }
    },
  ],
  [
    100,
    (step) => {
      // A spoiled file in the chain's shard and a forged list of changes, the same on both.
      const named = `${countdown(step.clock.at)}-${idOf(step.id)}`;
      const ahead = new Date(step.clock.at.getTime() + step.random.below(4 * MINUTE));
      for (const one of step.both) {
        one.fake.files.set(`e1/shards/${shardHex(shardOf(step.name))}/${named}-d`, gzipSync('spoiled'));
        one.fake.files.set(`e1/shards/changes/${countdown(ahead)}-${idOf(step.id)}`, gzipSync('forged'));
      }
      return Promise.resolve();
    },
  ],
];

async function run(seed: number) {
  const random = randomFrom(seed);
  const clock = { at: new Date(START.getTime() + 62 * MINUTE) };
  const both = [side(clock, false), side(clock, true)] as const;
  const seqs = new Map<string, bigint>();
  for (const one of both) {
    await one.writer.read();
    await one.reader.read();
  }
  for (let at = 0; at < STEPS; at += 1) {
    clock.at = new Date(clock.at.getTime() + 1000);
    const chain = CHAINS[random.below(CHAINS.length)] ?? { kind: 'platform' };
    const name = chainName(chain);
    const seq = (seqs.get(name) ?? 0n) + BigInt(1 + random.below(3));
    const point = { seq, hash: Buffer.alloc(32, Number(seq % 251n) + seed), macKeyVersion: 2 };
    const step: Step = { chain, name, seq, point, clock, both, seqs, random, id: at + 1 };
    const roll = random.below(100);
    await ACTIONS.find(([upTo]) => roll < upTo)?.[1](step);
  }
  for (const one of both) await one.writer.flush();
  clock.at = new Date(clock.at.getTime() + MINUTE);
  for (const one of both) {
    await one.writer.read();
    await one.reader.read();
  }
  return { whole: both[0], tight: both[1] };
}

const shardFiles = (fake: FakeWriteOnceStore): number =>
  [...fake.files.keys()].filter((name) => /^e1\/shards\/[0-9a-f]{2}\//.test(name)).length;

describe('SEC-ANC-05 shards let go and read again say what shards always held say (PL-65 PR3, differential)', () => {
  it.each(Array.from({ length: SEEDS }, (_, index) => index + 1))(
    'seed %i: every chain’s anchor, pass and place the same, as written and read afresh',
    async (seed) => {
      const { whole, tight } = await run(seed);
      // Shards were let go during the run: by the tight writer, by each side's reader, never by the writer holding all.
      expect(tight.evictions('writers')).toBeGreaterThan(0);
      expect(whole.evictions('writers')).toBe(0);
      expect(tight.evictions('readers') + whole.evictions('readers')).toBeGreaterThan(0);
      expect(tight.reader.memoryHeld().bytes).toBeLessThanOrEqual(TIGHT_BYTES);
      expect(shardFiles(tight.fake)).toBeGreaterThan(0);
      const freshWhole = whole.fresh(false);
      const freshTight = tight.fresh(true);
      await freshWhole.read();
      await freshTight.read();
      expect(freshTight.state()).toBe('read');
      expect(freshTight.organisations().toSorted()).toEqual(freshWhole.organisations().toSorted());
      for (const chain of CHAINS) {
        const expected = await said(freshWhole, chain);
        expect(expected.held).toBe(true);
        for (const log of [whole.writer, whole.reader, tight.writer, tight.reader, freshTight]) {
          expect(await said(log, chain), chainName(chain)).toEqual(expected);
        }
      }
    },
    60_000,
  );

  it('the tight side’s processes do let shards go', async () => {
    const { tight } = await run(1);
    const log = tight.fresh(true);
    await log.read();
    expect(CHAINS.filter((chain) => !log.holds(chain)).length).toBeGreaterThan(0);
  });
});
