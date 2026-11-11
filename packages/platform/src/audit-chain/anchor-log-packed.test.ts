// The packed anchor log (PL-65) against the object form it replaced. The same random stores, with forks, rebases,
// spoiled and future-dated files, read and written by the same steps, once with the packed tables and once with plain
// Maps of the very objects passed in, as before: every answer it gives, every line it logs and every byte it writes
// must be the same.
import { createFakeWriteOnceStore, type FakeWriteOnceStore, LogCapture, testLogger } from '@agentx/testing';
import { gunzipSync, gzipSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';

import { createKeyProvider } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { OverwriteRefused } from '../storage/write-once.ts';
import { type Anchor, type Progress, signAnchor, signPass, signProgress } from './anchor.ts';
import { type AnchorLog, createAnchorLog } from './anchor-log.ts';
import type { Chain } from './chain.ts';
import type { PackedLines, Stamped, Taken } from './packed-lines.ts';
import { rebaseFile, rebaseFileName, signRebase } from './rebase.ts';
import { shardOf } from './shards.ts';

const run = vi.hoisted(() => ({
  objects: false,
  ids: 0,
  tables: [] as { readonly size: number; readonly records: number }[],
}));

/** Each object's identity, as a number: in the object form a line's stamp is the object itself, as `===` was. */
const identities = new WeakMap<object, number>();
let identitiesGiven = 0;
const identityOf = (line: object): number => {
  const known = identities.get(line);
  if (known !== undefined) return known;
  // Below zero, so never one of the log's own stamps, which count up from one.
  identitiesGiven -= 1;
  identities.set(line, identitiesGiven);
  return identitiesGiven;
};

/**
 * The object form: a Map of the lines as they came, handing back the same objects, a stamp given ignored for the
 * object's own identity; nothing to hold for a file made, as an object never changes.
 */
function objectLines<T extends Anchor>(): PackedLines<T> {
  const index = new Map<string, { line: T; stamp: number; marked: boolean }>();
  return {
    get size() {
      return index.size;
    },
    get records() {
      return index.size;
    },
    has: (chain) => index.has(chain),
    get: (chain) => index.get(chain)?.line,
    stampOf: (chain) => index.get(chain)?.stamp,
    marked: (chain) => index.get(chain)?.marked ?? false,
    shardOf: (chain) => (index.has(chain) ? shardOf(chain) : undefined),
    set(line, stamp, marked = false) {
      // An identity given back (a file's lines read back from its bytes) stands for the object it was, as the old form
      // put that very object back; a stamp of the log's own is a new object's, so its identity.
      index.set(line.chain, { line, stamp: stamp < 0 ? stamp : identityOf(line), marked });
    },
    delete(chain) {
      index.delete(chain);
    },
    keys: () => index.keys(),
    *held(): Generator<Stamped<T>> {
      for (const { line, stamp } of index.values()) yield { line, stamp };
    },
    take(keep): Taken<T> {
      const got = [...index]
        .filter(([chain, entry]) => keep(chain, () => entry.line, shardOf(chain)))
        .map(([chain, entry]) => ({ chain, ...entry }));
      return {
        size: got.length,
        *lines() {
          for (const { line, stamp } of got) yield { line, stamp };
        },
        *stamps() {
          for (const { chain, stamp } of got) yield [chain, stamp] as const;
        },
        release: () => undefined,
      };
    },
  };
}

vi.mock('./packed-lines.ts', async (importOriginal) => {
  const real = await importOriginal<typeof import('./packed-lines.ts')>();
  return {
    ...real,
    packedLines: <T extends Anchor>(places: boolean) => {
      if (run.objects) return objectLines<T>();
      const table = real.packedLines<T>(places);
      run.tables.push(table);
      return table;
    },
  };
});

// Files named the same in both forms, so their bytes can be compared whole.
vi.mock('node:crypto', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:crypto')>();
  return {
    ...real,
    randomUUID: () => {
      run.ids += 1;
      return `00000000-0000-4000-8000-${String(run.ids).padStart(12, '0')}`;
    },
  };
});

const keys = createKeyProvider(
  byPurpose((purpose) => ({ current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 3)]]) })),
);
const START = new Date('2026-11-02T09:00:00.000Z');
const MINUTE = 60_000;
/** A line's end, as every file in the store writes it. */
const EOL = '\n';

/** A value the test knows is there, or the test fails saying so. */
function defined<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('the test expected a value here');
  return value;
}

/** The packed tables holding more records than lines: none, once nothing is taken. */
const recordsLeft = () =>
  run.tables.filter(({ size, records }) => records !== size).map(({ size, records }) => ({ size, records }));

/** A small, seeded random source, so a failing seed can be run again. */
function randomFrom(seed: number) {
  let state = seed >>> 0;
  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4_294_967_296;
  };
  const below = (count: number): number => Math.floor(next() * count);
  return { below, chance: (odds: number) => next() < odds };
}

const chainOf = (index: number): Chain =>
  index === 0
    ? { kind: 'platform' }
    : { kind: 'organisation', orgId: `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}` };

/** Everything a log says of itself: each chain's lines and rebases, its state and marks. */
function viewOf(log: AnchorLog, chains: number, at: Date) {
  return {
    state: log.state(),
    organisations: log.organisations(),
    lastFileAt: log.lastFileAt(),
    chains: Array.from({ length: chains }, (_, index) => ({
      latest: log.latest(chainOf(index)),
      lastPass: log.lastPass(chainOf(index)),
      lastProgress: log.lastProgress(chainOf(index)),
      rebasedAfter: [START, at].map((when) => log.rebasedAfter(chainOf(index), when)),
    })),
  };
}

/** A file's lines spoiled: its closing line taken off, or a line's signature changed, or not gzip at all. */
function spoiled(bytes: Buffer, how: number): Buffer {
  // Spoiled before, past gzip: as it is.
  if (bytes[0] !== 0x1f) return bytes;
  const lines = gunzipSync(bytes)
    .toString('utf8')
    .split(EOL)
    .filter((line) => line !== '');
  if (how === 0) return gzipSync(`${lines.slice(0, -1).join(EOL)}${EOL}`);
  if (how === 1) {
    const changed = lines.map((line, at) => (at === 0 ? line.replace('"sig":"', '"sig":"AA') : line));
    return gzipSync(`${changed.join(EOL)}${EOL}`);
  }
  return Buffer.from('not a gzipped file');
}

/** The same name dated ten minutes past the clock: passed over, and the alarm. */
const futureName = (name: string, now: Date): string =>
  name.replace(/\/\d{13}-/, `/${String(9_999_999_999_999 - now.getTime() - 10 * MINUTE).padStart(13, '0')}-`);

interface World {
  readonly random: ReturnType<typeof randomFrom>;
  readonly fake: FakeWriteOnceStore;
  readonly chains: number;
  clock: Date;
}

const pointOf = (world: World, seq: bigint) => ({
  seq,
  hash: Buffer.alloc(32, world.random.below(3)),
  macKeyVersion: 1 + world.random.below(2),
});

/** Another process's lines into the store: honest, so a fork comes only of two of them not knowing each other. */
async function anotherWrites(world: World, writer: AnchorLog): Promise<void> {
  const { random } = world;
  for (let step = random.below(6); step >= 0; step -= 1) {
    const chain = chainOf(random.below(world.chains));
    const point = pointOf(world, BigInt(1 + random.below(6)));
    const pick = random.below(3);
    if (pick === 0) writer.keep(signAnchor(keys, chain, point, world.clock, 1));
    else if (pick === 1) writer.keepPass(signPass(keys, chain, point, world.clock, 1));
    else {
      const began = new Date(world.clock.getTime() - random.below(30) * MINUTE);
      writer.keepProgress(signProgress(keys, chain, point, { at: world.clock, began }, 1));
    }
  }
  await writer.flush();
}

/** Something done to the store by someone else: a rebase, a file spoiled, or one dated ahead. */
function damage(world: World): void {
  const { random, fake } = world;
  const pick = random.below(4);
  const names = [...fake.files.keys()].filter((name) => !name.includes('/rebases/'));
  if (pick === 0) {
    const chain = chainOf(random.below(world.chains));
    const name = chain.kind === 'platform' ? 'platform' : `organisation:${chain.orgId}`;
    // Some dated past what the reader allows, so they wait, the alarm each read.
    const at = new Date(world.clock.getTime() + (random.chance(0.2) ? 2 * MINUTE : -random.below(20) * MINUTE));
    const id = `0199b000-0000-7000-8000-${String(run.ids + 1000 + random.below(1e6)).padStart(12, '0')}`;
    const rebase = signRebase(keys, 1, {
      id,
      chain: name,
      ...pointOf(world, BigInt(1 + random.below(8))),
      at,
      reason: 'repaired',
      evidence: 'INC-1/drill',
      from: null,
    });
    fake.files.set(rebaseFileName(1, id), rebaseFile(rebase));
  } else if (names.length > 0) {
    const name = defined(names[random.below(names.length)]);
    const bytes = defined(fake.files.get(name));
    if (pick === 3) fake.files.set(futureName(name, world.clock), bytes);
    else fake.files.set(name, spoiled(bytes, random.below(3)));
  }
}

/** One step of the log under test: its own lines, a read, a write, or a write the store refuses or overwrites. */
async function subjectStep(world: World, log: AnchorLog): Promise<void> {
  const { random, fake } = world;
  const chain = chainOf(random.below(world.chains));
  const pick = random.below(9);
  if (pick === 0) {
    log.keep(signAnchor(keys, chain, pointOf(world, BigInt(1 + random.below(8))), world.clock, 1));
  } else if (pick === 1) {
    // A copy `latest` gave, kept back: a rebase's stays a rebase's, and is left out of a snapshot.
    const held = log.latest(chain);
    if (held !== undefined) log.keep(held);
  } else if (pick === 2) {
    log.keepPass(signPass(keys, chain, pointOf(world, BigInt(1 + random.below(8))), world.clock, 1));
  } else if (pick === 3) {
    const began = new Date(world.clock.getTime() - random.below(90) * MINUTE);
    log.keepProgress(
      signProgress(keys, chain, pointOf(world, BigInt(1 + random.below(8))), { at: world.clock, began }, 1),
    );
  } else if (pick === 4) {
    await log.read();
  } else if (pick === 5) {
    // Lines kept while a file is made: what it holds stops waiting, and they don't.
    const writing = log.flush();
    log.keep(signAnchor(keys, chain, pointOf(world, BigInt(4 + random.below(8))), world.clock, 1));
    log.keepPass(signPass(keys, chainOf(random.below(world.chains)), pointOf(world, 3n), world.clock, 1));
    await writing;
  } else if (pick === 6) {
    fake.instead.put = () => Promise.reject(new Error('the store is away'));
    await log.flush();
    delete fake.instead.put;
  } else if (pick === 7) {
    // The name taken by other bytes: the alarm, and the lines wait again.
    fake.instead.put = (name) => {
      fake.files.set(name, gzipSync(`{"k":"x"}${EOL}`));
      return Promise.reject(new OverwriteRefused());
    };
    await log.flush();
    delete fake.instead.put;
  } else {
    await log.flush();
  }
}

/** One seed's story, start to end, and everything that can be seen of it. */
async function story(seed: number, objects: boolean) {
  run.objects = objects;
  run.ids = 0;
  run.tables = [];
  const random = randomFrom(seed);
  const world: World = { random, fake: createFakeWriteOnceStore(), chains: 2 + random.below(12), clock: START };
  const now = () => world.clock;
  const quiet = () => testLogger(new LogCapture());
  const writers = Array.from({ length: 1 + random.below(3) }, () =>
    createAnchorLog({ store: world.fake.store, keys, logger: quiet(), now, epoch: 1, alertAfterMs: MINUTE }),
  );
  for (const writer of writers) await writer.read();
  const capture = new LogCapture();
  const log = createAnchorLog({
    store: world.fake.store,
    keys,
    logger: testLogger(capture),
    now,
    epoch: 1,
    alertAfterMs: 5 * MINUTE,
  });
  const views: unknown[] = [];
  for (let step = 0; step < 40; step += 1) {
    world.clock = new Date(world.clock.getTime() + (random.chance(0.15) ? 61 : 1 + random.below(5)) * MINUTE);
    const pick = random.below(10);
    if (pick < 3) await anotherWrites(world, defined(writers[random.below(writers.length)]));
    else if (pick < 4) damage(world);
    else await subjectStep(world, log);
    views.push(viewOf(log, world.chains, world.clock));
    // Between steps nothing is taken: every table holds a record a line, and no more, whatever came before.
    expect(recordsLeft()).toEqual([]);
  }
  const files = [...world.fake.files].toSorted(([one], [other]) => (one < other ? -1 : 1));
  // The wall clock's time apart, which no two runs share, and an error's stack, which names the line of the test's call.
  const said = capture.lines().map(({ time: _time, err, ...rest }): Record<string, unknown> => ({
    ...rest,
    err: (err as { message?: unknown } | undefined)?.message,
  }));
  return { views, files, said };
}

describe('the packed anchor log answers as the object form did (PL-65)', () => {
  const seeds = Array.from({ length: 60 }, (_, index) => index + 1);
  const seen = { fork: 0, rebase: 0, future: 0, unclosed: 0, signature: 0, file: 0, overwrite: 0, snapshots: 0 };

  it.each(seeds)('seed %i: every answer, every line logged and every byte written the same', async (seed) => {
    const packed = await story(seed, false);
    const objects = await story(seed, true);
    expect(packed.views).toEqual(objects.views);
    expect(packed.said).toEqual(objects.said);
    expect(packed.files).toEqual(objects.files);
    for (const line of packed.said) {
      const reason = String(line.reason);
      if (reason in seen) seen[reason as keyof typeof seen] += 1;
      if (line.event === 'audit.rebased') seen.rebase += 1;
    }
    seen.snapshots += packed.files.filter(([name]) => name.includes('/snapshots/')).length;
  });

  it('the stories between them took every road: forks, rebases, spoiled, future-dated and overwritten files', () => {
    for (const [road, count] of Object.entries(seen)) expect({ road, taken: count > 0 }).toEqual({ road, taken: true });
  });
});

describe('a copy of a rebase`s anchor, kept back, is still the rebase`s', () => {
  it('is left out of the next snapshot, as the one object was', async () => {
    run.objects = false;
    const fake = createFakeWriteOnceStore();
    const clock = { at: START };
    const log = createAnchorLog({
      store: fake.store,
      keys,
      logger: testLogger(new LogCapture()),
      now: () => clock.at,
      epoch: 1,
      alertAfterMs: MINUTE,
    });
    const chain = chainOf(1);
    const name = chain.kind === 'organisation' ? `organisation:${chain.orgId}` : 'platform';
    const id = '0199b000-0000-7000-8000-000000000001';
    const rebase = signRebase(keys, 1, {
      id,
      chain: name,
      seq: 4n,
      hash: Buffer.alloc(32, 4),
      macKeyVersion: 1,
      at: START,
      reason: 'repaired',
      evidence: 'INC-1/drill',
      from: null,
    });
    fake.files.set(rebaseFileName(1, id), rebaseFile(rebase));
    await log.read();
    const held = defined(log.latest(chain));
    expect(held.signature).toEqual(rebase.signature);
    clock.at = new Date(START.getTime() + MINUTE);
    log.keep(held);
    log.keep(signAnchor(keys, chainOf(2), { seq: 1n, hash: Buffer.alloc(32, 1), macKeyVersion: 1 }, clock.at, 1));
    await log.flush();
    const snapshot = [...fake.files].find(([file]) => file.includes('/snapshots/'));
    const text = gunzipSync(defined(snapshot)[1]).toString('utf8');
    expect(text).not.toContain(name);
    expect(text).toContain(`organisation:${(chainOf(2) as { orgId: string }).orgId}`);
  });
});

describe('a file that could not be made', () => {
  it('lets its lines go and leaves them waiting: the next write holds them', async () => {
    run.objects = false;
    run.tables = [];
    const fake = createFakeWriteOnceStore();
    let refuse = true;
    const failing: typeof keys = {
      ...keys,
      sign: (purpose, message) => {
        if (refuse && message[0] === 'audit-anchor-file') throw new Error('the key is away');
        return keys.sign(purpose, message);
      },
    };
    const capture = new LogCapture();
    const log = createAnchorLog({
      store: fake.store,
      keys: failing,
      logger: testLogger(capture),
      now: () => START,
      epoch: 1,
      alertAfterMs: MINUTE,
    });
    await log.read();
    const line = signAnchor(keys, chainOf(4), { seq: 3n, hash: Buffer.alloc(32, 3), macKeyVersion: 1 }, START, 1);
    log.keep(line);
    await log.flush();
    expect(fake.files.size).toBe(0);
    expect(capture.lines().filter((said) => said.event === 'audit.anchor_store_write_failed')).toHaveLength(1);
    expect(recordsLeft()).toEqual([]);
    refuse = false;
    await log.flush();
    const [[, bytes]] = [...fake.files] as [[string, Buffer]];
    expect(gunzipSync(bytes).toString('utf8')).toContain(line.signature.toString('base64'));
  });
});

describe('a place reached, its own pass begun when', () => {
  it('comes back with when its pass began', async () => {
    run.objects = false;
    const fake = createFakeWriteOnceStore();
    const log = createAnchorLog({
      store: fake.store,
      keys,
      logger: testLogger(new LogCapture()),
      now: () => START,
      epoch: 1,
      alertAfterMs: MINUTE,
    });
    await log.read();
    const began = new Date(START.getTime() - 5 * MINUTE);
    const place: Progress = signProgress(
      keys,
      chainOf(3),
      { seq: 2n, hash: Buffer.alloc(32, 2), macKeyVersion: 1 },
      { at: START, began },
      1,
    );
    log.keepProgress(place);
    expect(log.lastProgress(chainOf(3))).toEqual(place);
    expect(log.lastProgress(chainOf(3))?.began).toEqual(began);
  });
});

describe('what a file holds of the tables, let go as soon as its bytes are made (PL-65 review)', () => {
  const started = async (fake: FakeWriteOnceStore, clock: { at: Date }) => {
    run.objects = false;
    run.tables = [];
    const log = createAnchorLog({
      store: fake.store,
      keys,
      logger: testLogger(new LogCapture()),
      now: () => clock.at,
      epoch: 1,
      alertAfterMs: MINUTE,
    });
    await log.read();
    return log;
  };
  const point = (seq: number) => ({ seq: BigInt(seq), hash: Buffer.alloc(32, seq % 256), macKeyVersion: 1 });
  const chains = 50;
  const keepAll = (log: AnchorLog, seq: number, at: Date) => {
    for (let index = 1; index <= chains; index += 1) {
      log.keep(signAnchor(keys, chainOf(index), point(seq), at, 1));
      log.keepPass(signPass(keys, chainOf(index), point(seq), at, 1));
    }
  };

  it('a write that lands leaves a record a line, and no more', async () => {
    const fake = createFakeWriteOnceStore();
    const clock = { at: START };
    const log = await started(fake, clock);
    keepAll(log, 1, START);
    await log.flush();
    expect(fake.files.size).toBe(1);
    expect(recordsLeft()).toEqual([]);
  });

  it('a store away for many writes: each tried again, the records stay one a line however many lines are kept', async () => {
    const fake = createFakeWriteOnceStore();
    const clock = { at: START };
    const log = await started(fake, clock);
    fake.instead.put = () => Promise.reject(new Error('the store is away'));
    keepAll(log, 1, START);
    await log.flush();
    for (let round = 2; round <= 40; round += 1) {
      clock.at = new Date(START.getTime() + round * MINUTE);
      keepAll(log, round, clock.at);
      await log.flush();
    }
    expect(fake.files.size).toBe(0);
    // 50 chains, each an anchor and a pass, in the held tables and the waiting ones: 200 records, after 4,000 lines kept.
    expect(recordsLeft()).toEqual([]);
    expect(run.tables.reduce((sum, { records }) => sum + records, 0)).toBe(4 * chains);
    delete fake.instead.put;
    await log.flush();
    // The file unsent all that time, then one of what moved since it was made.
    expect(fake.files.size).toBe(2);
    expect(recordsLeft()).toEqual([]);
  });

  it('a name taken by other bytes: the lines wait again from the file`s own bytes, a record a line', async () => {
    const fake = createFakeWriteOnceStore();
    const clock = { at: START };
    const log = await started(fake, clock);
    keepAll(log, 1, START);
    fake.instead.put = (name) => {
      fake.files.set(name, gzipSync(`{"k":"x"}${EOL}`));
      return Promise.reject(new OverwriteRefused());
    };
    await log.flush();
    expect(recordsLeft()).toEqual([]);
    delete fake.instead.put;
    await log.flush();
    const written = [...fake.files.values()].map((bytes) =>
      bytes[0] === 0x1f ? gunzipSync(bytes).toString('utf8') : '',
    );
    // The first file's lines, sent again under a new name: every chain's anchor and pass.
    expect(written.filter((text) => text.includes(`"k":"a"`))).toHaveLength(1);
    expect(
      written
        .find((text) => text.includes(`"k":"a"`))
        ?.split(EOL)
        .filter((line) => line !== ''),
    ).toHaveLength(2 * chains + 1);
  });
});
