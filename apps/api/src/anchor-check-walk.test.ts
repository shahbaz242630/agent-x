// The anchor check walking the anchors' store a shard at a time (PL-65 PR4), over a log that lets shards go past its
// budget (PR3): the forced cases, a restart being a new log and a new check over the same store.
import { type ChainReport, createAnchorLog } from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createFakeWriteOnceStore, type FakeWriteOnceStore, FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createAnchorCheck, type OrganisationChains, type ProbeAnswer } from './anchor-check.ts';
import { shardOfOrganisation } from './anchor-walk.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const AT = new Date('2026-11-02T09:00:00.000Z');
const STALE_MS = 900_000;
const MINUTE = 60_000;

const ok = (seq: bigint): ChainReport => ({ ok: true, seq, hash: Buffer.alloc(32, Number(seq)), macKeyVersion: 1 });

const many = (count: number, from: number): string[] =>
  Array.from({ length: count }, (_, index) => `0199a0f0-0000-7000-8000-${String(from + index).padStart(12, '0')}`);

/** The chains as a database holds them, every one at 3, and what the check asked of them. */
function chainsAt3(orgIds: readonly string[]) {
  const given = new Map<string, (bigint | undefined)[]>();
  const holds: [string, string | undefined][] = [];
  const organizations: OrganisationChains = {
    list: () => Promise.resolve(orgIds),
    recorded: () => Promise.resolve(orgIds),
    verify: (orgId, anchor) => {
      given.set(orgId, [...(given.get(orgId) ?? []), anchor?.seq]);
      return Promise.resolve(ok(3n));
    },
    hold: (orgId, failure) => {
      if (failure !== undefined) holds.push([orgId, failure]);
      return Promise.resolve();
    },
  };
  /** How many times each was read so far. */
  const reads = (): Map<string, number> => new Map(orgIds.map((orgId) => [orgId, given.get(orgId)?.length ?? 0]));
  return { organizations, given, holds, reads };
}

/** One process's start: a log and a check over the store. */
function process(
  fake: FakeWriteOnceStore,
  organizations: OrganisationChains,
  at: Date,
  shards: { readonly cutOver?: boolean; readonly evicts?: boolean; readonly mostFileBytes?: number },
) {
  const capture = new LogCapture();
  const logger = testLogger(capture);
  const clock = new FixedClock(at);
  const log = createAnchorLog({
    store: fake.store,
    keys,
    logger,
    now: () => clock.now(),
    epoch: 1,
    alertAfterMs: STALE_MS,
    ...shards,
  });
  const check = createAnchorCheck({
    chains: [],
    organizations,
    keys,
    clock,
    logger,
    staleAfterMs: STALE_MS,
    deadlineMs: 120_000,
    durable: log,
  });
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  return { log, check, lines, clock };
}

/** A store moved on to its shards by a process of its own, the migration done: every organisation anchored at 3. */
async function shardedStore(orgIds: readonly string[]) {
  const fake = createFakeWriteOnceStore();
  const chains = chainsAt3(orgIds);
  const writer = process(fake, chains.organizations, AT, { cutOver: true });
  await writer.check.run();
  writer.clock.advanceBy(61 * MINUTE);
  await writer.check.run();
  expect(fake.files.has('e1/shards/done-shards-v1')).toBe(true);
  // Past half the bound: each chain checked from here is signed again, so the store says when it was.
  writer.clock.advanceBy(10 * MINUTE);
  return { fake, chains, at: writer.clock.now() };
}

/** How many times each shard was read back, by shard. */
const loadsOf = (lines: readonly Record<string, unknown>[]): Map<unknown, number> => {
  const loads = new Map<unknown, number>();
  for (const { shard } of lines) loads.set(shard, (loads.get(shard) ?? 0) + 1);
  return loads;
};

/** The chains a probe answers for, as `answer` says. */
const probing =
  (asked: string[][], answer: (orgId: string) => ProbeAnswer): NonNullable<OrganisationChains['probe']> =>
  (chains, _signal, pages) => {
    asked.push(chains.map(({ orgId }) => orgId));
    expect(pages).toBeGreaterThan(0);
    return Promise.resolve(new Map(chains.map(({ orgId }) => [orgId, answer(orgId)])));
  };

describe('SEC-ANC-06 the anchor check walks the store a shard at a time (PL-65 PR4)', () => {
  // 600 organisations over about 230 shards, a budget holding about a third of them: before the walk, one run read 332
  // shards back for 234 (some three and four times); along it, each at most once a pass.
  const ORGS = many(600, 1000);
  const BUDGET = 150_000;

  it('a run reads each shard back at most once, holds no more than its budget, and compares every chain', async () => {
    const { fake, chains, at } = await shardedStore(ORGS);
    const after = process(fake, chains.organizations, at, { evicts: true, mostFileBytes: BUDGET });
    const before = chains.reads();
    await after.check.run();
    const first = loadsOf(after.lines('audit.anchor_shard_loaded'));
    expect(first.size).toBeGreaterThan(50);
    expect(Math.max(...first.values())).toBe(1);
    for (const orgId of ORGS) expect(chains.given.get(orgId)?.slice(before.get(orgId))).toEqual([3n]);
    expect(after.log.memoryHeld().bytes).toBeLessThanOrEqual(BUDGET);
    expect(after.lines('audit.integrity_failed')).toEqual([]);
    // The next pass the same: each shard let go read back once more at most.
    const loadedBefore = after.lines('audit.anchor_shard_loaded').length;
    after.clock.advanceBy(10 * MINUTE);
    await after.check.run();
    const second = loadsOf(after.lines('audit.anchor_shard_loaded').slice(loadedBefore));
    expect(second.size).toBeGreaterThan(50);
    expect(Math.max(...second.values())).toBe(1);
    expect(after.log.memoryHeld().bytes).toBeLessThanOrEqual(BUDGET);
  });

  it('past the budget, a round reads back only the shards that don’t fit: those the walk passed go first', async () => {
    // About two thirds of the 235 shards fit: before the walk told the log what it passed, least-recently-used let go
    // exactly what came next, and every round read back all 234.
    const budget = 230_000;
    const { fake, chains, at } = await shardedStore(ORGS);
    const after = process(fake, chains.organizations, at, { evicts: true, mostFileBytes: budget });
    const shards = new Set(ORGS.map(shardOfOrganisation));
    await after.check.run();
    for (let round = 0; round < 2; round += 1) {
      after.clock.advanceBy(10 * MINUTE);
      const heldAtStart = new Set(
        ORGS.filter((orgId) => after.log.holds({ kind: 'organisation', orgId })).map(shardOfOrganisation),
      );
      const loadedBefore = after.lines('audit.anchor_shard_loaded').length;
      await after.check.run();
      const loaded = after.lines('audit.anchor_shard_loaded').slice(loadedBefore);
      // The bound: the shards not held as the round begins, read back once each, and none of those held.
      expect(heldAtStart.size).toBeGreaterThan(100);
      expect(loaded.length).toBeLessThanOrEqual(shards.size - heldAtStart.size);
      const heldNames = new Set([...heldAtStart].map((shard) => shard.toString(16).padStart(2, '0')));
      expect(loaded.filter(({ shard }) => heldNames.has(String(shard)))).toEqual([]);
      expect(after.log.memoryHeld().bytes).toBeLessThanOrEqual(budget);
      for (const orgId of ORGS) expect(chains.given.get(orgId)?.at(-1)).toBe(3n);
    }
  });

  it('chains in shards let go are probed as the walk reaches their shard, once a shard, and those unmoved read no further', async () => {
    const orgIds = many(120, 3000);
    const { fake, chains, at } = await shardedStore(orgIds);
    const asked: string[][] = [];
    const organizations = { ...chains.organizations, probe: probing(asked, () => ({ kind: 'same' })) };
    const after = process(fake, organizations, at, { evicts: true, mostFileBytes: 30_000 });
    await after.log.read();
    const away = orgIds.filter((orgId) => !after.log.holds({ kind: 'organisation', orgId }));
    expect(away.length).toBeGreaterThan(40);
    const before = chains.reads();
    await after.check.run();
    // The run's probe asks of those held; each shard let go is asked once, alone, as the walk reaches it.
    const [atStart = [], ...byShard] = asked;
    expect(atStart.filter((orgId) => away.includes(orgId))).toEqual([]);
    for (const shard of byShard) expect(new Set(shard.map(shardOfOrganisation)).size).toBe(1);
    expect(new Set(byShard.map((shard) => shardOfOrganisation(shard[0] ?? ''))).size).toBe(byShard.length);
    expect(byShard.flat().toSorted()).toEqual(away.toSorted());
    // No chain read: every one found unmoved by a probe.
    expect(chains.reads()).toEqual(before);
    expect(Math.max(...loadsOf(after.lines('audit.anchor_shard_loaded')).values())).toBe(1);
    expect(after.lines('audit.integrity_failed')).toEqual([]);
  });

  it('a chain wound back in a shard let go is found by its shard’s probe: the alarm and its hold, never anchored afresh', async () => {
    const orgIds = many(60, 5000);
    const { fake, chains, at } = await shardedStore(orgIds);
    let victim = '';
    const organizations = {
      ...chains.organizations,
      probe: probing([], (orgId) =>
        orgId === victim ? { kind: 'failed', problem: { reason: 'anchor', seq: 3n } } : { kind: 'same' },
      ),
    };
    const after = process(fake, organizations, at, { evicts: true, mostFileBytes: 20_000 });
    await after.log.read();
    victim = orgIds.find((orgId) => !after.log.holds({ kind: 'organisation', orgId })) ?? '';
    expect(victim).not.toBe('');
    await after.check.run();
    expect(after.lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ orgId: victim, check: 'anchor', reason: 'anchor' }),
    ]);
    expect(chains.holds).toEqual([[victim, 'anchor']]);
    expect(after.lines('audit.anchored')).toEqual([]);
  });

  it('a shard’s probe that fails is said, and its chains are read in their turns, each against its anchor', async () => {
    const orgIds = many(60, 7000);
    const { fake, chains, at } = await shardedStore(orgIds);
    let atStart = true;
    const organizations: OrganisationChains = {
      ...chains.organizations,
      probe: () => {
        // The run's own probe answers for nobody; every shard's after it fails.
        if (atStart) {
          atStart = false;
          return Promise.resolve(new Map());
        }
        return Promise.reject(new Error('the database is away'));
      },
    };
    const after = process(fake, organizations, at, { evicts: true, mostFileBytes: 20_000 });
    await after.log.read();
    const away = orgIds.filter((orgId) => !after.log.holds({ kind: 'organisation', orgId }));
    const before = chains.reads();
    await after.check.run();
    for (const orgId of away) expect(chains.given.get(orgId)?.slice(before.get(orgId))).toEqual([3n]);
    expect(after.lines('audit.anchor_check_failed')).toEqual(
      expect.arrayContaining([expect.objectContaining({ level: 'warn', check: 'probe' })]),
    );
    expect(after.lines('audit.integrity_failed')).toEqual([]);
  });

  it('a shard that can’t be read back for its probe: nothing asked of it, and its chains wait in their turns', async () => {
    const orgIds = many(60, 8000);
    const { fake, chains, at } = await shardedStore(orgIds);
    const asked: string[][] = [];
    const organizations = { ...chains.organizations, probe: probing(asked, () => ({ kind: 'same' })) };
    const after = process(fake, organizations, at, { evicts: true, mostFileBytes: 20_000 });
    await after.log.read();
    const victim = orgIds.find((orgId) => !after.log.holds({ kind: 'organisation', orgId })) ?? '';
    const folder = `e1/shards/${shardOfOrganisation(victim).toString(16).padStart(2, '0')}/`;
    fake.instead.list = (start, most, next) =>
      start === folder ? Promise.reject(new Error('the store is away')) : fake.real.list(start, most, next);
    const before = chains.reads();
    await after.check.run();
    expect(asked.flat()).not.toContain(victim);
    expect(chains.reads().get(victim)).toBe(before.get(victim));
    expect(after.log.latest({ kind: 'organisation', orgId: victim })).toBeUndefined();
    expect(after.lines('audit.anchored')).toEqual([]);
    expect(after.lines('audit.anchor_shard_unreadable').length).toBeGreaterThan(0);
  });

  it('late shards are reached: restarts each cut short after a few chains still reach every one, the longest waiting first', async () => {
    const orgIds = many(40, 9000);
    const { fake, chains, at } = await shardedStore(orgIds);
    const reached: string[][] = [];
    let now = at;
    for (let restart = 0; restart < 8 && new Set(reached.flat()).size < orgIds.length; restart += 1) {
      const stop = new AbortController();
      const these: string[] = [];
      const organizations: OrganisationChains = {
        ...chains.organizations,
        verify: async (orgId, anchor) => {
          const report = await chains.organizations.verify(orgId, anchor);
          these.push(orgId);
          // A process stopped after ten of them, as a deploy or a sleeping environment stops one.
          if (these.length === 10) stop.abort();
          return report;
        },
      };
      const one = process(fake, organizations, now, { evicts: true, mostFileBytes: 11_000 });
      await one.check.run(stop.signal);
      await one.check.finish();
      reached.push(these);
      now = new Date(now.getTime() + 10 * MINUTE);
    }
    // Every chain reached within four processes of ten, and one more for those cut off in flight as each stopped.
    expect(new Set(reached.flat())).toEqual(new Set(orgIds));
    expect(reached.length).toBeLessThanOrEqual(5);
    // Each process began with a chain no process before had compared: the shard waiting longest, its oldest first. (A
    // shard is taken whole, so one compared before may follow in it.) Compared for sure: all but the last four read, as
    // four lanes run at once and the stop cuts those in flight off.
    const compared = new Set<string>();
    for (const these of reached) {
      expect(compared.has(these[0] ?? '')).toBe(false);
      for (const orgId of these.slice(0, these.length - 4)) compared.add(orgId);
    }
  });
});
