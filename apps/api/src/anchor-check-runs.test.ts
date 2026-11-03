// The anchor check's bounded runs (4D2e E6): lanes side by side, a run's time, its
// writes along the way, and whose turn it is. Every order here is forced: a check
// that "takes long" is one held until the test lets it go.
import {
  type AnchorLog,
  type ChainReport,
  createAnchorLog,
  createMemoryAnchorStore,
  ChainStoreError,
  signAnchor,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createFakeWriteOnceStore, FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type AnchorCheckOptions,
  createAnchorCheck,
  type OrganisationChains,
  reachWithin,
  RUN_WITHIN_MS,
} from './anchor-check.ts';
import { createTurns, lanesWithin, shuffledAfresh, SLOW_AFTER_MS, startAnywhere } from './anchor-turns.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const org = (index: number): string => `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`;
const orgs = (count: number): string[] => Array.from({ length: count }, (_, index) => org(index + 1));
const AT = new Date('2026-11-02T09:00:00.000Z');
const STALE_MS = 900_000;
const REACH_MS = 3_600_000;
const DEADLINE_MS = 120_000;
const ok = (seq: bigint, fill = Number(seq)) => ({
  ok: true as const,
  seq,
  hash: Buffer.alloc(32, fill),
  macKeyVersion: 1,
});
/** Lets everything ready run, with the timers faked or not. */
const settled = async (): Promise<void> => {
  for (let round = 0; round < 3000; round += 1) await Promise.resolve();
};

/** Checks that hold until let go, by organisation: each starts when asked, and ends as `report` says or when `let` is called. */
function directory(listed: readonly string[], report: (orgId: string) => ChainReport | undefined = () => ok(1n)) {
  const started: string[] = [];
  const running = new Map<string, () => void>();
  const holds: [string, string | undefined][] = [];
  const list = { now: listed };
  const organizations: OrganisationChains = {
    list: () => Promise.resolve(list.now),
    recorded: () => Promise.resolve([]),
    verify: (orgId) => {
      started.push(orgId);
      const answer = report(orgId);
      if (answer !== undefined) return Promise.resolve(answer);
      return new Promise((resolve) => {
        running.set(orgId, () => {
          resolve(ok(1n));
        });
      });
    },
    hold: (orgId, failure) => {
      holds.push([orgId, failure]);
      return Promise.resolve();
    },
  };
  const release = (orgId: string): void => {
    running.get(orgId)?.();
    running.delete(orgId);
  };
  return { organizations, started, running, holds, list, release };
}

function checking(
  organizations: OrganisationChains,
  more: Partial<AnchorCheckOptions> = {},
): { check: ReturnType<typeof createAnchorCheck>; capture: LogCapture; clock: FixedClock } {
  const capture = new LogCapture();
  const clock = new FixedClock(AT);
  const check = createAnchorCheck({
    chains: [],
    organizations,
    keys,
    clock,
    logger: testLogger(capture),
    staleAfterMs: STALE_MS,
    reachWithinMs: REACH_MS,
    deadlineMs: DEADLINE_MS,
    shuffled: (orgIds) => orgIds,
    pastCapStart: () => 0,
    ...more,
  });
  return { check, capture, clock };
}

const lines = (capture: LogCapture, event: string) => capture.lines().filter((line) => line.event === event);

afterEach(() => {
  vi.useRealTimers();
});

describe('one slow or locked organisation holds its own lane alone (partner: its blast radius stays its own)', () => {
  it('everyone else is checked and anchored while one organisation hangs', async () => {
    vi.useFakeTimers();
    const [stuck = '', ...rest] = orgs(50);
    const { organizations, started } = directory([stuck, ...rest], (orgId) => (orgId === stuck ? undefined : ok(1n)));
    const anchors = createMemoryAnchorStore();
    const { check } = checking(organizations, { anchors });
    const run = check.run();
    await settled();
    // The stuck one still hanging, and the run not ended.
    expect(started).toHaveLength(50);
    for (const orgId of rest) expect(anchors.latest({ kind: 'organisation', orgId })?.seq).toBe(1n);
    expect(anchors.latest({ kind: 'organisation', orgId: stuck })).toBeUndefined();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await run;
  });

  it('checks no more than its lanes at once', async () => {
    const all = orgs(9);
    const { organizations, started, release } = directory(all, () => undefined);
    const { check } = checking(organizations, { lanes: 3 });
    const run = check.run();
    await settled();
    expect(started).toEqual(all.slice(0, 3));
    release(org(2));
    await settled();
    expect(started).toEqual(all.slice(0, 4));
    for (const orgId of all) {
      release(orgId);
      await settled();
    }
    for (const orgId of all) release(orgId);
    await run;
    expect(started).toEqual(all);
  });

  it('stuck organisations hold everyone only for their first deadline, at the default time: seen slow, they take a share', async () => {
    vi.useFakeTimers();
    const stuck = orgs(8);
    const others = Array.from({ length: 40 }, (_, index) => org(index + 100));
    const { organizations, started, release } = directory([...stuck, ...others], (orgId) =>
      stuck.includes(orgId) ? undefined : ok(1n),
    );
    const endThem = async (them: readonly string[]): Promise<void> => {
      for (const orgId of them) release(orgId);
      await settled();
    };
    const { check, capture } = checking(organizations, { lanes: 4 });
    const first = check.run();
    await settled();
    expect(started).toEqual(stuck.slice(0, 4));
    // Past their deadline; each then ends, as a statement limit ends it, freeing what it held.
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await endThem(stuck.slice(0, 4));
    expect(started).toEqual(stuck);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await endThem(stuck);
    await first;
    expect(lines(capture, 'audit.anchor_check_done').at(-1)).toMatchObject({ unchecked: 8, left: 40 });

    // The next run: a slow chain on one lane, and the others straight through everyone else, whose wait was that one run.
    started.length = 0;
    const second = check.run();
    await settled();
    // Those the run's end cut off go again on two lanes, one slow chain on the third, and the fourth has everyone else.
    expect(started.slice(0, 3)).toEqual([stuck[4], stuck[5], stuck[0]]);
    expect(started.slice(3, 43)).toEqual(others);
    await vi.advanceTimersByTimeAsync(RUN_WITHIN_MS);
    await endThem(stuck);
    await second;
  });

  it('a check that comes back fast again no longer counts as slow', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    let hanging = true;
    const { organizations, started, release } = directory(all, (orgId) =>
      orgId === org(3) && hanging ? undefined : ok(1n),
    );
    const { check } = checking(organizations, { lanes: 2 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    release(org(3));
    await first;
    hanging = false;
    started.length = 0;
    // Slow: lane 0 takes it ahead of its place, while lane 1 has the rest.
    await check.run();
    expect(started).toEqual([org(3), org(1), org(2)]);
    started.length = 0;
    await check.run();
    // Quick again: back in its place in the list.
    expect(started).toEqual(all);
  });

  it('a lone lane takes a slow chain turn about with the quick ones (the review: it used to leave them to last, holding the round)', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    let hanging = true;
    const { organizations, started, release } = directory(all, (orgId) =>
      orgId === org(3) && hanging ? undefined : ok(1n),
    );
    const { check } = checking(organizations, { lanes: 1 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    release(org(3));
    await first;
    hanging = false;
    started.length = 0;
    await check.run();
    expect(started).toEqual([org(3), org(1), org(2)]);
  });

  it('a hung hold holds its lane alone', async () => {
    vi.useFakeTimers();
    const all = orgs(6);
    const { organizations, started } = directory(all, (orgId) =>
      orgId === org(1) ? { ok: false, problem: { reason: 'hash', seq: 2n } } : ok(1n),
    );
    const { check } = checking(
      {
        ...organizations,
        hold: (orgId) => (orgId === org(1) ? new Promise<void>(() => undefined) : Promise.resolve()),
      },
      { lanes: 2 },
    );
    const run = check.run();
    await settled();
    expect(started).toEqual(all);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await run;
  });
});

describe('a run ends in its time, with its line, and the next goes on from there', () => {
  it('ends at its time, with the line the dead-man rule reads, whatever is under way and however long its deadline', async () => {
    vi.useFakeTimers();
    const all = orgs(6);
    const { organizations, started } = directory(all, () => undefined);
    const { check, capture } = checking(organizations, { lanes: 2, deadlineMs: 10 * RUN_WITHIN_MS });
    const run = check.run();
    await settled();
    expect(started).toEqual(all.slice(0, 2));
    await vi.advanceTimersByTimeAsync(RUN_WITHIN_MS - 1);
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await run;
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([expect.objectContaining({ left: 4, unchecked: 2 })]);
  });

  it('the time cuts off a check under way without a warning: it goes first next run', async () => {
    vi.useFakeTimers();
    const all = orgs(4);
    let hanging = true;
    const { organizations, started, running } = directory(all, () => (hanging ? undefined : ok(1n)));
    const { check, capture } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await run;
    expect(lines(capture, 'audit.anchor_check_failed')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_unfinished')).toEqual([
      expect.objectContaining({ left: 3, lanes: 1, withinMs: 1000 }),
    ]);
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([expect.objectContaining({ unchecked: 1, left: 3 })]);
    for (const release of running.values()) release();
    await settled();

    hanging = false;
    started.length = 0;
    await check.run();
    expect(started).toEqual(all);
    // The one cut off ended after the run and was anchored then, so this run finds it unchanged.
    expect(lines(capture, 'audit.anchor_check_done').at(-1)).toMatchObject({ anchored: 3, unchanged: 1, left: 0 });
  });

  it('says so when its time ran out on the last one, with none waiting', async () => {
    vi.useFakeTimers();
    const { organizations } = directory(orgs(1), () => undefined);
    const { check, capture } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await run;
    expect(lines(capture, 'audit.anchor_check_unfinished')).toEqual([expect.objectContaining({ left: 0 })]);
  });

  it('a whole round goes by across runs, each organisation in its turn, before the next begins', async () => {
    vi.useFakeTimers();
    const all = orgs(4);
    const { organizations, started, running, release } = directory(all, () => undefined);
    const { check } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    /** One run: the one cut off last run ends this time, the next is cut off in turn. */
    const oneRun = async (): Promise<readonly string[]> => {
      started.length = 0;
      const run = check.run();
      await settled();
      const firstUp = started[0] ?? '';
      release(firstUp);
      await settled();
      await vi.advanceTimersByTimeAsync(1000);
      await run;
      for (const orgId of [...running.keys()]) release(orgId);
      await settled();
      return [...started];
    };
    expect(await oneRun()).toEqual([org(1), org(2)]);
    expect(await oneRun()).toEqual([org(2), org(3)]);
    expect(await oneRun()).toEqual([org(3), org(4)]);
    // The fourth goes last, and only then does the round begin again.
    expect(await oneRun()).toEqual([org(4), org(1)]);
  });

  it('an organisation listed in the middle of a round waits its turn in that round', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    const { organizations, started, list, release } = directory(all, () => undefined);
    const { check } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    release(org(1));
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    release(org(2));
    await settled();

    list.now = [...all, org(4)];
    started.length = 0;
    const second = check.run();
    await settled();
    for (const orgId of [org(2), org(3), org(4)]) {
      release(orgId);
      await settled();
    }
    await second;
    expect(started).toEqual([org(2), org(3), org(4)]);
  });

  it('an organisation leaving the list in the middle of a round is the alarm once, and no check', async () => {
    vi.useFakeTimers();
    const all = orgs(4);
    let hanging = true;
    const { organizations, started, list, release, holds } = directory(all, () => (hanging ? undefined : ok(1n)));
    const { check, capture } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    release(org(1));
    await settled();

    // Org 4 was waiting for its turn.
    list.now = [org(1), org(2), org(3)];
    hanging = false;
    started.length = 0;
    await check.run();
    expect(holds.filter(([orgId]) => orgId === org(4))).toEqual([[org(4), 'unlisted']]);
    expect(
      capture.lines().filter((line) => line.event === 'audit.integrity_failed' && line.reason === 'unlisted'),
    ).toEqual([expect.objectContaining({ orgId: org(4) })]);
    expect(new Set(started)).toEqual(new Set([org(1), org(2), org(3)]));
    expect(started).toHaveLength(3);
  });

  it('an alarm repeats every run, and first, even while the rest of the round waits', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    const { organizations, started, release } = directory(all, (orgId) =>
      orgId === org(3) ? { ok: false, problem: { reason: 'hash', seq: 2n } } : undefined,
    );
    const { check, capture } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    release(org(1));
    await settled();
    release(org(2));
    await settled();
    await first;
    started.length = 0;
    const second = check.run();
    await settled();
    expect(started[0]).toBe(org(3));
    for (const orgId of all) release(orgId);
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    const alarms = capture.lines().filter((line) => line.reason === 'hash');
    expect(alarms).toHaveLength(2);
  });

  it('a stop ends the run at once with nothing said of what is left: the process is going, or the lease', async () => {
    const all = orgs(4);
    const stopping = new AbortController();
    const { organizations } = directory(all, () => undefined);
    const { check, capture } = checking(organizations, { lanes: 1 });
    const run = check.run(stopping.signal);
    await settled();
    stopping.abort();
    await run;
    expect(lines(capture, 'audit.anchor_check_unfinished')).toEqual([]);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_done')).toHaveLength(1);
  });

  it('a run stopped before it began starts no check', async () => {
    const stopping = new AbortController();
    stopping.abort();
    const { organizations, started } = directory(orgs(4));
    const { check } = checking(organizations);
    await check.run(stopping.signal);
    expect(started).toEqual([]);
  });

  it('time run out before the list is read counts against the list: a run that always does still raises the alarm', async () => {
    vi.useFakeTimers();
    const { organizations } = directory(orgs(1));
    const { check, capture, clock } = checking(
      { ...organizations, recorded: () => new Promise<readonly string[]>(() => undefined) },
      { runWithinMs: 1000 },
    );
    clock.advanceBy(STALE_MS);
    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await run;
    expect(lines(capture, 'audit.anchor_check_done')).toHaveLength(1);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'list' })]);
  });

  it('a stop while the list is read still says nothing of the list', async () => {
    const stopping = new AbortController();
    const { organizations } = directory(orgs(1));
    const { check, capture, clock } = checking({
      ...organizations,
      recorded: () => new Promise<readonly string[]>(() => undefined),
    });
    clock.advanceBy(STALE_MS);
    const run = check.run(stopping.signal);
    await settled();
    stopping.abort();
    await run;
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_failed')).toEqual([]);
  });

  it('a platform chain the time cuts off leaves no organisation started', async () => {
    vi.useFakeTimers();
    const { organizations, started } = directory(orgs(1));
    const { check } = checking(organizations, {
      chains: [{ chain: { kind: 'platform' }, verify: () => new Promise<ChainReport>(() => undefined) }],
      runWithinMs: 1000,
    });
    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await run;
    expect(started).toEqual([]);
  });

  it('leaves no timer behind and nothing listening once it ends', async () => {
    vi.useFakeTimers();
    const stopping = new AbortController();
    const { organizations } = directory(orgs(1));
    const removed = vi.spyOn(stopping.signal, 'removeEventListener');
    const { check } = checking(organizations, { durable: logOver(new FixedClock(AT)).log });
    await check.run(stopping.signal);
    expect(vi.getTimerCount()).toBe(0);
    expect(removed).toHaveBeenCalled();
  });
});

describe('how long a turn may take (the bound) and what is said past it', () => {
  it('keeps its lanes to half the pool, and at least one', () => {
    expect(lanesWithin(4, 10)).toBe(4);
    expect(lanesWithin(64, 10)).toBe(5);
    expect(lanesWithin(4, 7)).toBe(3);
    expect(lanesWithin(4, 1)).toBe(1);
  });

  it('states the bound: seven runs’ time, 63 minutes at the default interval, and a run of four minutes', () => {
    expect(RUN_WITHIN_MS).toBe(240_000);
    expect(reachWithin(300_000)).toBe(63 * 60_000);
  });

  it('a whole run of chains with a long round: one failed check is a warning, not the alarm, under the bound', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    let failing = false;
    const { organizations, started, release } = directory(all, () => undefined);
    const verify: OrganisationChains['verify'] = (orgId, anchor) =>
      failing ? Promise.reject(new Error('connect ECONNREFUSED')) : organizations.verify(orgId, anchor);
    const { check, capture, clock } = checking({ ...organizations, verify }, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    release(org(1));
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    expect(started).toEqual([org(1), org(2)]);
    release(org(2));
    await settled();

    // Past the stale period, under the bound: runs aren't reaching them all, so it can't yet mean one has gone missing.
    clock.advanceBy(STALE_MS);
    failing = true;
    await check.run();
    expect(lines(capture, 'audit.anchor_check_failed').length).toBeGreaterThan(0);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
  });

  it('the platform’s chain keeps the short limit however long the organisations’ round: a run always comes to it', async () => {
    vi.useFakeTimers();
    const { organizations } = directory(orgs(3), () => undefined);
    let failing = false;
    const { check, capture, clock } = checking(organizations, {
      lanes: 1,
      runWithinMs: 1000,
      chains: [
        {
          chain: { kind: 'platform' },
          verify: () => (failing ? Promise.reject(new Error('connect ECONNREFUSED')) : Promise.resolve(ok(1n))),
        },
      ],
    });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    clock.advanceBy(STALE_MS);
    failing = true;
    const second = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    expect(lines(capture, 'audit.integrity_failed')).toEqual([
      expect.objectContaining({ chain: 'platform', reason: 'unchecked' }),
    ]);
  });

  it('the alarm for a failed check still comes at the short limit where a run reaches them all', async () => {
    const all = orgs(1);
    let failing = false;
    const { organizations } = directory(all);
    const verify: OrganisationChains['verify'] = (orgId, anchor) =>
      failing ? Promise.reject(new Error('connect ECONNREFUSED')) : organizations.verify(orgId, anchor);
    const { check, capture, clock } = checking({ ...organizations, verify });
    await check.run();
    await check.run();
    clock.advanceBy(STALE_MS);
    failing = true;
    await check.run();
    expect(lines(capture, 'audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'unchecked' })]);
  });

  it('the run finishing a long round still allows the long limit, and a whole round in one run brings the short one back', async () => {
    vi.useFakeTimers();
    const all = orgs(2);
    const hanging = new Set([org(1), org(2)]);
    let failing = false;
    const { organizations, running } = directory(all, (orgId) => (hanging.has(orgId) ? undefined : ok(1n)));
    const verify: OrganisationChains['verify'] = (orgId, anchor) =>
      failing ? Promise.reject(new Error('connect ECONNREFUSED')) : organizations.verify(orgId, anchor);
    const { check, capture, clock } = checking({ ...organizations, verify }, { lanes: 1, runWithinMs: 1000 });
    const alarms = () => lines(capture, 'audit.integrity_failed');
    // Org 1 is cut off, with org 2 left: the round goes over to the next run.
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    for (const release of running.values()) release();
    running.clear();
    await settled();
    hanging.clear();
    // This one finishes the round, leaving none.
    await check.run();
    expect(lines(capture, 'audit.anchor_check_done').at(-1)).toMatchObject({ left: 0 });

    clock.advanceBy(STALE_MS);
    failing = true;
    await check.run();
    expect(alarms()).toEqual([]);

    failing = false;
    await check.run();
    await check.run();
    clock.advanceBy(STALE_MS);
    failing = true;
    await check.run();
    expect(alarms().filter((line) => line.reason === 'unchecked')).toEqual([
      expect.objectContaining({ organisations: 2 }),
    ]);
  });

  it('no run’s turn completing for the whole bound is the alarm, by count, naming the first few; no hold', async () => {
    vi.useFakeTimers();
    const all = orgs(30);
    const { organizations, holds, running } = directory(all, () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const oneRun = async (): Promise<void> => {
      const run = check.run();
      await settled();
      await vi.advanceTimersByTimeAsync(1000);
      await run;
    };
    await oneRun();
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);

    clock.advanceBy(REACH_MS - 1);
    await oneRun();
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);

    clock.advanceBy(1);
    await oneRun();
    // The one still under way all that time is past the ceiling, its own alarm; the other 29 went unreached.
    const alarms = lines(capture, 'audit.integrity_failed');
    expect(alarms).toEqual([
      expect.objectContaining({ reason: 'unchecked', organisations: 1, firstFew: [org(1)] }),
      expect.objectContaining({ reason: 'unreached' }),
    ]);
    expect(alarms[1]).toMatchObject({ level: 'error', chain: 'organisation', check: 'anchor', organisations: 29 });
    expect(alarms[1]?.firstFew as string[]).toHaveLength(5);
    expect(holds.filter(([, failure]) => failure !== undefined)).toEqual([]);
    for (const release of running.values()) release();
  });

  it('an organisation’s wait counts from when it was first seen, as a new one can’t have waited longer', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    const { organizations, list, running } = directory(all, () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    clock.advanceBy(REACH_MS - 1000);
    list.now = [...all, org(4)];
    const second = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    clock.advanceBy(1000);
    const third = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await third;
    // Org 1, under way all that time, is past the ceiling, on its own line; org 4, new, has not waited.
    const alarm = lines(capture, 'audit.integrity_failed').at(-1);
    expect(alarm).toMatchObject({ reason: 'unreached', firstFew: [org(2), org(3)] });
    for (const release of running.values()) release();
  });

  it('after a restart a chain’s wait counts from its anchor in the store, so restarts can’t hide one left out', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    await durable.log.read();
    durable.log.keep(signAnchor(keys, { kind: 'organisation', orgId: org(1) }, ok(1n), AT, durable.log.epoch));
    clock.advanceBy(REACH_MS);
    // A new process, with org 1 known only by its anchor, its check not ending, and org 2 checked and fine.
    const { organizations, running } = directory(orgs(2), (orgId) => (orgId === org(1) ? undefined : ok(1n)));
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const { check, capture } = checking(organizations, { lanes: 2, durable: durable.log, clock, runWithinMs: 1000 });
    const run = check.run();
    await new Promise((resolve) => setImmediate(resolve));
    await vi.advanceTimersByTimeAsync(1000);
    await new Promise((resolve) => setImmediate(resolve));
    await run;
    expect(lines(capture, 'audit.anchor_check_behind')).toEqual([expect.objectContaining({ firstFew: [org(1)] })]);
    for (const release of running.values()) release();
  });

  it('an idle chain’s anchor is signed again as it is checked, past half the bound, and read back at its newer time', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    const { organizations } = directory([org(1)]);
    const { check } = checking(organizations, { lanes: 1, durable: durable.log, clock });
    await check.run();
    const before = durable.fake.calls.puts;
    clock.advanceBy(REACH_MS / 2 - 1);
    await check.run();
    expect(durable.fake.calls.puts).toBe(before);
    clock.advanceBy(1);
    await check.run();
    expect(durable.fake.calls.puts).toBe(before + 1);
    const restarted = durable.restarted();
    await restarted.read();
    expect(restarted.latest({ kind: 'organisation', orgId: org(1) })?.at).toEqual(clock.now());
  });

  it('an idle chain’s anchor is not signed again while the store is unread', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    const { organizations } = directory([org(1)]);
    const { check } = checking(organizations, { lanes: 1, durable: durable.log, clock });
    await check.run();
    durable.fake.instead.list = () => Promise.reject(new Error('the store is away'));
    const keptAt = durable.log.latest({ kind: 'organisation', orgId: org(1) })?.at;
    const next = durable.restarted();
    next.keep(signAnchor(keys, { kind: 'organisation', orgId: org(1) }, ok(1n), AT, next.epoch));
    clock.advanceBy(REACH_MS);
    const { check: unread } = checking(organizations, { lanes: 1, durable: next, clock });
    await unread.run();
    expect(next.latest({ kind: 'organisation', orgId: org(1) })?.at).toEqual(keptAt);
  });

  it('`unanchored`: a chain whose anchor landed during its check goes first next run, so the gap is one interval and one run', async () => {
    vi.useFakeTimers();
    const all = orgs(5);
    const anchors = createMemoryAnchorStore();
    const landed = signAnchor(keys, { kind: 'organisation', orgId: org(5) }, ok(7n), AT);
    const { organizations, started, release } = directory(all, () => undefined);
    const verify: OrganisationChains['verify'] = (orgId, anchor) => {
      // The anchor landing while the last of the round is checked: an honest copy, or the store's late read.
      if (orgId === org(5) && anchor === undefined) anchors.keep(landed);
      return organizations.verify(orgId, anchor);
    };
    const { check, capture } = checking({ ...organizations, verify }, { lanes: 1, anchors, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    for (const orgId of all) {
      release(orgId);
      await settled();
    }
    await first;
    expect(lines(capture, 'audit.anchor_check_done').at(-1)).toMatchObject({ unanchored: 1 });
    started.length = 0;
    const second = check.run();
    await settled();
    expect(started).toEqual([org(5)]);
    release(org(5));
    await settled();
    // Its head is behind what landed: the alarm, on the very next run, before anyone else's turn.
    expect(capture.lines().filter((line) => line.reason === 'anchor')).toEqual([
      expect.objectContaining({ orgId: org(5), anchorSeq: '7' }),
    ]);
    for (const orgId of all) {
      release(orgId);
      await settled();
    }
    await second;
  });
});

/** The anchors' store, fake, over this clock. */
function logOver(clock: FixedClock) {
  const capture = new LogCapture();
  const fake = createFakeWriteOnceStore();
  const logOn = (lines: LogCapture): AnchorLog =>
    createAnchorLog({
      store: fake.store,
      keys,
      logger: testLogger(lines),
      now: () => clock.now(),
      epoch: 1,
      alertAfterMs: 120_000,
    });
  return { log: logOn(capture), restarted: () => logOn(new LogCapture()), fake, capture };
}

describe('writes come on a schedule of their own during a run', () => {
  /** A real zlib in `flush`: fake timers would hold it, so these let real time pass in small steps. */
  const untilTrue = async (condition: () => boolean): Promise<void> => {
    await vi.waitUntil(condition, { timeout: 4000, interval: 2 });
  };

  it('what lanes finished is written while another hangs, with no lane waiting on the store', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    const all = orgs(3);
    const { organizations, release } = directory(all, (orgId) => (orgId === org(1) ? undefined : ok(1n)));
    const { check, capture } = checking(organizations, {
      durable: durable.log,
      clock,
      writeEveryMs: 5,
      lanes: 2,
    });
    const run = check.run();
    // The stuck one still hanging, and the others already in the store.
    await untilTrue(() => durable.capture.lines().some((line) => line.event === 'audit.anchors_written'));
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([]);
    const restarted = durable.restarted();
    await restarted.read();
    expect(restarted.latest({ kind: 'organisation', orgId: org(2) })?.seq).toBe(1n);
    expect(restarted.latest({ kind: 'organisation', orgId: org(1) })).toBeUndefined();
    release(org(1));
    await run;
  });

  it('a run stopped midway leaves what it finished written, as when the lease goes and nothing calls `finish`', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    const stopping = new AbortController();
    const { organizations } = directory(orgs(3), (orgId) => (orgId === org(1) ? undefined : ok(1n)));
    const { check } = checking(organizations, { durable: durable.log, clock, lanes: 2 });
    const run = check.run(stopping.signal);
    await untilTrue(() => durable.log.latest({ kind: 'organisation', orgId: org(3) }) !== undefined);
    stopping.abort();
    await run;
    await untilTrue(() => durable.fake.files.size > 0);
    const restarted = durable.restarted();
    await restarted.read();
    expect(restarted.latest({ kind: 'organisation', orgId: org(2) })?.seq).toBe(1n);
  });

  it('a store failing is said during a long run, and in time the alert, not only at its end', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    await durable.log.read();
    durable.fake.instead.put = () => Promise.reject(new Error('the store is away'));
    const { organizations, release } = directory(orgs(2), (orgId) => (orgId === org(1) ? undefined : ok(1n)));
    const { check, capture } = checking(organizations, {
      durable: durable.log,
      clock,
      writeEveryMs: 5,
      lanes: 2,
    });
    const run = check.run();
    await untilTrue(() => durable.capture.lines().some((line) => line.event === 'audit.anchor_store_write_failed'));
    clock.advanceBy(120_000);
    await untilTrue(() => durable.capture.lines().some((line) => line.event === 'audit.anchor_store_unwritable'));
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([]);
    release(org(1));
    await run;
  });

  it('a store that hangs holds no lane and no check: the run goes through everyone, and its last write has a minute', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    await durable.log.read();
    durable.fake.instead.put = () => new Promise<void>(() => undefined);
    const all = orgs(6);
    const { organizations, started } = directory(all);
    const { check, capture } = checking(organizations, { durable: durable.log, clock });
    const run = check.run();
    await vi.advanceTimersByTimeAsync(0);
    await new Promise((resolve) => setImmediate(resolve));
    expect(started).toEqual(all);
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([]);
    await vi.advanceTimersByTimeAsync(59_999);
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await run;
    expect(lines(capture, 'audit.anchor_check_done')).toHaveLength(1);
    expect(durable.capture.lines().filter((line) => line.event === 'audit.anchor_store_write_failed')).toHaveLength(1);
  });

  it('no writes after the run, even with a write under way as it ends: the timer ends with it', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    await durable.log.read();
    const { promise: letGo, resolve: release } = Promise.withResolvers<undefined>();
    durable.fake.instead.put = async (name, bytes) => {
      await letGo;
      return durable.fake.real.put(name, bytes);
    };
    const { organizations, release: endCheck } = directory(orgs(2), (orgId) => (orgId === org(1) ? undefined : ok(1n)));
    const { check } = checking(organizations, { durable: durable.log, clock, writeEveryMs: 1 });
    const running = check.run();
    // The timer's write under way, held at the store, as the run's last check ends.
    await vi.waitUntil(() => durable.fake.calls.puts > 0, { timeout: 4000, interval: 1 });
    endCheck(org(1));
    await new Promise((resolve) => setTimeout(resolve, 5));
    release(undefined);
    await running;
    await new Promise((resolve) => setTimeout(resolve, 5));
    // What moves after the run waits for the next: a timer gone on would write it.
    durable.log.keep(signAnchor(keys, { kind: 'organisation', orgId: org(9) }, ok(1n), AT));
    const after = durable.fake.calls.puts;
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(durable.fake.calls.puts).toBe(after);
  });
});

describe('second round (4D2e E6 review): any number of organisations may slow it, never break it or cry tamper', () => {
  const slowFirst = async (
    check: { run(): Promise<void> },
    slowOnes: readonly string[],
    release: (id: string) => void,
  ) => {
    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    for (const orgId of slowOnes) release(orgId);
    await settled();
    await run;
  };

  it('#1 quick organisations go round on their own, every run, however long the slow chains take', async () => {
    vi.useFakeTimers();
    const hanging = new Set([org(1), org(2), org(3)]);
    const all = orgs(6);
    const { organizations, started, release } = directory(all, (orgId) => (hanging.has(orgId) ? undefined : ok(1n)));
    const { check } = checking(organizations, { lanes: 2, runWithinMs: SLOW_AFTER_MS * 2 });
    // All three seen slow, two lanes' worth at a time.
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    release(org(1));
    release(org(2));
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    release(org(3));
    await first;
    await settled();

    // One slow chain hangs through each whole run with others of its kind waiting; the quick ones go round every time.
    for (let round = 0; round < 3; round += 1) {
      started.length = 0;
      const run = check.run();
      await settled();
      expect(started.filter((orgId) => !hanging.has(orgId))).toEqual([org(4), org(5), org(6)]);
      await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS * 2);
      await run;
      for (const orgId of hanging) release(orgId);
      await settled();
    }
  });

  it('#1 an idle lane takes a slow chain, so a few long chains are not held to one lane', async () => {
    vi.useFakeTimers();
    const hanging = new Set([org(1), org(2)]);
    const { organizations, running, release } = directory(orgs(3), (orgId) =>
      hanging.has(orgId) ? undefined : ok(1n),
    );
    const { check } = checking(organizations, { lanes: 2 });
    await slowFirst(check, [org(1), org(2)], release);
    const run = check.run();
    await settled();
    // Org 3 done at once on its lane: that lane is free, so both slow chains are under way.
    expect([...running.keys()]).toEqual([org(1), org(2)]);
    for (const orgId of hanging) release(orgId);
    await run;
  });

  it('#1 and #4 lateness is judged over all of them, and with turns progressing it is capacity, said by count', async () => {
    vi.useFakeTimers();
    const hanging = new Set([org(1), org(3)]);
    const { organizations, release } = directory(orgs(4), (orgId) => (hanging.has(orgId) ? undefined : ok(1n)));
    const { check, capture, clock } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    release(org(1));
    await settled();
    hanging.delete(org(1));
    clock.advanceBy(REACH_MS);
    // Org 1 came first, as the one cut off, and org 2 after it: both complete. Org 3 is under way as the time runs out.
    const second = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    release(org(3));
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_behind')).toEqual([
      expect.objectContaining({ level: 'error', organisations: 2, firstFew: [org(3), org(4)], lanes: 1 }),
    ]);
  });

  it('#2 restarts more often than a round: every chain still gets its turn, idle ones too, from what the store holds', async () => {
    const clock = new FixedClock(AT);
    const fake = createFakeWriteOnceStore();
    const all = orgs(8);
    const turnsSeen = new Set<string>();
    for (let life = 0; life < 8 && turnsSeen.size < all.length; life += 1) {
      const durable = createAnchorLog({
        store: fake.store,
        keys,
        logger: testLogger(),
        now: () => clock.now(),
        epoch: 1,
        alertAfterMs: 120_000,
      });
      const stopping = new AbortController();
      let turnsThisLife = 0;
      const { organizations } = directory(all);
      const verify: OrganisationChains['verify'] = (orgId, anchor) => {
        turnsSeen.add(orgId);
        turnsThisLife += 1;
        // The API is stopped, as a release would, after two chains' checks of the round.
        if (turnsThisLife === 2) stopping.abort();
        return organizations.verify(orgId, anchor);
      };
      const { check } = checking({ ...organizations, verify }, { lanes: 1, durable, clock });
      await check.run(stopping.signal);
      await check.finish();
      // Long enough that an idle chain's check is worth saying again in the store.
      clock.advanceBy(REACH_MS);
    }
    expect(turnsSeen).toEqual(new Set(all));
  });

  it('#2 orders a round by the store: never anchored first, then the oldest anchor', async () => {
    const clock = new FixedClock(AT);
    const anchors = logOver(clock);
    await anchors.log.read();
    const point = (index: number, at: Date) =>
      signAnchor(keys, { kind: 'organisation', orgId: org(index) }, ok(1n), at, anchors.log.epoch);
    anchors.log.keep(point(1, new Date(AT.getTime() - 1000)));
    anchors.log.keep(point(2, new Date(AT.getTime() - 3000)));
    anchors.log.keep(point(3, new Date(AT.getTime() - 2000)));
    const { organizations, started } = directory(orgs(4));
    const { check } = checking(organizations, { lanes: 1, durable: anchors.log, clock });
    await check.run();
    expect(started).toEqual([org(4), org(2), org(3), org(1)]);
  });

  it('#2 with no store a round is shuffled afresh, so restarts can’t keep a tail unreached', async () => {
    const all = orgs(5);
    const turnsSeen = new Set<string>();
    for (let life = 0; life < 300 && turnsSeen.size < all.length; life += 1) {
      const stopping = new AbortController();
      const { organizations } = directory(all);
      const verify: OrganisationChains['verify'] = (orgId, anchor) => {
        turnsSeen.add(orgId);
        stopping.abort();
        return organizations.verify(orgId, anchor);
      };
      const { check } = checking({ ...organizations, verify }, { lanes: 1, shuffled: shuffledAfresh });
      await check.run(stopping.signal);
    }
    expect(turnsSeen).toEqual(new Set(all));
  });

  it('#3 past the most it notes it refuses nothing: all checked, with one SEV-2 line and no tamper alarm', async () => {
    const all = orgs(5);
    const { organizations, started } = directory(all);
    const { check, capture } = checking(organizations, { lanes: 2, mostOrganisations: 3 });
    await check.run();
    expect(started).toHaveLength(5);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_over_size')).toEqual([
      expect.objectContaining({ level: 'error', listed: 5, beyond: 2, most: 3 }),
    ]);
  });

  it('#3 a list one past the default is no tamper alarm', { timeout: 60_000 }, async () => {
    const all = Array.from({ length: 100_001 }, (_, index) => org(index + 1));
    const { organizations } = directory(all);
    const { check, capture } = checking(organizations);
    await check.run();
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_over_size')).toHaveLength(1);
  });

  it('#4 no turn completing at all is the alarm, by count, with the bound passed', async () => {
    vi.useFakeTimers();
    const { organizations, running, release } = directory(orgs(4), () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    for (const orgId of [...running.keys()]) release(orgId);
    await settled();
    clock.advanceBy(REACH_MS);
    const second = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    expect(lines(capture, 'audit.anchor_check_behind')).toEqual([]);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([expect.objectContaining({ reason: 'unreached' })]);
  });

  it('#4 a chain past its deadline that then finishes is compared all the same: its failure the alarm, its head anchored', async () => {
    vi.useFakeTimers();
    const anchors = createMemoryAnchorStore();
    const answers = new Map<string, (report: ChainReport) => void>();
    const { organizations } = directory(orgs(2));
    const verify: OrganisationChains['verify'] = (orgId) =>
      new Promise((resolve) => {
        answers.set(orgId, resolve);
      });
    const { check, capture } = checking({ ...organizations, verify }, { lanes: 2, anchors });
    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await run;
    answers.get(org(1))?.(ok(5n));
    answers.get(org(2))?.({ ok: false, problem: { reason: 'hash', seq: 2n } });
    await settled();
    expect(anchors.latest({ kind: 'organisation', orgId: org(1) })?.seq).toBe(5n);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'hash', orgId: org(2) }),
    ]);
  });

  it('#5 checks in flight, hung ones among them, never pass the lanes; one ending makes room in the same run', async () => {
    vi.useFakeTimers();
    const all = orgs(9);
    const { organizations, started, running, release } = directory(all, () => undefined);
    const { check } = checking(organizations, { lanes: 2 });
    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await settled();
    expect(running.size).toBe(2);
    expect(started).toHaveLength(2);
    release(org(1));
    await settled();
    expect(started).toHaveLength(3);
    expect(running.size).toBe(2);
    await vi.advanceTimersByTimeAsync(RUN_WITHIN_MS);
    for (const orgId of all) release(orgId);
    await run;
  });

  it('#5 repeats take at most half the lanes, so fresh chains always advance', async () => {
    vi.useFakeTimers();
    const failing = orgs(8);
    const fresh = Array.from({ length: 20 }, (_, index) => org(index + 100));
    let hang = false;
    const { organizations, started, running } = directory([...failing, ...fresh], (orgId) => {
      if (fresh.includes(orgId)) return ok(1n);
      return hang ? undefined : { ok: false, problem: { reason: 'hash', seq: 2n } };
    });
    const { check } = checking(organizations, { lanes: 4 });
    await check.run();
    hang = true;
    started.length = 0;
    const run = check.run();
    await settled();
    // Two lanes hold repeats, and the other two go through every fresh chain; only then may idle lanes take more.
    expect(started.slice(0, 2)).toEqual(failing.slice(0, 2));
    expect(started.slice(2, 22)).toEqual(fresh);
    await vi.advanceTimersByTimeAsync(RUN_WITHIN_MS);
    for (const release of running.values()) release();
    await run;
  });

  it('#5 a lone lane takes turn about, so repeats can’t starve fresh chains there either', async () => {
    const { organizations, started } = directory(orgs(4), (orgId) =>
      orgId === org(1) || orgId === org(2) ? { ok: false, problem: { reason: 'hash', seq: 2n } } : ok(1n),
    );
    const { check } = checking(organizations, { lanes: 1 });
    await check.run();
    started.length = 0;
    await check.run();
    expect(started).toEqual([org(1), org(3), org(2), org(4)]);
  });

  it('a database down is one line a run however many chains: the count and a few, and past the limit one alarm line', async () => {
    const all = orgs(12);
    const { organizations, holds } = directory(all);
    let down = false;
    const verify: OrganisationChains['verify'] = (orgId, anchor) =>
      down ? Promise.reject(new Error('connect ECONNREFUSED')) : organizations.verify(orgId, anchor);
    const { check, capture, clock } = checking({ ...organizations, verify }, { lanes: 2 });
    await check.run();
    down = true;
    await check.run();
    expect(lines(capture, 'audit.anchor_check_failed')).toEqual([
      expect.objectContaining({ level: 'warn', chain: 'organisation', chains: 12, firstFew: all.slice(0, 5) }),
    ]);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);

    clock.advanceBy(STALE_MS);
    await check.run();
    expect(lines(capture, 'audit.anchor_check_failed')).toHaveLength(2);
    // What the SEV-1 alert counts: this event, once, with how many it covers.
    expect(lines(capture, 'audit.integrity_failed')).toEqual([
      expect.objectContaining({ chain: 'organisation', check: 'anchor', reason: 'unchecked', organisations: 12 }),
    ]);
    expect(holds.filter(([, failure]) => failure !== undefined)).toEqual([]);
  });

  it('the hand-off’s own check of one organisation still says so on its own line, as no run sums it up', async () => {
    const { organizations } = directory([org(1)]);
    const verify: OrganisationChains['verify'] = () => Promise.reject(new Error('connect ECONNREFUSED'));
    const { check, capture } = checking({ ...organizations, verify }, { lanes: 1 });
    await check.anchorOrganisation(org(1));
    expect(lines(capture, 'audit.anchor_check_failed')).toEqual([
      expect.objectContaining({ chain: 'organisation', orgId: org(1) }),
    ]);
  });

  it('#8 a list that can’t be read leaves the last in use, with a warning: everyone is still checked', async () => {
    const all = orgs(3);
    const { organizations, started } = directory(all);
    let failing = false;
    const list = () =>
      failing ? Promise.reject(new Error('canceling statement due to statement timeout')) : organizations.list();
    const { check, capture } = checking({ ...organizations, list }, { lanes: 1 });
    await check.run();
    failing = true;
    started.length = 0;
    await check.run();
    expect(started).toEqual(all);
    expect(lines(capture, 'audit.anchor_check_failed')).toEqual([expect.objectContaining({ check: 'list' })]);
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
  });

  it('a run’s last write takes what moved during a write already under way, so nothing waits for the next run', async () => {
    const clock = new FixedClock(AT);
    const durable = logOver(clock);
    await durable.log.read();
    const { promise: letGo, resolve: release } = Promise.withResolvers<undefined>();
    durable.fake.instead.put = async (name, bytes) => {
      await letGo;
      return durable.fake.real.put(name, bytes);
    };
    const { organizations, release: endCheck } = directory(orgs(2), (orgId) => (orgId === org(1) ? undefined : ok(1n)));
    const { check } = checking(organizations, { durable: durable.log, clock, writeEveryMs: 1 });
    const running = check.run();
    await vi.waitUntil(() => durable.fake.calls.puts > 0, { timeout: 4000, interval: 1 });
    // Org 1 anchors after the file under way was made.
    endCheck(org(1));
    await new Promise((resolve) => setTimeout(resolve, 5));
    release(undefined);
    await running;
    const restarted = durable.restarted();
    await restarted.read();
    expect(restarted.latest({ kind: 'organisation', orgId: org(1) })?.seq).toBe(1n);
  });
});

describe('third round (4D2e E6 review)', () => {
  const unreached = (capture: LogCapture) =>
    lines(capture, 'audit.integrity_failed').filter((line) => line.reason === 'unreached');

  it('#1 a slow chain keeps its mark through a run-end cut and a "not finished" miss, so quick chains keep their lanes', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    let hanging = true;
    const { organizations, started, release } = directory(all, (orgId) =>
      orgId === org(3) && hanging ? undefined : ok(1n),
    );
    const { check } = checking(organizations, { lanes: 2 });
    const marking = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    release(org(3));
    await marking;
    await settled();

    // Cut off soon after it starts: a second, not a check run to its end.
    const stopping = new AbortController();
    const cut = check.run(stopping.signal);
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    stopping.abort();
    await cut;
    // Still under way, so its turn meets "has not finished".
    await check.run();

    release(org(3));
    await settled();
    hanging = false;
    started.length = 0;
    await check.run();
    await check.run();
    // Slow still: taken ahead of its place on the slow lane's share, as a quick chain would not be.
    expect(started.slice(0, 3)).toEqual([org(3), org(1), org(2)]);
  });

  it('#3 one bad run while behind says nothing of tamper: a turn completed within the bound', async () => {
    const all = orgs(2);
    const { organizations } = directory(all);
    let downFor: (orgId: string) => boolean = () => false;
    const verify: OrganisationChains['verify'] = (orgId, anchor) =>
      downFor(orgId) ? Promise.reject(new Error('connect ECONNREFUSED')) : organizations.verify(orgId, anchor);
    const { check, capture, clock } = checking({ ...organizations, verify }, { lanes: 2 });
    await check.run();
    clock.advanceBy(REACH_MS - 1);
    downFor = (orgId) => orgId === org(2);
    await check.run();
    clock.advanceBy(1);
    downFor = () => true;
    await check.run();
    expect(unreached(capture)).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_behind')).toEqual([]);
  });

  it('#3 a check landing between runs counts as a turn completed', async () => {
    vi.useFakeTimers();
    const all = orgs(4);
    const { organizations, release } = directory(all, () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 3, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    clock.advanceBy(REACH_MS - 1);
    // Two land between the runs. The next run completes no turn; org 4, never reached, is the late one.
    release(org(1));
    release(org(2));
    await settled();
    clock.advanceBy(1);
    const second = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    expect(unreached(capture)).toEqual([]);
    release(org(3));
    release(org(4));
  });

  it('#3 wedged lanes raise the alarm at the bound, however many hand-offs land', async () => {
    const all = orgs(2);
    const { organizations } = directory(all);
    let down = false;
    let handingOff = false;
    const verify: OrganisationChains['verify'] = (orgId, anchor) =>
      down && !handingOff ? Promise.reject(new Error('connect ECONNREFUSED')) : organizations.verify(orgId, anchor);
    const { check, capture, clock } = checking({ ...organizations, verify }, { lanes: 2 });
    await check.run();
    down = true;
    clock.advanceBy(REACH_MS - 1);
    handingOff = true;
    await check.anchorOrganisation(org(1));
    handingOff = false;
    clock.advanceBy(1);
    await check.run();
    expect(unreached(capture)).toEqual([expect.objectContaining({ organisations: 1, firstFew: [org(2)] })]);
  });

  it('#5 past the cap every chain still takes its turn, by a cursor that goes on between runs', async () => {
    vi.useFakeTimers();
    const all = orgs(6);
    const { organizations, started } = directory(all);
    // Each check takes real time, so a run of a second gets through two or three on its lone lane.
    const verify: OrganisationChains['verify'] = async (orgId, anchor) => {
      await new Promise((resolve) => setTimeout(resolve, 400));
      return organizations.verify(orgId, anchor);
    };
    const { check, capture } = checking(
      { ...organizations, verify },
      { lanes: 1, mostOrganisations: 1, runWithinMs: 1000 },
    );
    // The stated bound: a lone lane reaches one chain past the cap at least every second run, so ten runs for these five.
    for (let runs = 0; runs < 10 && new Set(started).size < all.length; runs += 1) {
      const run = check.run();
      await vi.advanceTimersByTimeAsync(1000);
      await run;
      await vi.advanceTimersByTimeAsync(400);
    }
    expect(new Set(started)).toEqual(new Set(all));
    expect(lines(capture, 'audit.anchor_check_over_size').at(0)).toMatchObject({ level: 'error', beyond: 5, most: 1 });
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
  });

  it('#5 past the cap a restart starts anywhere, so restarts more often than a round leave no tail unchecked', async () => {
    const all = orgs(6);
    const turnsSeen = new Set<string>();
    for (let life = 0; life < 300 && turnsSeen.size < all.length; life += 1) {
      const stopping = new AbortController();
      let turnsThisLife = 0;
      const { organizations } = directory(all);
      const verify: OrganisationChains['verify'] = (orgId, anchor) => {
        turnsSeen.add(orgId);
        turnsThisLife += 1;
        if (turnsThisLife === 2) stopping.abort();
        return organizations.verify(orgId, anchor);
      };
      const { check } = checking(
        { ...organizations, verify },
        { lanes: 1, mostOrganisations: 1, pastCapStart: startAnywhere },
      );
      await check.run(stopping.signal);
    }
    expect(turnsSeen).toEqual(new Set(all));
  });

  it('#5 the start of a round past the cap goes where it is told, once in a process, and then the cursor goes on', async () => {
    const all = orgs(5);
    const asked: number[] = [];
    const { organizations, started } = directory(all);
    const { check } = checking(organizations, {
      lanes: 1,
      mostOrganisations: 1,
      pastCapStart: (count) => {
        asked.push(count);
        return 2;
      },
    });
    await check.run();
    expect(started.filter((orgId) => orgId !== org(1))).toEqual([org(4), org(5), org(2), org(3)]);
    started.length = 0;
    await check.run();
    expect(started.filter((orgId) => orgId !== org(1))).toEqual([org(4), org(5), org(2), org(3)]);
    expect(asked).toEqual([4]);
  });

  it('#5 a run that reaches none past the cap does not put back how long they have waited', () => {
    const turns = createTurns(
      1,
      (orgIds) => orgIds,
      () => 0,
    );
    const past = [org(2), org(3)];
    turns.begin([], [], [], past);
    expect(turns.pastCapStarts()).toBe(true);
    turns.begin([], [], [], past);
    expect(turns.pastCapStarts()).toBe(false);
    expect(turns.next()).toBe(org(2));
    turns.begin([], [], [], past);
    expect(turns.pastCapStarts()).toBe(false);
    expect(turns.next()).toBe(org(3));
    turns.begin([], [], [], past);
    expect(turns.pastCapStarts()).toBe(true);
  });

  it('a mass removal from the list names the first 20, and one line counts the rest: still the tamper alarm', async () => {
    const all = orgs(30);
    const { organizations, list, holds } = directory(all);
    const { check, capture } = checking(organizations, { lanes: 4 });
    await check.run();
    list.now = all.slice(25);
    await check.run();
    const said = lines(capture, 'audit.integrity_failed').filter((line) => line.reason === 'unlisted');
    const named = said.filter((line) => line.organisations === undefined);
    expect(named).toHaveLength(20);
    expect(said.filter((line) => line.organisations !== undefined)).toEqual([
      expect.objectContaining({ level: 'error', chain: 'organisation', check: 'anchor', organisations: 5 }),
    ]);
    expect(lines(capture, 'audit.anchor_check_behind')).toEqual([]);
    // Every one held all the same, and the next run says it all again.
    expect(holds.filter(([, reason]) => reason === 'unlisted')).toHaveLength(25);
    await check.run();
    expect(lines(capture, 'audit.integrity_failed').filter((line) => line.reason === 'unlisted')).toHaveLength(42);
  });

  it('20 removed or fewer are all named, with no line of the rest', async () => {
    const all = orgs(21);
    const { organizations, list } = directory(all);
    const { check, capture } = checking(organizations, { lanes: 2 });
    await check.run();
    list.now = all.slice(20);
    await check.run();
    const said = lines(capture, 'audit.integrity_failed').filter((line) => line.reason === 'unlisted');
    expect(said).toHaveLength(20);
    expect(said.every((line) => line.organisations === undefined)).toBe(true);
  });

  it('#5 a wind-back on the last chain past the cap is found, with its hold', async () => {
    const all = orgs(4);
    let wound = false;
    const { organizations, holds } = directory(all, (orgId) => (orgId === org(4) && wound ? ok(1n) : ok(5n)));
    const { check, capture } = checking(organizations, { lanes: 2, mostOrganisations: 1 });
    await check.run();
    wound = true;
    await check.run();
    expect(lines(capture, 'audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'anchor', orgId: org(4) }),
    ]);
    expect(holds).toContainEqual([org(4), 'anchor']);
  });

  it('#5 chains past the cap have a share of the lanes: known chains filling every run can’t starve them', async () => {
    vi.useFakeTimers();
    const known = orgs(3);
    const past = Array.from({ length: 3 }, (_, index) => org(index + 100));
    const { organizations, started, running, release } = directory([...known, ...past], (orgId) =>
      known.includes(orgId) ? undefined : ok(1n),
    );
    const { check } = checking(organizations, { lanes: 2, mostOrganisations: 3 });
    const run = check.run();
    await settled();
    // One lane on a known chain, hanging; the other goes on through those past the cap.
    expect(started.filter((orgId) => past.includes(orgId))).toEqual(past);
    await vi.advanceTimersByTimeAsync(RUN_WITHIN_MS);
    for (const orgId of known) release(orgId);
    await run;
    expect(running.size).toBe(0);
  });

  it('#5 and #6 recorded but off the list is the alarm past the cap too, from the two lists in memory', async () => {
    const { organizations, holds } = directory(orgs(2));
    const { check, capture } = checking(
      { ...organizations, recorded: () => Promise.resolve(orgs(3)) },
      { lanes: 2, mostOrganisations: 1 },
    );
    await check.run();
    expect(capture.lines().filter((line) => line.reason === 'unlisted')).toEqual([
      expect.objectContaining({ orgId: org(3) }),
    ]);
    expect(holds).toContainEqual([org(3), 'unlisted']);
  });

  it('#7 a check still running past the stale window is capacity, not the alarm; one that fails past it is the alarm', async () => {
    vi.useFakeTimers();
    const { organizations, running, release } = directory(orgs(1), () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 2 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await first;
    clock.advanceBy(STALE_MS);
    await check.run();
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([]);
    // Still running past the bound: late, and said as capacity with a turn completing elsewhere.
    for (const orgId of [...running.keys()]) release(orgId);
    await settled();
    const failing = directory(orgs(1));
    const rejected = checking({
      ...failing.organizations,
      verify: (orgId, anchor) =>
        failing.started.length > 0
          ? Promise.reject(new Error('connect ECONNREFUSED'))
          : failing.organizations.verify(orgId, anchor),
    });
    await rejected.check.run();
    rejected.clock.advanceBy(STALE_MS);
    await rejected.check.run();
    expect(rejected.capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([
      expect.objectContaining({ organisations: 1 }),
    ]);
  });

  it('a run of more organisations than an array spread can take is no crash', { timeout: 60_000 }, async () => {
    const all = Array.from({ length: 200_000 }, (_, index) => org(index + 1));
    const { organizations } = directory(all);
    const { check, capture } = checking(organizations, { mostOrganisations: 300_000 });
    await check.run();
    expect(lines(capture, 'audit.anchor_check_crashed')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_done').at(-1)).toMatchObject({ chains: 200_000 });
  });
});

describe('fourth round (4D2e E6 review)', () => {
  /** A check of a whole chain that rejects only past its deadline, each turn: the failure `report` says. */
  const lateFailure = (failure: () => Error) => {
    const { organizations } = directory([org(1)]);
    const verify: OrganisationChains['verify'] = () =>
      new Promise((_, reject) => {
        setTimeout(() => {
          reject(failure());
        }, DEADLINE_MS + 1000);
      });
    return { ...organizations, verify };
  };
  /** One run past the check's deadline, and then its late end. */
  const lateRun = async (check: { run(): Promise<void> }): Promise<void> => {
    const run = check.run();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await run;
    await vi.advanceTimersByTimeAsync(1000);
  };

  it('#1 a check that fails past its deadline, every turn, is the alarm by the stale limit', async () => {
    vi.useFakeTimers();
    const { check, capture, clock } = checking(lateFailure(() => new Error('Query read timeout')));
    await lateRun(check);
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([]);
    clock.advanceBy(STALE_MS);
    await lateRun(check);
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([
      expect.objectContaining({ orgId: org(1), chain: 'organisation' }),
    ]);
  });

  it('#1 a store’s broken contract, or a refusal, past the deadline is the `store` alarm, with its hold', async () => {
    for (const failure of [
      () => new ChainStoreError('a row that cannot be'),
      () => Object.assign(new Error('permission denied'), { code: '42501' }),
    ]) {
      vi.useFakeTimers();
      const organizations = lateFailure(failure);
      const holds: (string | undefined)[] = [];
      const { check, capture } = checking({
        ...organizations,
        hold: (_, reason) => {
          holds.push(reason);
          return Promise.resolve();
        },
      });
      await lateRun(check);
      expect(capture.lines().filter((line) => line.reason === 'store')).toEqual([
        expect.objectContaining({ orgId: org(1) }),
      ]);
      expect(holds).toContain('store');
    }
  });

  it('#1 past the run’s own end too: a check cut off that then fails is counted', async () => {
    vi.useFakeTimers();
    const { check, capture, clock } = checking(
      lateFailure(() => new Error('connection lost')),
      { runWithinMs: 1000 },
    );
    const first = check.run();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    await vi.advanceTimersByTimeAsync(DEADLINE_MS + 1000);
    clock.advanceBy(STALE_MS);
    const second = check.run();
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    await vi.advanceTimersByTimeAsync(DEADLINE_MS + 1000);
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toHaveLength(1);
  });

  it('#2 one chain in flight past the ceiling, while others complete, is `unchecked`: no hold, and not capacity', async () => {
    vi.useFakeTimers();
    const { organizations, holds, running } = directory(orgs(3), (orgId) => (orgId === org(1) ? undefined : ok(1n)));
    const { check, capture, clock } = checking(organizations, { lanes: 2 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await first;
    clock.advanceBy(REACH_MS - 1);
    await check.run();
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([]);
    clock.advanceBy(1);
    await check.run();
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([
      expect.objectContaining({ level: 'error', chain: 'organisation', organisations: 1, firstFew: [org(1)] }),
    ]);
    expect(lines(capture, 'audit.anchor_check_behind').at(-1)?.firstFew ?? []).not.toContain(org(1));
    expect(holds.filter(([, reason]) => reason !== undefined)).toEqual([]);
    expect(running.size).toBe(1);
  });

  it('#2 the same for the platform chain, on its own line', async () => {
    vi.useFakeTimers();
    const { check, capture, clock } = checking(directory([]).organizations, {
      chains: [{ chain: { kind: 'platform' }, verify: () => new Promise<ChainReport>(() => undefined) }],
    });
    const first = check.run();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await first;
    clock.advanceBy(REACH_MS);
    await check.run();
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([
      expect.objectContaining({ chain: 'platform' }),
    ]);
  });

  it('#2 in flight past the stale limit but under the ceiling is `behind` where the chain is late, never the alarm', async () => {
    vi.useFakeTimers();
    let hanging = false;
    const { organizations } = directory(orgs(2), (orgId) => (orgId === org(1) && hanging ? undefined : ok(1n)));
    const { check, capture, clock } = checking(organizations, { lanes: 2 });
    await check.run();
    clock.advanceBy(REACH_MS - STALE_MS);
    hanging = true;
    const second = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await second;
    clock.advanceBy(STALE_MS);
    await check.run();
    expect(capture.lines().filter((line) => line.reason === 'unchecked')).toEqual([]);
    expect(lines(capture, 'audit.anchor_check_behind').at(-1)).toMatchObject({ firstFew: [org(1)] });
  });

  it('#2 ending under the ceiling clears it: a long honest chain raises nothing', async () => {
    vi.useFakeTimers();
    const { organizations, release } = directory(orgs(1), () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 2 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await first;
    clock.advanceBy(REACH_MS - 1);
    release(org(1));
    await settled();
    clock.advanceBy(1);
    const second = check.run();
    await settled();
    release(org(1));
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await second;
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
  });

  it('a past-cap list that empties and fills again starts afresh: nothing reads as late until a round has had its chance', async () => {
    const { organizations, list } = directory([org(1), org(2)]);
    const { check, capture, clock } = checking(organizations, { lanes: 2, mostOrganisations: 1 });
    await check.run();
    list.now = [org(1)];
    await check.run();
    clock.advanceBy(REACH_MS);
    await check.run();
    list.now = [org(1), org(3), org(4), org(5)];
    await check.run();
    expect(lines(capture, 'audit.anchor_check_behind')).toEqual([]);
  });

  it('a past-cap list that empties and fills again starts where it is told, once more', () => {
    const asked: number[] = [];
    const turns = createTurns(
      1,
      (orgIds) => orgIds,
      (count) => {
        asked.push(count);
        return 1;
      },
    );
    turns.begin([], [], [], orgs(2));
    turns.next();
    turns.begin([], [], [], []);
    expect(turns.pastCapStarts()).toBe(false);
    turns.begin([], [], [], orgs(3));
    expect(turns.pastCapStarts()).toBe(true);
    expect(asked).toEqual([2, 3]);
    expect(turns.next()).toBe(org(2));
  });

  it('slow chains and those past the cap take turn about at the one seat they share', () => {
    const turns = createTurns(
      2,
      (orgIds) => orgIds,
      () => 0,
    );
    const slow = orgs(2);
    for (const orgId of slow) turns.after(orgId, { ms: SLOW_AFTER_MS, again: false });
    turns.begin(slow, [], [], [org(50)]);
    expect(turns.next()).toBe(org(1));
    turns.ended(org(1));
    expect(turns.next()).toBe(org(50));
    turns.ended(org(50));
    expect(turns.next()).toBe(org(2));
  });

  it('past the cap, with no note of its last check, two failed turns running are the alarm, one is not', async () => {
    const { organizations } = directory(orgs(2));
    let down = false;
    const verify: OrganisationChains['verify'] = (orgId, anchor) =>
      down && orgId === org(2)
        ? Promise.reject(new Error('connect ECONNREFUSED'))
        : organizations.verify(orgId, anchor);
    const { check, capture, clock } = checking({ ...organizations, verify }, { lanes: 2, mostOrganisations: 1 });
    clock.advanceBy(STALE_MS);
    await check.run();
    down = true;
    await check.run();
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    await check.run();
    expect(lines(capture, 'audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'unchecked', firstFew: [org(2)] }),
    ]);
  });

  it('#6 a run cut off in the middle, then full runs, ends the round: the lateness clock goes back', () => {
    const turns = createTurns(
      1,
      (orgIds) => orgIds,
      () => 1,
    );
    const past = orgs(5);
    turns.begin([], [], [], past);
    expect(turns.pastCapStarts()).toBe(true);
    turns.next();
    turns.next();
    turns.next();
    turns.begin([], [], [], past);
    expect(turns.pastCapStarts()).toBe(false);
    for (let taken = 0; taken < 5; taken += 1) turns.next();
    turns.begin([], [], [], past);
    expect(turns.pastCapStarts()).toBe(true);
  });

  it('#6 a list shrinking in the middle of a round does not start one', () => {
    const turns = createTurns(
      1,
      (orgIds) => orgIds,
      () => 3,
    );
    const past = orgs(5);
    turns.begin([], [], [], past);
    turns.next();
    turns.begin([], [], [], past.slice(0, 3));
    expect(turns.pastCapStarts()).toBe(false);
    turns.next();
    turns.next();
    turns.begin([], [], [], past.slice(0, 3));
    expect(turns.pastCapStarts()).toBe(true);
  });
});
