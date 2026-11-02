// The anchor check's bounded runs (4D2e E6): lanes side by side, a run's time, its
// writes along the way, and whose turn it is. Every order here is forced: a check
// that "takes long" is one held until the test lets it go.
import {
  type AnchorLog,
  type ChainReport,
  createAnchorLog,
  createMemoryAnchorStore,
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
import { lanesWithin, SLOW_AFTER_MS } from './anchor-turns.ts';

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

  it('stuck organisations hold everyone only for their first deadline: seen slow, they then keep to one lane', async () => {
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
    const { check, capture } = checking(organizations, { lanes: 4, runWithinMs: 2 * DEADLINE_MS + 1000 });
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
    expect(started.filter((orgId) => others.includes(orgId))).toEqual(others);
    expect(lines(capture, 'audit.anchor_check_done').at(-1)).toMatchObject({ unchecked: 8, anchored: 40, left: 0 });

    // The next round: one slow chain at a time, and the other three lanes straight through everyone else.
    started.length = 0;
    const second = check.run();
    await settled();
    expect(started.filter((orgId) => stuck.includes(orgId))).toEqual([stuck[0]]);
    expect(started.filter((orgId) => others.includes(orgId))).toEqual(others);
    await vi.advanceTimersByTimeAsync(2 * DEADLINE_MS + 1000);
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

  it('a new round waits for the slow chains of this one, even with all the quick ones done', async () => {
    vi.useFakeTimers();
    const all = orgs(4);
    const hanging = new Set([org(1), org(2)]);
    const { organizations, started, release } = directory(all, (orgId) => (hanging.has(orgId) ? undefined : ok(1n)));
    const { check } = checking(organizations, { lanes: 2, runWithinMs: SLOW_AFTER_MS * 2 });
    const asSlow = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    release(org(1));
    release(org(2));
    await asSlow;

    // Lane 0 on one slow chain to its end, lane 1 through the quick ones, with the other slow chain waiting.
    hanging.delete(org(2));
    const cut = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS * 2);
    await cut;
    release(org(1));
    await settled();

    hanging.clear();
    started.length = 0;
    await check.run();
    expect(started).toEqual([org(1), org(2)]);
  });

  it('a lone lane leaves a slow chain until everyone else has had their turn', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    let hanging = true;
    const { organizations, started, release } = directory(all, (orgId) =>
      orgId === org(1) && hanging ? undefined : ok(1n),
    );
    const { check } = checking(organizations, { lanes: 1 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(SLOW_AFTER_MS);
    release(org(1));
    await first;
    hanging = false;
    started.length = 0;
    await check.run();
    expect(started).toEqual([org(2), org(3), org(1)]);
  });

  it('stops starting checks once twice its lanes hang on past their deadline: the connections are the API’s too', async () => {
    vi.useFakeTimers();
    const all = orgs(20);
    const { organizations, started, running, release } = directory(all, () => undefined);
    const { check, capture } = checking(organizations, { lanes: 2, runWithinMs: 100 * DEADLINE_MS });
    const run = check.run();
    await settled();
    expect(started).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    // The first two hang on past their deadline; two more are begun.
    expect(started).toHaveLength(4);
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await run;
    // Four held at once, and no more, and the rest are said to be waiting.
    expect(started).toHaveLength(4);
    expect(running.size).toBe(4);
    expect(lines(capture, 'audit.anchor_check_unfinished')).toEqual([expect.objectContaining({ left: 16 })]);
    expect(lines(capture, 'audit.anchor_check_done')).toEqual([expect.objectContaining({ left: 16 })]);
    for (const orgId of all) release(orgId);
    await settled();
    // Ended, the next run goes on from where it stopped.
    started.length = 0;
    const next = check.run();
    await settled();
    expect(started.slice(0, 2)).toEqual([org(5), org(6)]);
    await vi.advanceTimersByTimeAsync(10 * DEADLINE_MS);
    for (const orgId of all) release(orgId);
    await next;
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
    expect(lines(capture, 'audit.anchor_check_done').at(-1)).toMatchObject({ anchored: 4, left: 0 });
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
    expect(started).toEqual([org(1), org(2), org(3)]);
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
    expect(alarms().filter((line) => line.reason === 'unchecked')).toHaveLength(2);
  });

  it('an organisation still waiting at the bound is the alarm, by count, naming the first few; no hold, as for any chain unchecked', async () => {
    vi.useFakeTimers();
    const all = orgs(30);
    const { organizations, holds, release, running } = directory(all, () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    for (const orgId of running.keys()) release(orgId);
    await settled();

    clock.advanceBy(REACH_MS - 1);
    const under = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await under;
    expect(lines(capture, 'audit.integrity_failed')).toEqual([]);
    for (const orgId of running.keys()) release(orgId);
    await settled();

    clock.advanceBy(1);
    const past = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await past;
    const alarms = lines(capture, 'audit.integrity_failed');
    expect(alarms).toHaveLength(1);
    expect(alarms[0]).toMatchObject({
      level: 'error',
      chain: 'organisation',
      check: 'anchor',
      reason: 'unreached',
      // Of 30: the one cut off each run has had its turn, and goes again.
      organisations: 29,
    });
    expect(alarms[0]?.firstFew as string[]).toHaveLength(20);
    expect((alarms[0]?.firstFew as string[])[0]).toBe(org(2));
    expect(holds.filter(([, failure]) => failure !== undefined)).toEqual([]);
  });

  it('an organisation’s wait for its turn counts from when it was first seen, as a new one can’t have waited longer', async () => {
    vi.useFakeTimers();
    const all = orgs(3);
    const { organizations, list, release, running } = directory(all, () => undefined);
    const { check, capture, clock } = checking(organizations, { lanes: 1, runWithinMs: 1000 });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await first;
    for (const orgId of running.keys()) release(orgId);
    await settled();
    clock.advanceBy(REACH_MS - 1000);
    list.now = [...all, org(4)];
    const second = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await second;
    for (const orgId of running.keys()) release(orgId);
    await settled();
    clock.advanceBy(1000);
    const third = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(1000);
    await third;
    const alarm = lines(capture, 'audit.integrity_failed').at(-1);
    expect(alarm?.organisations).toBe(2);
    expect(alarm?.firstFew).toEqual([org(2), org(3)]);
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
