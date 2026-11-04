// The rotation inside the anchor check's run (4D2e E7): after the turns, within the lanes' share, one read at a time,
// its failures the integrity alarm and the hold as any check's. Every order here is forced: a read that "takes long" is
// one held until the test lets it go.
import {
  type ChainProblem,
  type ChainReport,
  type ChainStep,
  ChainStoreError,
  createAnchorLog,
  createMemoryAnchorStore,
  signAnchor,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createFakeWriteOnceStore, FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { gunzipSync } from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type AnchorCheckOptions, createAnchorCheck, type OrganisationChains } from './anchor-check.ts';
import { type RotatedChecks, slotOf } from './anchor-rotation.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
/** 09:00 UTC: slot 108 begins, so an organisation of that slot is due at the first run. */
const AT = new Date('2026-11-02T09:00:00.000Z');
const DEADLINE_MS = 120_000;

function orgInSlot(slot: number, nth = 0): string {
  let found = 0;
  for (let index = 0; ; index += 1) {
    const orgId = `0199a0f0-0000-7000-8000-${String(index).padStart(12, '0')}`;
    if (slotOf(orgId) === slot && found++ === nth) return orgId;
  }
}
const ok = (seq: bigint): ChainReport => ({ ok: true, seq, hash: Buffer.alloc(32, Number(seq)), macKeyVersion: 1 });
const settled = async (): Promise<void> => {
  for (let round = 0; round < 3000; round += 1) await Promise.resolve();
};

/** A directory whose chains all check out at `seq`, unless held; its holds kept. */
function directory(listed: readonly string[], seq = 10n) {
  const holds: [string, string | undefined][] = [];
  const held = new Map<string, () => void>();
  const hanging = new Set<string>();
  const organizations: OrganisationChains = {
    list: () => Promise.resolve(listed),
    recorded: () => Promise.resolve([]),
    verify: (orgId) =>
      hanging.has(orgId)
        ? new Promise((resolve) => {
            held.set(orgId, () => {
              resolve(ok(seq));
            });
          })
        : Promise.resolve(ok(seq)),
    hold: (orgId, failure) => {
      holds.push([orgId, failure]);
      return Promise.resolve();
    },
  };
  // Every turn tries a hold waiting, with no reason: only those with one are holds placed.
  const placed = () => holds.filter(([, failure]) => failure !== undefined);
  return { organizations, placed, held, hanging };
}

/** Rotation reads that pass, each kept, unless a test says otherwise. */
function rotationReads() {
  const calls: string[] = [];
  const answer: {
    count?: () => Promise<ChainProblem | undefined>;
    walk?: () => Promise<ChainStep>;
  } = {};
  const reads: RotatedChecks = {
    count: (orgId, after, upTo) => {
      calls.push(`count ${orgId} ${String(after)}-${String(upTo)}`);
      return answer.count?.() ?? Promise.resolve(undefined);
    },
    walkLast: (orgId, target) => {
      calls.push(`walk ${orgId}`);
      return answer.walk?.() ?? Promise.resolve({ ...ok(target.seq), to: target.seq });
    },
    passStep: (orgId, _cursor, target) => {
      calls.push(`pass ${orgId}`);
      return Promise.resolve({ ...ok(target.seq), to: target.seq });
    },
  };
  return { reads, calls, answer };
}

/** An anchors' log over the fake store, in epoch 3, at this clock: a process's, each call a new process's. */
const anchorLogOver = (fake: ReturnType<typeof createFakeWriteOnceStore>, clock: FixedClock) =>
  createAnchorLog({
    store: fake.store,
    keys,
    logger: testLogger(new LogCapture()),
    now: () => clock.now(),
    epoch: 3,
    alertAfterMs: 120_000,
  });

/**
 * The last process: it reads the store, anchors the organisation at 10 and writes it, three hours before this one
 * starts. The new process's log, the clock moved on.
 */
async function leftThreeHoursAgo(
  fake: ReturnType<typeof createFakeWriteOnceStore>,
  clock: FixedClock,
  orgId: string,
): Promise<ReturnType<typeof anchorLogOver>> {
  const last = anchorLogOver(fake, clock);
  await last.read();
  last.keep(
    signAnchor(
      keys,
      { kind: 'organisation', orgId },
      { seq: 10n, hash: Buffer.alloc(32, 10), macKeyVersion: 1 },
      clock.now(),
      3,
    ),
  );
  await last.flush();
  clock.advanceBy(3 * 3_600_000);
  return anchorLogOver(fake, clock);
}

function checking(organizations: OrganisationChains, more: Partial<AnchorCheckOptions> = {}) {
  const capture = new LogCapture();
  const clock = new FixedClock(AT);
  const check = createAnchorCheck({
    chains: [],
    organizations,
    keys,
    clock,
    logger: testLogger(capture),
    staleAfterMs: 900_000,
    reachWithinMs: 3_600_000,
    deadlineMs: DEADLINE_MS,
    shuffled: (orgIds) => orgIds,
    pastCapStart: () => 0,
    anchors: createMemoryAnchorStore(),
    ...more,
  });
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  return { check, capture, clock, lines };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('the rotation in a run (4D2e E7)', () => {
  it('runs after the turns, on the anchors they made, and says what it did before the run is done', async () => {
    const orgId = orgInSlot(108);
    const { organizations } = directory([orgId]);
    const { reads, calls } = rotationReads();
    const { check, capture } = checking(organizations, { rotation: reads });
    await check.run();

    expect(calls).toEqual([`count ${orgId} 0-10`, `walk ${orgId}`, `pass ${orgId}`]);
    expect(capture.lines().map((line) => line.event)).toEqual([
      'audit.anchored',
      'audit.anchor_rotation_done',
      'audit.anchor_check_done',
    ]);
  });

  it('has no rotation without its reads', async () => {
    const { organizations } = directory([orgInSlot(108)]);
    const { check, lines } = checking(organizations);
    await check.run();
    expect(lines('audit.anchor_rotation_done')).toEqual([]);
  });

  it('a chain the rotation finds failing is the integrity alarm, naming the read, and the organisation held', async () => {
    const orgId = orgInSlot(108);
    const { organizations, placed } = directory([orgId]);
    const { reads, answer } = rotationReads();
    answer.count = () => Promise.resolve({ reason: 'gap', seq: 1n });
    const { check, lines } = checking(organizations, { rotation: reads });
    await check.run();

    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({
        level: 'error',
        orgId,
        chain: 'organisation',
        check: 'count',
        reason: 'gap',
        seq: '1',
      }),
    ]);
    expect(placed()).toEqual([[orgId, 'gap']]);
  });

  it('a read the database refuses is the alarm too, as for any check: the store changed under it', async () => {
    const orgId = orgInSlot(108);
    const { organizations, placed } = directory([orgId]);
    const { reads, answer } = rotationReads();
    answer.walk = () => Promise.reject(new ChainStoreError('it gave more than asked'));
    const { check, lines } = checking(organizations, { rotation: reads });
    await check.run();
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ orgId, check: 'walk', reason: 'store' }),
    ]);
    expect(lines('audit.integrity_failed')[0]).not.toHaveProperty('seq');
    expect(placed()).toEqual([[orgId, 'store']]);

    const refused = directory([orgId]);
    const again = rotationReads();
    again.answer.count = () => Promise.reject(Object.assign(new Error('permission denied'), { code: '42501' }));
    const second = checking(refused.organizations, { rotation: again.reads });
    await second.check.run();
    expect(second.lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ orgId, check: 'count', reason: 'store' }),
    ]);
  });

  it('a read that fails otherwise is a warning naming the organisation and the read, and no hold', async () => {
    const orgId = orgInSlot(108);
    const { organizations, placed } = directory([orgId]);
    const { reads, answer } = rotationReads();
    answer.count = () => Promise.reject(new Error('the database is away'));
    const { check, lines } = checking(organizations, { rotation: reads });
    await check.run();

    expect(lines('audit.anchor_check_failed')).toEqual([
      expect.objectContaining({ level: 'warn', orgId, chain: 'organisation', check: 'count' }),
    ]);
    expect(lines('audit.integrity_failed')).toEqual([]);
    expect(placed()).toEqual([]);
  });

  it("waits for room in the lanes: a check past its deadline still holds its connection, and the rotation's read waits for it", async () => {
    vi.useFakeTimers();
    const [stuck, due] = [orgInSlot(5), orgInSlot(108)];
    const { organizations, held, hanging } = directory([due, stuck]);
    const { reads, calls } = rotationReads();
    const { check } = checking(organizations, { rotation: reads, lanes: 1 });
    // A first run anchors both.
    await check.run();
    calls.length = 0;
    hanging.add(stuck);

    const run = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    // The stuck one past its deadline, its connection still held: the one lane is full, and the rotation waits.
    expect(calls).toEqual([]);
    held.get(stuck)?.();
    await settled();
    await run;
    expect(calls).toEqual([`pass ${stuck}`]);
  });

  it('one read at a time across runs: one still running past its deadline keeps the next run from starting another', async () => {
    vi.useFakeTimers();
    const orgId = orgInSlot(108);
    const { organizations } = directory([orgId]);
    const { reads, answer, calls } = rotationReads();
    const { promise: holding, resolve: letGo } = Promise.withResolvers<ChainProblem | undefined>();
    answer.count = () => holding;
    const { check, clock, lines } = checking(organizations, { rotation: reads });
    const first = check.run();
    await settled();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await first;
    // The count past its deadline, then the pass's read refused while it still runs: no second connection.
    const notFinished = (index: number) =>
      String((lines('audit.anchor_check_failed')[index]?.err as { message?: unknown }).message);
    expect(lines('audit.anchor_check_failed')).toEqual([
      expect.objectContaining({ check: 'count' }),
      expect.objectContaining({ check: 'pass' }),
    ]);
    expect(notFinished(1)).toContain('has not finished');

    clock.advanceBy(300_000);
    await check.run();
    expect(lines('audit.anchor_check_failed')).toHaveLength(4);
    expect(notFinished(2)).toContain('has not finished');
    expect(calls).toEqual([`count ${orgId} 0-10`]);
    letGo(undefined);
  });

  it("writes a finished pass to the anchors' store, signed for its epoch", async () => {
    const orgId = orgInSlot(5);
    const { organizations } = directory([orgId]);
    const { reads } = rotationReads();
    const fake = createFakeWriteOnceStore();
    const clock = new FixedClock(AT);
    const durable = anchorLogOver(fake, clock);
    const { check } = checking(organizations, { rotation: reads, durable, anchors: durable, clock });
    await check.run();
    await check.finish();

    const written = [...fake.files.values()].flatMap((bytes) =>
      gunzipSync(bytes)
        .toString('utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line) as Record<string, unknown>),
    );
    expect(written.filter((line) => line.k === 'p')).toEqual([
      expect.objectContaining({ chain: `organisation:${orgId}`, seq: '10' }),
    ]);
    const restarted = anchorLogOver(fake, clock);
    await restarted.read();
    expect(restarted.lastPass({ kind: 'organisation', orgId })?.seq).toBe(10n);
  });

  it("a first run looks back to the store's newest file, where the last process left off", async () => {
    const inOutage = orgInSlot(80);
    const { organizations } = directory([inOutage]);
    const { reads, calls } = rotationReads();
    const fake = createFakeWriteOnceStore();
    const clock = new FixedClock(new Date(AT.getTime() - 3 * 3_600_000));
    // The last process: it writes and goes, three hours before this one starts.
    const restarted = await leftThreeHoursAgo(fake, clock, inOutage);
    const { check } = checking(organizations, { rotation: reads, durable: restarted, anchors: restarted, clock });
    await check.run();
    expect(calls.slice(0, 2)).toEqual([`count ${inOutage} 0-10`, `walk ${inOutage}`]);
  });

  it('takes where the last process left off before this one writes: a snapshot written mid-run moves nothing back', async () => {
    const inOutage = orgInSlot(80);
    const slow = orgInSlot(5);
    const { organizations, held, hanging } = directory([inOutage, slow]);
    hanging.add(slow);
    const { reads, calls } = rotationReads();
    const fake = createFakeWriteOnceStore();
    const clock = new FixedClock(new Date(AT.getTime() - 3 * 3_600_000));
    const restarted = await leftThreeHoursAgo(fake, clock, inOutage);
    const { check } = checking(organizations, {
      rotation: reads,
      durable: restarted,
      anchors: restarted,
      clock,
      writeEveryMs: 5,
    });
    const run = check.run();
    // While the slow organisation's check is held, this process writes a file of its own, dated now.
    const before = fake.files.size;
    await vi.waitUntil(() => fake.files.size > before, { timeout: 4000, interval: 2 });
    expect(restarted.lastFileAt()).toEqual(clock.now());
    held.get(slow)?.();
    await run;
    expect(calls.slice(0, 2)).toEqual([`count ${inOutage} 0-10`, `walk ${inOutage}`]);
  });

  it("keeps the store's first look, though this process writes before the rotation's first run, a run later", async () => {
    const inOutage = orgInSlot(80);
    const { organizations } = directory([inOutage]);
    let listFails = true;
    const listing: OrganisationChains = {
      ...organizations,
      list: () => (listFails ? Promise.reject(new Error('the list is away')) : organizations.list()),
    };
    const { reads, calls } = rotationReads();
    const fake = createFakeWriteOnceStore();
    const clock = new FixedClock(new Date(AT.getTime() - 3 * 3_600_000));
    const restarted = await leftThreeHoursAgo(fake, clock, inOutage);
    const { check } = checking(listing, {
      chains: [{ chain: { kind: 'platform' }, verify: () => Promise.resolve(ok(5n)) }],
      rotation: reads,
      durable: restarted,
      anchors: restarted,
      clock,
    });
    // The first run: the list unread, so no rotation; the platform chain anchored and written, dated now.
    await check.run();
    expect(calls).toEqual([]);
    expect(restarted.lastFileAt()).toEqual(clock.now());
    listFails = false;
    clock.advanceBy(300_000);
    await check.run();
    expect(calls.slice(0, 2)).toEqual([`count ${inOutage} 0-10`, `walk ${inOutage}`]);
  });

  it("runs no rotation while the store is unread: an outage's days wait for where the last process left off", async () => {
    const inOutage = orgInSlot(80);
    const { organizations } = directory([inOutage]);
    const { reads, calls } = rotationReads();
    const fake = createFakeWriteOnceStore();
    const clock = new FixedClock(new Date(AT.getTime() - 3 * 3_600_000));
    const restarted = await leftThreeHoursAgo(fake, clock, inOutage);
    fake.instead.list = () => Promise.reject(new Error('the store is away'));
    const { check, lines } = checking(organizations, {
      rotation: reads,
      durable: restarted,
      anchors: restarted,
      clock,
    });
    // The store unread, the list read: no rotation, so no first look back from now.
    await check.run();
    expect(restarted.state()).toBe('unreadable');
    expect(calls).toEqual([]);
    expect(lines('audit.anchor_rotation_done')).toEqual([]);
    delete fake.instead.list;
    clock.advanceBy(300_000);
    await check.run();
    expect(calls.slice(0, 2)).toEqual([`count ${inOutage} 0-10`, `walk ${inOutage}`]);
  });

  it('tells the rotation the process is stopping, so a pass cut short then is no capacity warning', async () => {
    const [due, slow] = [orgInSlot(108), orgInSlot(5)];
    const { organizations, held, hanging } = directory([due, slow]);
    const { reads } = rotationReads();
    const { check, lines } = checking(organizations, { rotation: reads });
    // A first run anchors both, so the next has a pass to take.
    await check.run();
    hanging.add(slow);
    const stopping = new AbortController();
    const run = check.run(stopping.signal);
    await settled();
    stopping.abort();
    held.get(slow)?.();
    await run;
    expect(lines('audit.full_pass_behind')).toEqual([]);

    // Cut short by the run's own time instead: said.
    const timed = checking(organizations, { rotation: reads, runWithinMs: 1_000 });
    // The slow one still held: the run's second is up while it waits, and the pass gets none of its time.
    await timed.check.run();
    held.get(slow)?.();
    expect(timed.lines('audit.full_pass_behind')).toEqual([expect.objectContaining({ by: 'run' })]);
  });
});
