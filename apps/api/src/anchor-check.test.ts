import {
  type AnchorStore,
  type ChainReport,
  ChainStoreError,
  createMemoryAnchorStore,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, type KeyMaterial, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { FixedClock, LogCapture } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type AnchorCheck, type CheckedChain, createAnchorCheck, scheduleAnchorCheck } from './anchor-check.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ) as unknown as KeyMaterial,
);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const AT = new Date('2026-09-19T09:00:00.000Z');
const STALE_MS = 900_000;

const ok = (seq: bigint, fill = Number(seq)): ChainReport => ({ ok: true, seq, hash: Buffer.alloc(32, fill) });
const unreachable = (): Error => new Error('connect ECONNREFUSED');
const refused = (code: string): Error => Object.assign(new Error('the database refused the check'), { code });

/** A chain whose check gives the reports in turn (the last one again once they run out), and records the anchors it was given. */
function chainGiving(reports: readonly (ChainReport | Error)[], chain: CheckedChain['chain'] = { kind: 'platform' }) {
  const given: unknown[] = [];
  let turn = 0;
  const checked: CheckedChain = {
    chain,
    verify: (anchor) => {
      given.push(anchor === undefined ? undefined : { seq: anchor.seq, hash: anchor.hash });
      const report = reports[Math.min(turn, reports.length - 1)];
      turn += 1;
      if (report === undefined) throw new Error('The test gave no reports');
      return report instanceof Error ? Promise.reject(report) : Promise.resolve(report);
    },
  };
  return { checked, given };
}

function checking(chains: readonly CheckedChain[], anchors: AnchorStore = createMemoryAnchorStore()) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  const clock = new FixedClock(AT);
  const check = createAnchorCheck({ chains, keys, clock, logger, staleAfterMs: STALE_MS, anchors });
  /** Each chain's lines, without the run's closing line. */
  const events = () =>
    capture
      .lines()
      .filter((line) => String(line.event).startsWith('audit.') && line.event !== 'audit.anchor_check_done')
      .map(({ level, event, chain, check: kind, reason, seq, anchorSeq, headHash, keyVersion, orgId }) => ({
        level,
        event,
        chain,
        ...(kind === undefined ? {} : { check: kind }),
        ...(reason === undefined ? {} : { reason }),
        ...(seq === undefined ? {} : { seq }),
        ...(anchorSeq === undefined ? {} : { anchorSeq }),
        ...(headHash === undefined ? {} : { headHash }),
        ...(keyVersion === undefined ? {} : { keyVersion }),
        ...(orgId === undefined ? {} : { orgId }),
      }));
  const done = () =>
    capture
      .lines()
      .filter((line) => line.event === 'audit.anchor_check_done')
      .map(({ level, chains: count, anchored, unchanged, failed, unchecked }) => ({
        level,
        chains: count,
        anchored,
        unchanged,
        failed,
        unchecked,
      }));
  return { check, anchors, events, done, capture, clock };
}

const alarm = (reason: string, more: Record<string, string> = {}) => ({
  level: 'error',
  event: 'audit.integrity_failed',
  chain: 'platform',
  check: 'anchor',
  reason,
  ...more,
});
const warning = { level: 'warn', event: 'audit.anchor_check_failed', chain: 'platform' };

describe('the anchor check (ADR-012 §2, SEC-DB-11)', () => {
  it('anchors a chain that checks out, signed, and logs its place, hash and key version', async () => {
    const { checked, given } = chainGiving([ok(3n)]);
    const { check, anchors, events } = checking([checked]);
    await check.run();

    expect(given).toEqual([undefined]);
    expect(events()).toEqual([
      {
        level: 'info',
        event: 'audit.anchored',
        chain: 'platform',
        seq: '3',
        headHash: Buffer.alloc(32, 3).toString('hex'),
        keyVersion: 1,
      },
    ]);
    expect(anchors.latest({ kind: 'platform' })).toMatchObject({ chain: 'platform', seq: 3n, at: AT, keyVersion: 1 });
  });

  it('checks each next run against the last anchor, and anchors again only when the chain has moved on', async () => {
    const { checked, given } = chainGiving([ok(3n), ok(3n), ok(5n)]);
    const { check, events } = checking([checked]);
    await check.run();
    await check.run();
    await check.run();

    expect(given).toEqual([undefined, { seq: 3n, hash: Buffer.alloc(32, 3) }, { seq: 3n, hash: Buffer.alloc(32, 3) }]);
    expect(events().map((line) => line.seq)).toEqual(['3', '5']);
  });

  it('raises the integrity alarm for a chain that fails, and keeps its last good anchor, so the alarm repeats', async () => {
    const failing: ChainReport = { ok: false, problem: { reason: 'anchor', seq: 3n } };
    const { checked, given } = chainGiving([ok(3n), failing, failing]);
    const { check, events } = checking([checked]);
    await check.run();
    await check.run();
    await check.run();

    expect(events().slice(1)).toEqual([
      alarm('anchor', { seq: '3', anchorSeq: '3' }),
      alarm('anchor', { seq: '3', anchorSeq: '3' }),
    ]);
    expect(given.slice(1)).toEqual([
      { seq: 3n, hash: Buffer.alloc(32, 3) },
      { seq: 3n, hash: Buffer.alloc(32, 3) },
    ]);
  });

  it('raises the alarm for a chain never anchored that fails, with no anchor to name', async () => {
    const { checked } = chainGiving([{ ok: false, problem: { reason: 'mac', seq: 2n } }]);
    const { check, events } = checking([checked]);
    await check.run();

    expect(events()).toEqual([alarm('mac', { seq: '2' })]);
  });

  it('raises the alarm for a store that broke its contract, which a hostile database can cause', async () => {
    const { checked } = chainGiving([new ChainStoreError('it gave an event past the head it was asked to read up to')]);
    const { check, events } = checking([checked]);
    await check.run();

    expect(events()).toEqual([alarm('store')]);
  });

  it.each([
    ['a right taken away', '42501'],
    ['a table gone', '42P01'],
    ['a column gone', '42703'],
  ])('raises the alarm at once for a database changed so the check is refused: %s', async (_, code) => {
    const { checked } = chainGiving([refused(code)]);
    const { check, events } = checking([checked]);
    await check.run();

    expect(events()).toEqual([alarm('store')]);
  });

  it('warns, without the alarm, when the check cannot run at all, for any other reason', async () => {
    const { checked } = chainGiving([unreachable(), refused('57P01')]);
    const { check, events, capture } = checking([checked]);
    await check.run();
    await check.run();

    expect(events()).toEqual([warning, warning]);
    expect(capture.lines().find((line) => line.event === 'audit.anchor_check_failed')?.err).toEqual(
      expect.objectContaining({ message: 'connect ECONNREFUSED' }),
    );
  });

  it('raises the alarm once a chain has gone unchecked a whole stale period since the process began', async () => {
    const { checked } = chainGiving([unreachable()]);
    const { check, events, clock } = checking([checked]);
    await check.run();
    clock.advanceBy(STALE_MS - 1);
    await check.run();
    clock.advanceBy(1);
    await check.run();
    await check.run();

    expect(events()).toEqual([warning, warning, warning, alarm('unchecked'), warning, alarm('unchecked')]);
  });

  it('counts the stale period from the last completed check, and names the anchor it holds', async () => {
    const { checked } = chainGiving([ok(3n), unreachable()]);
    const { check, events, clock } = checking([checked]);
    clock.advanceBy(STALE_MS);
    await check.run();
    clock.advanceBy(STALE_MS - 1);
    await check.run();
    clock.advanceBy(1);
    await check.run();

    expect(events().slice(1)).toEqual([warning, warning, alarm('unchecked', { anchorSeq: '3' })]);
  });

  it("counts each chain's stale period on its own: one organisation's checks don't vouch for another's", async () => {
    const fine = chainGiving([ok(2n)], { kind: 'organisation', orgId: ORG });
    const failing = chainGiving([unreachable()], { kind: 'organisation', orgId: OTHER_ORG });
    const { check, events, clock } = checking([fine.checked, failing.checked]);
    await check.run();
    clock.advanceBy(STALE_MS);
    await check.run();

    expect(events().filter((line) => line.event === 'audit.integrity_failed')).toEqual([
      { ...alarm('unchecked'), chain: 'organisation', orgId: OTHER_ORG },
    ]);
  });

  it.each([
    ['wound back below it', ok(2n)],
    ['at its place with another hash', ok(3n, 9)],
  ])('raises the alarm, should a check pass a chain that is not what was anchored: %s', async (_, report) => {
    const { checked, given } = chainGiving([ok(3n), report, ok(4n)]);
    const { check, anchors, events } = checking([checked]);
    await check.run();
    await check.run();

    expect(events().slice(1)).toEqual([alarm('anchor', { seq: '3', anchorSeq: '3' })]);
    expect(anchors.latest({ kind: 'platform' })).toMatchObject({ seq: 3n, hash: Buffer.alloc(32, 3) });
    await check.run();
    expect(given.at(-1)).toEqual({ seq: 3n, hash: Buffer.alloc(32, 3) });
  });

  it("checks every chain, one's failure not stopping the next, and names an organisation's on its line", async () => {
    const broken = chainGiving([unreachable()]);
    const org = chainGiving([ok(2n)], { kind: 'organisation', orgId: ORG });
    const { check, events } = checking([broken.checked, org.checked]);
    await check.run();

    expect(events()).toEqual([
      warning,
      {
        level: 'info',
        event: 'audit.anchored',
        chain: 'organisation',
        seq: '2',
        headHash: Buffer.alloc(32, 2).toString('hex'),
        keyVersion: 1,
        orgId: ORG,
      },
    ]);
  });

  it('ends every run with one line counting what each chain came to, so a check that has stopped shows', async () => {
    const moving = chainGiving([ok(1n), ok(2n)], { kind: 'organisation', orgId: ORG });
    const still = chainGiving([ok(1n)], { kind: 'organisation', orgId: OTHER_ORG });
    const failing = chainGiving([ok(1n), { ok: false, problem: { reason: 'link', seq: 1n } }]);
    const { check, done } = checking([moving.checked, still.checked, failing.checked]);
    await check.run();
    await check.run();

    expect(done()).toEqual([
      { level: 'info', chains: 3, anchored: 3, unchanged: 0, failed: 0, unchecked: 0 },
      { level: 'info', chains: 3, anchored: 1, unchanged: 1, failed: 1, unchecked: 0 },
    ]);
  });

  it('logs a run with no chains to check too', async () => {
    const { check, done } = checking([]);
    await check.run();

    expect(done()).toEqual([{ level: 'info', chains: 0, anchored: 0, unchanged: 0, failed: 0, unchecked: 0 }]);
  });

  it('contains a check that crashes: logs it, counts it unchecked, and goes on to the next chain', async () => {
    const memory = createMemoryAnchorStore();
    const crashing: AnchorStore = {
      latest: (chain) => {
        if (chain.kind === 'platform') throw new Error('the anchor store fell over');
        return memory.latest(chain);
      },
      keep: (anchor) => {
        memory.keep(anchor);
      },
    };
    const platform = chainGiving([ok(1n)]);
    const org = chainGiving([ok(2n)], { kind: 'organisation', orgId: ORG });
    const { check, events, done, capture } = checking([platform.checked, org.checked], crashing);
    await expect(check.run()).resolves.toBeUndefined();

    expect(events().map((line) => line.event)).toEqual(['audit.anchor_check_crashed', 'audit.anchored']);
    const crashed = capture.lines().find((line) => line.event === 'audit.anchor_check_crashed');
    expect(crashed).toMatchObject({ level: 'error', chain: 'platform' });
    expect(crashed?.err).toEqual(expect.objectContaining({ message: 'the anchor store fell over' }));
    expect(done()).toEqual([{ level: 'info', chains: 2, anchored: 1, unchanged: 0, failed: 0, unchecked: 1 }]);
  });
});

describe('the anchor check schedule', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** A check that counts its runs, each taking as long as the test says. */
  function counting(runMs = 0): AnchorCheck & { runs: number } {
    const check = {
      runs: 0,
      run: async () => {
        check.runs += 1;
        if (runMs > 0) await new Promise((resolve) => setTimeout(resolve, runMs));
      },
    };
    return check;
  }

  it('runs at once, then again after each interval', async () => {
    vi.useFakeTimers();
    const check = counting();
    const schedule = scheduleAnchorCheck(check, 60_000);
    await vi.advanceTimersByTimeAsync(0);
    expect(check.runs).toBe(1);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(check.runs).toBe(2);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(check.runs).toBe(3);
    await schedule.stop();
  });

  it('waits a whole interval after a run ends, so a slow run never overlaps the next', async () => {
    vi.useFakeTimers();
    const check = counting(90_000);
    const schedule = scheduleAnchorCheck(check, 60_000);
    await vi.advanceTimersByTimeAsync(149_999);
    expect(check.runs).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(check.runs).toBe(2);
    await vi.advanceTimersByTimeAsync(90_000);
    await schedule.stop();
  });

  it('stops between runs: the next one never comes', async () => {
    vi.useFakeTimers();
    const check = counting();
    const schedule = scheduleAnchorCheck(check, 60_000);
    await vi.advanceTimersByTimeAsync(30_000);
    await schedule.stop();
    await vi.advanceTimersByTimeAsync(600_000);

    expect(check.runs).toBe(1);
  });

  it('stops: waits for a run in flight, then runs no more', async () => {
    vi.useFakeTimers();
    const check = counting(5_000);
    const schedule = scheduleAnchorCheck(check, 60_000);
    let stopped = false;
    const stopping = schedule.stop().then(() => {
      stopped = true;
    });
    await vi.advanceTimersByTimeAsync(4_999);
    expect(stopped).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await stopping;

    expect(stopped).toBe(true);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(check.runs).toBe(1);
  });
});
