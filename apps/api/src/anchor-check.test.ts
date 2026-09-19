import { type ChainReport, ChainStoreError, createMemoryAnchorStore } from '@agentx/platform/audit-chain';
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
const AT = new Date('2026-09-19T09:00:00.000Z');

const ok = (seq: bigint): ChainReport => ({ ok: true, seq, hash: Buffer.alloc(32, Number(seq)) });

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

function checking(chains: readonly CheckedChain[]) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  const anchors = createMemoryAnchorStore();
  const check = createAnchorCheck({ chains, keys, clock: new FixedClock(AT), logger, anchors });
  const events = () =>
    capture
      .lines()
      .filter((line) => String(line.event).startsWith('audit.'))
      .map(({ level, event, chain, check: kind, reason, seq, headHash, orgId }) => ({
        level,
        event,
        chain,
        ...(kind === undefined ? {} : { check: kind }),
        ...(reason === undefined ? {} : { reason }),
        ...(seq === undefined ? {} : { seq }),
        ...(headHash === undefined ? {} : { headHash }),
        ...(orgId === undefined ? {} : { orgId }),
      }));
  return { check, anchors, events, capture };
}

describe('the anchor check (ADR-012 §2, SEC-DB-11)', () => {
  it('anchors a chain that checks out, signed, and logs its place and hash', async () => {
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
      {
        level: 'error',
        event: 'audit.integrity_failed',
        chain: 'platform',
        check: 'anchor',
        reason: 'anchor',
        seq: '3',
      },
      {
        level: 'error',
        event: 'audit.integrity_failed',
        chain: 'platform',
        check: 'anchor',
        reason: 'anchor',
        seq: '3',
      },
    ]);
    expect(given.slice(1)).toEqual([
      { seq: 3n, hash: Buffer.alloc(32, 3) },
      { seq: 3n, hash: Buffer.alloc(32, 3) },
    ]);
  });

  it('raises the alarm for a store that broke its contract, which a hostile database can cause', async () => {
    const { checked } = chainGiving([new ChainStoreError('it gave an event past the head it was asked to read up to')]);
    const { check, events } = checking([checked]);
    await check.run();

    expect(events()).toEqual([
      { level: 'error', event: 'audit.integrity_failed', chain: 'platform', check: 'anchor', reason: 'store' },
    ]);
  });

  it('warns, without the alarm, when the check cannot run at all', async () => {
    const { checked } = chainGiving([new Error('connect ECONNREFUSED')]);
    const { check, events, capture } = checking([checked]);
    await check.run();

    expect(events()).toEqual([{ level: 'warn', event: 'audit.anchor_check_failed', chain: 'platform' }]);
    expect(capture.lines().at(-1)?.err).toEqual(expect.objectContaining({ message: 'connect ECONNREFUSED' }));
  });

  it("checks every chain, one's failure not stopping the next, and names an organisation's on its line", async () => {
    const broken = chainGiving([new Error('connect ECONNREFUSED')]);
    const org = chainGiving([ok(2n)], { kind: 'organisation', orgId: ORG });
    const { check, events } = checking([broken.checked, org.checked]);
    await check.run();

    expect(events()).toEqual([
      { level: 'warn', event: 'audit.anchor_check_failed', chain: 'platform' },
      {
        level: 'info',
        event: 'audit.anchored',
        chain: 'organisation',
        seq: '2',
        headHash: Buffer.alloc(32, 2).toString('hex'),
        orgId: ORG,
      },
    ]);
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
