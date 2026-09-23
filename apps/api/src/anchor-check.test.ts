import {
  type AnchorStore,
  type ChainReport,
  ChainStoreError,
  createMemoryAnchorStore,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { FixedClock, LogCapture } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type AnchorCheck,
  type CheckedChain,
  createAnchorCheck,
  type OrganisationChains,
  scheduleAnchorCheck,
} from './anchor-check.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const AT = new Date('2026-09-19T09:00:00.000Z');
const STALE_MS = 900_000;
const DEADLINE_MS = 120_000;

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

function checking(
  chains: readonly CheckedChain[],
  anchors: AnchorStore = createMemoryAnchorStore(),
  organizations?: OrganisationChains,
) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  const clock = new FixedClock(AT);
  const check = createAnchorCheck({
    chains,
    keys,
    clock,
    logger,
    staleAfterMs: STALE_MS,
    deadlineMs: DEADLINE_MS,
    anchors,
    ...(organizations === undefined ? {} : { organizations }),
  });
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

describe('the anchor check when a check does not finish', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** A chain whose check never ends, and how often it was started. */
  function hanging(chain: CheckedChain['chain'] = { kind: 'platform' }) {
    const started = { count: 0 };
    const checked: CheckedChain = {
      chain,
      verify: () => {
        started.count += 1;
        return new Promise<never>(() => undefined);
      },
    };
    return { checked, started };
  }

  it('counts a check past its deadline as not completed, and never starts a second on the same chain meanwhile', async () => {
    vi.useFakeTimers();
    const { checked, started } = hanging();
    const { check, events, done, capture, clock } = checking([checked]);
    const run = check.run();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS - 1);
    expect(done()).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await run;

    expect(events()).toEqual([warning]);
    expect(capture.lines().find((line) => line.event === 'audit.anchor_check_failed')?.err).toEqual(
      expect.objectContaining({ message: `the check did not finish within ${String(DEADLINE_MS)} ms` }),
    );
    clock.advanceBy(STALE_MS);
    await check.run();
    expect(events()).toEqual([warning, warning, alarm('unchecked')]);
    expect(
      capture
        .lines()
        .filter((line) => line.event === 'audit.anchor_check_failed')
        .at(-1)?.err,
    ).toEqual(expect.objectContaining({ message: 'the last check of this chain has not finished' }));
    expect(started.count).toBe(1);
  });

  it.each([
    [
      'with a report',
      (settle: { resolve: (report: ChainReport) => void }) => {
        settle.resolve(ok(1n));
      },
    ],
    [
      'with an error, which goes unhandled nowhere',
      (settle: { reject: (error: Error) => void }) => {
        settle.reject(new Error('connection lost'));
      },
    ],
  ])('checks the chain again once the late check has ended %s', async (_, end) => {
    vi.useFakeTimers();
    const settle: { resolve: (report: ChainReport) => void; reject: (error: Error) => void } = {
      resolve: () => undefined,
      reject: () => undefined,
    };
    let turn = 0;
    const late: CheckedChain = {
      chain: { kind: 'platform' },
      verify: () => {
        turn += 1;
        return turn === 1
          ? new Promise<ChainReport>((resolve, reject) => {
              Object.assign(settle, { resolve, reject });
            })
          : Promise.resolve(ok(2n));
      },
    };
    const { check, events } = checking([late]);
    const run = check.run();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    await run;
    end(settle);
    await vi.advanceTimersByTimeAsync(0);
    await check.run();

    expect(events().map((line) => line.event)).toEqual(['audit.anchor_check_failed', 'audit.anchored']);
    expect(turn).toBe(2);
    // Each check's deadline is cleared once it ends.
    expect(vi.getTimerCount()).toBe(0);
  });

  it('leaves nothing listening on the stop signal once a check ends, however many runs share it', async () => {
    const listening = new Set<unknown>();
    const signal = {
      aborted: false,
      addEventListener: (_type: string, listener: unknown) => listening.add(listener),
      removeEventListener: (_type: string, listener: unknown) => listening.delete(listener),
    } as unknown as AbortSignal;
    const { checked } = chainGiving([ok(1n)]);
    const { check } = checking([checked]);
    await check.run(signal);
    await check.run(signal);

    expect(listening.size).toBe(0);
  });

  it('ends at once when stopped mid-check, raising nothing, and checks no more chains', async () => {
    const { checked } = hanging();
    const next = chainGiving([ok(1n)], { kind: 'organisation', orgId: ORG });
    const { check, events, done } = checking([checked, next.checked]);
    const stopping = new AbortController();
    const run = check.run(stopping.signal);
    stopping.abort();
    await run;

    expect(events()).toEqual([]);
    expect(next.given).toEqual([]);
    expect(done()).toEqual([{ level: 'info', chains: 1, anchored: 0, unchanged: 0, failed: 0, unchecked: 1 }]);
  });

  it('checks nothing in a run stopped before it began', async () => {
    const { checked, started } = hanging();
    const { check, done } = checking([checked]);
    await check.run(AbortSignal.abort());

    expect(started.count).toBe(0);
    expect(done()).toEqual([{ level: 'info', chains: 0, anchored: 0, unchanged: 0, failed: 0, unchecked: 0 }]);
  });
});

describe("the organisations' chains, from the directory's list at each run (B1d-2)", () => {
  /**
   * A directory whose list gives the answers in turn (the last one again once
   * they run out), and chains that check out at seq 1, or as `reports` says.
   */
  function directory(
    lists: readonly (readonly unknown[] | Error)[],
    reports: Record<string, ChainReport> = {},
    recorded: readonly unknown[] | Error = [],
  ) {
    const verified: string[] = [];
    let turn = 0;
    const organizations: OrganisationChains = {
      list: () => {
        const answer = lists[Math.min(turn, lists.length - 1)];
        turn += 1;
        if (answer === undefined) throw new Error('The test gave no lists');
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer as string[]);
      },
      recorded: () => (recorded instanceof Error ? Promise.reject(recorded) : Promise.resolve(recorded as string[])),
      verify: (orgId) => {
        verified.push(orgId);
        return Promise.resolve(reports[orgId] ?? ok(1n));
      },
      hold: () => Promise.resolve(),
    };
    return { organizations, verified };
  }

  const anchored = (orgId: string) => ({
    level: 'info',
    event: 'audit.anchored',
    chain: 'organisation',
    seq: '1',
    headHash: Buffer.alloc(32, 1).toString('hex'),
    keyVersion: 1,
    orgId,
  });
  const orgAlarm = (reason: string, orgId: string, more: Record<string, string> = {}) => ({
    level: 'error',
    event: 'audit.integrity_failed',
    chain: 'organisation',
    check: 'anchor',
    reason,
    ...more,
    orgId,
  });

  it('checks each listed organisation after the platform, anchoring each on its own line, and counts them all', async () => {
    const platform = chainGiving([ok(3n)]);
    const { organizations, verified } = directory([[ORG, OTHER_ORG]]);
    const { check, events, done } = checking([platform.checked], undefined, organizations);
    await check.run();

    expect(verified).toEqual([ORG, OTHER_ORG]);
    expect(events().slice(1)).toEqual([anchored(ORG), anchored(OTHER_ORG)]);
    expect(done()).toEqual([{ level: 'info', chains: 3, anchored: 3, unchanged: 0, failed: 0, unchecked: 0 }]);
  });

  it('raises the alarm for an organisation that fails, and goes on to the next', async () => {
    const { organizations, verified } = directory([[ORG, OTHER_ORG]], {
      [ORG]: { ok: false, problem: { reason: 'hash', seq: 2n } },
    });
    const { check, events } = checking([], undefined, organizations);
    await check.run();

    expect(verified).toEqual([ORG, OTHER_ORG]);
    expect(events()).toEqual([orgAlarm('hash', ORG, { seq: '2' }), anchored(OTHER_ORG)]);
  });

  it('reads the list afresh each run, so an organisation added since is checked', async () => {
    const { organizations, verified } = directory([[ORG], [ORG, OTHER_ORG]]);
    const { check } = checking([], undefined, organizations);
    await check.run();
    await check.run();

    expect(verified).toEqual([ORG, ORG, OTHER_ORG]);
  });

  it('raises the alarm, every run, for an organisation seen listed that has left the list, naming its anchor', async () => {
    const { organizations, verified } = directory([[ORG, OTHER_ORG], [OTHER_ORG]]);
    const { check, events, done } = checking([], undefined, organizations);
    await check.run();
    await check.run();
    await check.run();

    expect(verified).toEqual([ORG, OTHER_ORG, OTHER_ORG, OTHER_ORG]);
    expect(events().slice(2)).toEqual([
      orgAlarm('unlisted', ORG, { anchorSeq: '1' }),
      orgAlarm('unlisted', ORG, { anchorSeq: '1' }),
    ]);
    expect(done().at(-1)).toEqual({ level: 'info', chains: 2, anchored: 0, unchanged: 1, failed: 1, unchecked: 0 });
  });

  it('takes the list’s IDs in any case as the same organisation', async () => {
    const { organizations, verified } = directory([[ORG.toUpperCase()], [ORG]]);
    const { check, events } = checking([], undefined, organizations);
    await check.run();
    await check.run();

    expect(verified).toEqual([ORG, ORG]);
    expect(events()).toEqual([anchored(ORG)]);
  });

  it('raises the alarm for a list the database refuses, and each organisation seen goes stale as unchecked', async () => {
    const { organizations } = directory([[ORG], refused('42501')]);
    const { check, events, done, clock } = checking([], undefined, organizations);
    await check.run();
    await check.run();
    const listAlarm = {
      level: 'error',
      event: 'audit.integrity_failed',
      chain: 'organisation',
      check: 'anchor',
      reason: 'list',
    };
    expect(events().slice(1)).toEqual([listAlarm]);
    expect(done().at(-1)).toEqual({ level: 'info', chains: 1, anchored: 0, unchanged: 0, failed: 0, unchecked: 1 });

    clock.advanceBy(STALE_MS);
    await check.run();
    expect(events().slice(2)).toEqual([listAlarm, orgAlarm('unchecked', ORG, { anchorSeq: '1' })]);
  });

  it('warns, without the alarm, for a list that cannot be read for any other reason, until the list and each organisation seen go stale', async () => {
    const { organizations } = directory([[ORG], unreachable()]);
    const { check, events, clock } = checking([], undefined, organizations);
    await check.run();
    clock.advanceBy(STALE_MS - 1);
    await check.run();
    const listWarning = { level: 'warn', event: 'audit.anchor_check_failed', chain: 'organisation', check: 'list' };
    expect(events().slice(1)).toEqual([listWarning]);

    clock.advanceBy(1);
    await check.run();
    expect(events().slice(2)).toEqual([
      listWarning,
      { level: 'error', event: 'audit.integrity_failed', chain: 'organisation', check: 'anchor', reason: 'list' },
      orgAlarm('unchecked', ORG, { anchorSeq: '1' }),
    ]);
  });

  const listAlarm = {
    level: 'error',
    event: 'audit.integrity_failed',
    chain: 'organisation',
    check: 'anchor',
    reason: 'list',
  };

  it('raises the alarm, from the first run, for an organisation the platform chain records but the list leaves out', async () => {
    const { organizations, verified } = directory([[OTHER_ORG]], {}, [ORG, OTHER_ORG]);
    const { check, events } = checking([], undefined, organizations);
    await check.run();

    expect(verified).toEqual([OTHER_ORG]);
    expect(events()).toEqual([orgAlarm('unlisted', ORG), anchored(OTHER_ORG)]);
  });

  it('reads the record of created organisations before the list, and the list only once the record is in', async () => {
    const reads: string[] = [];
    const organizations: OrganisationChains = {
      hold: () => Promise.resolve(),
      recorded: () => {
        reads.push('recorded');
        return Promise.resolve([ORG]);
      },
      list: () => {
        reads.push('list');
        return Promise.resolve([ORG]);
      },
      verify: () => Promise.resolve(ok(1n)),
    };
    const { check } = checking([], undefined, organizations);
    await check.run();

    expect(reads).toEqual(['recorded', 'list']);
  });

  it('reads no list when the record fails, so nothing is left reading behind it', async () => {
    let lists = 0;
    const organizations: OrganisationChains = {
      hold: () => Promise.resolve(),
      recorded: () => Promise.reject(unreachable()),
      list: () => {
        lists += 1;
        return Promise.resolve([ORG]);
      },
      verify: () => Promise.resolve(ok(1n)),
    };
    const { check, events } = checking([], undefined, organizations);
    await check.run();

    expect(lists).toBe(0);
    expect(events()).toEqual([
      { level: 'warn', event: 'audit.anchor_check_failed', chain: 'organisation', check: 'list' },
    ]);
  });

  it('takes a list of the most organisations it allows', async () => {
    const { organizations, verified } = directory([Array.from({ length: 10_000 }, () => ORG)]);
    const { check } = checking([], undefined, organizations);
    await check.run();

    expect(verified).toEqual([ORG]);
  });

  it('checks no more organisations once stopped during one’s check', async () => {
    const stopping = new AbortController();
    const verified: string[] = [];
    const organizations: OrganisationChains = {
      hold: () => Promise.resolve(),
      recorded: () => Promise.resolve([]),
      list: () => Promise.resolve([ORG, OTHER_ORG]),
      verify: (orgId) => {
        verified.push(orgId);
        stopping.abort();
        return Promise.resolve(ok(1n));
      },
    };
    const { check } = checking([], undefined, organizations);
    await check.run(stopping.signal);

    expect(verified).toEqual([ORG]);
  });

  it('counts nothing for the organisations it knows when stopped while the list is read', async () => {
    let hang = false;
    const organizations: OrganisationChains = {
      hold: () => Promise.resolve(),
      recorded: () => Promise.resolve([]),
      list: () => (hang ? new Promise<never>(() => undefined) : Promise.resolve([ORG])),
      verify: () => Promise.resolve(ok(1n)),
    };
    const { check, done } = checking([], undefined, organizations);
    await check.run();
    hang = true;
    const stopping = new AbortController();
    const run = check.run(stopping.signal);
    stopping.abort();
    await run;

    expect(done().at(-1)).toEqual({ level: 'info', chains: 0, anchored: 0, unchanged: 0, failed: 0, unchecked: 0 });
  });

  it.each([
    ['an entry that is not text', [ORG, null]],
    ['an ID with more after it', [`${ORG}0`]],
    ['an ID with more before it', [`x${ORG}`]],
    ['an entry that is not an ID', [ORG, 'not-an-id']],
    ['more organisations than any real list', Array.from({ length: 10_001 }, () => ORG)],
  ])('raises the alarm for a list holding %s, and checks none of it', async (_, list) => {
    const { organizations, verified } = directory([list]);
    const { check, events } = checking([], undefined, organizations);
    await check.run();

    expect(verified).toEqual([]);
    expect(events()).toEqual([listAlarm]);
  });

  it('raises the alarm for a record of created organisations that is not IDs, or that the database refuses', async () => {
    for (const recorded of [[42], refused('42501')]) {
      const { organizations, verified } = directory([[ORG]], {}, recorded);
      const { check, events } = checking([], undefined, organizations);
      await check.run();

      expect(verified).toEqual([]);
      expect(events()).toEqual([listAlarm]);
    }
  });

  it('raises the alarm for a list never read for a whole stale period, though no organisation is known yet', async () => {
    const { organizations } = directory([unreachable()]);
    const { check, events, clock } = checking([], undefined, organizations);
    await check.run();
    clock.advanceBy(STALE_MS - 1);
    await check.run();
    const listWarning = { level: 'warn', event: 'audit.anchor_check_failed', chain: 'organisation', check: 'list' };
    expect(events()).toEqual([listWarning, listWarning]);

    clock.advanceBy(1);
    await check.run();
    expect(events().slice(2)).toEqual([listWarning, listAlarm]);
  });

  it('counts the list’s stale period from its last whole read', async () => {
    const { organizations } = directory([[], unreachable()]);
    const { check, events, clock } = checking([], undefined, organizations);
    clock.advanceBy(STALE_MS);
    await check.run();
    clock.advanceBy(STALE_MS - 1);
    await check.run();

    expect(events().map((line) => line.level)).toEqual(['warn']);
  });

  it('contains a list that throws before giving a promise, as a warning', async () => {
    const organizations: OrganisationChains = {
      hold: () => Promise.resolve(),
      list: () => {
        throw new Error('the list broke');
      },
      recorded: () => Promise.resolve([]),
      verify: () => Promise.resolve(ok(1n)),
    };
    const { check, events, done } = checking([], undefined, organizations);
    await check.run();

    expect(events()).toEqual([
      { level: 'warn', event: 'audit.anchor_check_failed', chain: 'organisation', check: 'list' },
    ]);
    expect(done()).toHaveLength(1);
  });

  it('starts a newly listed organisation’s stale period when it is first seen, not when the process began', async () => {
    const { organizations } = directory([[], [ORG]], { [ORG]: unreachable() as unknown as ChainReport });
    const failing: OrganisationChains = {
      ...organizations,
      verify: () => Promise.reject(unreachable()),
    };
    const { check, events, clock } = checking([], undefined, failing);
    await check.run();
    clock.advanceBy(STALE_MS);
    await check.run();

    expect(events()).toEqual([
      { level: 'warn', event: 'audit.anchor_check_failed', chain: 'organisation', orgId: ORG },
    ]);
  });

  it('never reads the list twice at once: a read still hung is a warning, and no second read starts', async () => {
    vi.useFakeTimers();
    try {
      let reads = 0;
      const organizations: OrganisationChains = {
        hold: () => Promise.resolve(),
        list: () => {
          reads += 1;
          return new Promise<never>(() => undefined);
        },
        recorded: () => Promise.resolve([]),
        verify: () => Promise.resolve(ok(1n)),
      };
      const { check, events } = checking([], undefined, organizations);
      const first = check.run();
      await vi.advanceTimersByTimeAsync(DEADLINE_MS);
      await first;
      await check.run();

      expect(reads).toBe(1);
      expect(events()).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('counts a list past its deadline as not read', async () => {
    vi.useFakeTimers();
    try {
      const organizations: OrganisationChains = {
        hold: () => Promise.resolve(),
        list: () => new Promise<never>(() => undefined),
        recorded: () => Promise.resolve([]),
        verify: () => Promise.resolve(ok(1n)),
      };
      const { check, events } = checking([], undefined, organizations);
      const run = check.run();
      await vi.advanceTimersByTimeAsync(DEADLINE_MS);
      await run;

      expect(events()).toEqual([
        { level: 'warn', event: 'audit.anchor_check_failed', chain: 'organisation', check: 'list' },
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('ends at once, raising nothing, when stopped while the list is read', async () => {
    const organizations: OrganisationChains = {
      hold: () => Promise.resolve(),
      list: () => new Promise<never>(() => undefined),
      recorded: () => Promise.resolve([]),
      verify: () => Promise.resolve(ok(1n)),
    };
    const { check, events, done } = checking([], undefined, organizations);
    const stopping = new AbortController();
    const run = check.run(stopping.signal);
    stopping.abort();
    await run;

    expect(events()).toEqual([]);
    expect(done()).toEqual([{ level: 'info', chains: 0, anchored: 0, unchanged: 0, failed: 0, unchecked: 0 }]);
  });

  it('reads no list in a run stopped during the platform’s check', async () => {
    let listed = 0;
    const organizations: OrganisationChains = {
      hold: () => Promise.resolve(),
      list: () => {
        listed += 1;
        return Promise.resolve([ORG]);
      },
      recorded: () => Promise.resolve([]),
      verify: () => Promise.resolve(ok(1n)),
    };
    const stopping = new AbortController();
    const platform: CheckedChain = {
      chain: { kind: 'platform' },
      verify: () => {
        stopping.abort();
        return Promise.resolve(ok(1n));
      },
    };
    const { check } = checking([platform], undefined, organizations);
    await check.run(stopping.signal);

    expect(listed).toBe(0);
  });
});

describe('an organisation that fails is put on its integrity hold (B1d-3)', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /**
   * A directory giving the lists in turn (the last again once they run out;
   * an Error refuses), recording ORG as created, whose chains check out at
   * seq 1 or as `reports` says, and whose holds are recorded in turn, each
   * ending as `holdWith` says.
   */
  function holding(
    lists: readonly (readonly string[] | Error)[],
    reports: Record<string, ChainReport | Error> = {},
    holdWith: (orgId: string) => Promise<void> = () => Promise.resolve(),
  ) {
    const steps: string[] = [];
    let turn = 0;
    const organizations: OrganisationChains = {
      list: () => {
        const listed = lists[Math.min(turn, lists.length - 1)] ?? [];
        turn += 1;
        return listed instanceof Error ? Promise.reject(listed) : Promise.resolve(listed);
      },
      recorded: () => Promise.resolve([ORG]),
      verify: (orgId) => {
        steps.push(`verify ${orgId}`);
        const report = reports[orgId] ?? ok(1n);
        return report instanceof Error ? Promise.reject(report) : Promise.resolve(report);
      },
      // A hold given no failure (`-`) only tries one waiting.
      hold: (orgId, failure) => {
        steps.push(`hold ${orgId} ${failure ?? '-'}`);
        return holdWith(orgId);
      },
    };
    return { organizations, steps };
  }
  const holdAlarm = (orgId: string) => ({
    level: 'error',
    event: 'audit.integrity_failed',
    chain: 'organisation',
    check: 'hold',
    reason: 'not_recorded',
    orgId,
  });

  it('holds an organisation whose chain fails, straight after its check, and tries a waiting hold for each that passes', async () => {
    const { organizations, steps } = holding([[ORG, OTHER_ORG]], {
      [ORG]: { ok: false, problem: { reason: 'hash', seq: 2n } },
    });
    const { check } = checking([], undefined, organizations);
    await check.run();

    expect(steps).toEqual([`verify ${ORG}`, `hold ${ORG} hash`, `verify ${OTHER_ORG}`, `hold ${OTHER_ORG} -`]);
  });

  it('holds an organisation that fails its anchor, every run, as the alarm repeats', async () => {
    const reports: Record<string, ChainReport> = { [ORG]: ok(3n) };
    const { organizations, steps } = holding([[ORG]], reports);
    const { check } = checking([], undefined, organizations);
    await check.run();
    reports[ORG] = ok(2n);
    await check.run();
    await check.run();

    expect(steps.filter((step) => step.startsWith('hold'))).toEqual([
      `hold ${ORG} -`,
      `hold ${ORG} anchor`,
      `hold ${ORG} anchor`,
    ]);
  });

  it('holds only for this run’s failure: a chain that fails and then checks out is not held again', async () => {
    const reports: Record<string, ChainReport> = { [ORG]: { ok: false, problem: { reason: 'hash', seq: 2n } } };
    const { organizations, steps } = holding([[ORG]], reports);
    const { check } = checking([], undefined, organizations);
    await check.run();
    reports[ORG] = ok(1n);
    await check.run();

    expect(steps.filter((step) => step.startsWith('hold'))).toEqual([`hold ${ORG} hash`, `hold ${ORG} -`]);
  });

  it('stops among the organisations that have left the list: no alarm or hold for those after', async () => {
    const stopping = new AbortController();
    const steps: string[] = [];
    const organizations: OrganisationChains = {
      list: () => Promise.resolve([]),
      recorded: () => Promise.resolve([ORG, OTHER_ORG]),
      verify: () => Promise.resolve(ok(1n)),
      hold: (orgId) => {
        steps.push(orgId);
        stopping.abort();
        return Promise.resolve();
      },
    };
    const { check, events } = checking([], undefined, organizations);
    await check.run(stopping.signal);

    expect(steps).toEqual([ORG]);
    expect(events().filter((line) => line.reason === 'unlisted')).toEqual([expect.objectContaining({ orgId: ORG })]);
  });

  it('holds an organisation that has left the list, by its ID', async () => {
    const { organizations, steps } = holding([[OTHER_ORG]]);
    const { check } = checking([], undefined, organizations);
    await check.run();

    expect(steps).toEqual([`hold ${ORG} unlisted`, `verify ${OTHER_ORG}`, `hold ${OTHER_ORG} -`]);
  });

  it('holds a chain the database refuses to check, but not one unchecked, even past its stale period, which is the alarm alone', async () => {
    const { organizations, steps } = holding([[ORG, OTHER_ORG]], {
      [ORG]: refused('42501'),
      [OTHER_ORG]: unreachable(),
    });
    const { check, clock, events } = checking([], undefined, organizations);
    await check.run();
    clock.advanceBy(STALE_MS);
    await check.run();

    expect(steps.filter((step) => step.startsWith('hold'))).toEqual([
      `hold ${ORG} store`,
      `hold ${OTHER_ORG} -`,
      `hold ${ORG} store`,
      `hold ${OTHER_ORG} -`,
    ]);
    expect(events().filter((line) => line.orgId === OTHER_ORG && line.event === 'audit.integrity_failed')).toEqual([
      expect.objectContaining({ reason: 'unchecked' }),
    ]);
  });

  it('with no list to go by, only tries a waiting hold for each organisation seen, stale or not', async () => {
    const { organizations, steps } = holding([[ORG], unreachable()]);
    const { check, clock } = checking([], undefined, organizations);
    await check.run();
    await check.run();
    clock.advanceBy(STALE_MS);
    await check.run();

    expect(steps).toEqual([`verify ${ORG}`, `hold ${ORG} -`, `hold ${ORG} -`, `hold ${ORG} -`]);
  });

  it('a hold that throws, against its word, is the alarm, and the run goes on to the next organisation', async () => {
    const { organizations, steps } = holding([[ORG, OTHER_ORG]], {}, (orgId) =>
      orgId === ORG ? Promise.reject(new Error('the hold broke its word')) : Promise.resolve(),
    );
    const { check, events, done } = checking([], undefined, organizations);
    await check.run();

    expect(steps).toEqual([`verify ${ORG}`, `hold ${ORG} -`, `verify ${OTHER_ORG}`, `hold ${OTHER_ORG} -`]);
    expect(events().filter((line) => line.event === 'audit.integrity_failed')).toEqual([holdAlarm(ORG)]);
    expect(done()).toEqual([{ level: 'info', chains: 2, anchored: 2, unchanged: 0, failed: 0, unchecked: 0 }]);
  });

  it('a hold past the deadline is the alarm, and no second hold of that organisation starts while it hangs', async () => {
    vi.useFakeTimers();
    const { organizations, steps } = holding(
      [[ORG]],
      { [ORG]: { ok: false, problem: { reason: 'hash', seq: 2n } } },
      () => new Promise<never>(() => undefined),
    );
    const { check, events, capture } = checking([], undefined, organizations);
    const first = check.run();
    await vi.advanceTimersByTimeAsync(DEADLINE_MS - 1);
    expect(events().filter((line) => line.check === 'hold')).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await first;
    const second = check.run();
    await vi.advanceTimersByTimeAsync(0);
    await second;

    expect(steps).toEqual([`verify ${ORG}`, `hold ${ORG} hash`, `verify ${ORG}`]);
    expect(events().filter((line) => line.check === 'hold')).toEqual([holdAlarm(ORG), holdAlarm(ORG)]);
    expect(
      capture
        .lines()
        .filter((line) => line.check === 'hold')
        .map((line) => (line.err as { message?: string } | undefined)?.message),
    ).toEqual([
      `the check did not finish within ${String(DEADLINE_MS)} ms`,
      'the last hold of this organisation has not finished',
    ]);
  });

  it('ends at once when stopped during a hold, raising nothing, and checks no more organisations', async () => {
    const stopping = new AbortController();
    const { organizations, steps } = holding([[ORG, OTHER_ORG]], {}, () => {
      stopping.abort();
      return new Promise<never>(() => undefined);
    });
    const { check, events } = checking([], undefined, organizations);
    await check.run(stopping.signal);

    expect(steps).toEqual([`verify ${ORG}`, `hold ${ORG} -`]);
    expect(events().filter((line) => line.check === 'hold')).toEqual([]);
  });

  it('tries no hold for an organisation whose check was stopped', async () => {
    const stopping = new AbortController();
    const steps: string[] = [];
    const organizations: OrganisationChains = {
      list: () => Promise.resolve([ORG]),
      recorded: () => Promise.resolve([]),
      verify: () => {
        steps.push('verify');
        stopping.abort();
        return new Promise<never>(() => undefined);
      },
      hold: () => {
        steps.push('hold');
        return Promise.resolve();
      },
    };
    const { check } = checking([], undefined, organizations);
    await check.run(stopping.signal);

    expect(steps).toEqual(['verify']);
  });
});

describe('the anchor check schedule', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** A check that counts its runs, each taking as long as the test says unless it is stopped first. */
  function counting(runMs = 0): AnchorCheck & { runs: number; signals: AbortSignal[] } {
    const check = {
      runs: 0,
      signals: [] as AbortSignal[],
      run: async (signal?: AbortSignal) => {
        check.runs += 1;
        if (signal !== undefined) check.signals.push(signal);
        if (runMs === 0) return;
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, runMs);
          signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            resolve();
          });
        });
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

  it('stops: ends a run in flight at once and waits for it to end, then runs no more', async () => {
    vi.useFakeTimers();
    const check = counting(5_000);
    const schedule = scheduleAnchorCheck(check, 60_000);
    expect(check.signals.map((signal) => signal.aborted)).toEqual([false]);
    await vi.advanceTimersByTimeAsync(1_000);
    await schedule.stop();

    expect(check.signals.map((signal) => signal.aborted)).toEqual([true]);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(check.runs).toBe(1);
  });

  it('stops: waits for a run in flight that is slow to end', async () => {
    vi.useFakeTimers();
    let end: () => void = () => undefined;
    const check: AnchorCheck = {
      run: () =>
        new Promise<void>((resolve) => {
          end = resolve;
        }),
    };
    const schedule = scheduleAnchorCheck(check, 60_000);
    let stopped = false;
    const stopping = schedule.stop().then(() => {
      stopped = true;
    });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(stopped).toBe(false);
    end();
    await stopping;

    expect(stopped).toBe(true);
  });
});
