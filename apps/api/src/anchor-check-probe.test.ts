// The anchor check's probe (4D2e E8): every anchored chain's head read against its anchor
// at a run's start, so a chain that hasn't moved takes its turn with no read of its own,
// one found failing is the alarm and its hold, and anything the probe didn't answer for is
// read in its turn as before. The probe's own reads are the audit trail's (probeHeads).
import {
  type AnchorPoint,
  type ChainReport,
  type CheckedPoint,
  createMemoryAnchorStore,
  signAnchor,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import {
  type AnchorCheckOptions,
  createAnchorCheck,
  type OrganisationChains,
  type ProbeAnswer,
} from './anchor-check.ts';
import { platformChainCheck, recordedSince } from './anchor-rotation.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const AT = new Date('2026-11-04T09:00:00.000Z');

const point = (seq: bigint, fill = Number(seq)): CheckedPoint => ({
  seq,
  hash: Buffer.alloc(32, fill),
  macKeyVersion: 1,
});
const ok = (seq: bigint): ChainReport => ({ ok: true, ...point(seq) });

type Probing = (
  chains: readonly { readonly orgId: string; readonly from: CheckedPoint }[],
  signal: AbortSignal,
  pagesAtOnce: number,
) => Promise<ReadonlyMap<string, ProbeAnswer>>;

/** Two organisations (or `orgs`) whose chains check out at seq 1, the probe as given, every read, probe and hold recorded. */
function probing(
  probe: Probing | undefined,
  deadlineMs = 120_000,
  lanes = 1,
  {
    orgs = [ORG, OTHER_ORG],
    held = new Set<string>(),
    ...more
  }: {
    readonly orgs?: readonly string[];
    /** Organisations whose checks go on until released. */
    readonly held?: ReadonlySet<string>;
  } & Pick<AnchorCheckOptions, 'runWithinMs' | 'probePages'> = {},
) {
  const steps: string[] = [];
  const asked: { orgId: string; seq: bigint }[][] = [];
  const pagesGiven: number[] = [];
  const clock = new FixedClock(AT);
  const releases: (() => void)[] = [];
  const organizations: OrganisationChains = {
    list: () => Promise.resolve(orgs),
    recorded: () => Promise.resolve(orgs),
    verify: (orgId, anchor) => {
      steps.push(`verify ${orgId} ${anchor?.seq.toString() ?? '-'}`);
      if (!held.has(orgId)) return Promise.resolve(ok(1n));
      return new Promise((resolve) => {
        releases.push(() => {
          resolve(ok(1n));
        });
      });
    },
    hold: (orgId, failure) => {
      if (failure !== undefined) steps.push(`hold ${orgId} ${failure}`);
      return Promise.resolve();
    },
    ...(probe === undefined
      ? {}
      : {
          probe: (chains, signal, pagesAtOnce) => {
            asked.push(chains.map(({ orgId, from }) => ({ orgId, seq: from.seq })));
            pagesGiven.push(pagesAtOnce);
            return probe(chains, signal, pagesAtOnce);
          },
        }),
  };
  const capture = new LogCapture();
  const anchors = createMemoryAnchorStore();
  const check = createAnchorCheck({
    chains: [],
    organizations,
    keys,
    clock,
    logger: testLogger(capture),
    staleAfterMs: 900_000,
    deadlineMs,
    anchors,
    shuffled: (orgIds) => orgIds,
    lanes,
    ...more,
  });
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  const release = (): void => {
    for (const each of releases.splice(0)) each();
  };
  return { check, steps, asked, anchors, lines, pagesGiven, clock, release };
}

const answering =
  (answers: Record<string, ProbeAnswer>): Probing =>
  () =>
    Promise.resolve(new Map(Object.entries(answers)));

const probeWarning = (chains: number): unknown =>
  expect.objectContaining({ level: 'warn', event: 'audit.anchor_check_failed', check: 'probe', chains });

describe('the probe at the start of a run (4D2e E8)', () => {
  it('probes only chains with an anchor, and reads none it found unmoved: those are checked, unchanged', async () => {
    const { check, steps, asked, lines } = probing(
      answering({ [ORG]: { kind: 'same' }, [OTHER_ORG]: { kind: 'same' } }),
    );
    await check.run();
    expect(asked).toEqual([]);
    expect(steps).toEqual([`verify ${ORG} -`, `verify ${OTHER_ORG} -`]);

    await check.run();
    expect(asked).toEqual([
      [
        { orgId: ORG, seq: 1n },
        { orgId: OTHER_ORG, seq: 1n },
      ],
    ]);
    expect(steps).toHaveLength(2);
    expect(lines('audit.anchor_check_done').at(-1)).toMatchObject({ chains: 2, unchanged: 2, failed: 0 });
  });

  it('reads from its anchor a chain the probe found moved, and only that one', async () => {
    const { check, steps } = probing(answering({ [ORG]: { kind: 'moved' }, [OTHER_ORG]: { kind: 'same' } }));
    await check.run();
    await check.run();

    expect(steps.slice(2)).toEqual([`verify ${ORG} 1`]);
  });

  it('raises the alarm on a chain the probe found failing, and holds it, with no read of its own', async () => {
    const { check, steps, lines } = probing(
      answering({ [ORG]: { kind: 'failed', problem: { reason: 'gap', seq: 3n } }, [OTHER_ORG]: { kind: 'same' } }),
    );
    await check.run();
    await check.run();

    expect(steps.slice(2)).toEqual([`hold ${ORG} gap`]);
    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({
        level: 'error',
        chain: 'organisation',
        check: 'anchor',
        reason: 'gap',
        seq: '3',
        orgId: ORG,
      }),
    ]);
  });

  it('reads in its turn a chain the probe missed or did not answer for, with one warning for the misses', async () => {
    const { check, steps, lines } = probing(answering({ [ORG]: { kind: 'missed', error: new Error('read timeout') } }));
    await check.run();
    await check.run();

    expect(steps.slice(2)).toEqual([`verify ${ORG} 1`, `verify ${OTHER_ORG} 1`]);
    expect(lines('audit.anchor_check_failed')).toEqual([probeWarning(1)]);
  });

  it('reads every chain in its turn when the probe fails whole, with one warning', async () => {
    const { check, steps, lines } = probing(() => Promise.reject(new Error('connect ECONNREFUSED')));
    await check.run();
    await check.run();

    expect(steps.slice(2)).toEqual([`verify ${ORG} 1`, `verify ${OTHER_ORG} 1`]);
    expect(lines('audit.anchor_check_failed')).toEqual([probeWarning(2)]);
  });

  it('reads a chain anchored again since the probe compared it: the answer was for another anchor', async () => {
    const later: { anchors?: ReturnType<typeof probing>['anchors'] } = {};
    const { check, steps, anchors } = probing((chains) => {
      // A hand-off anchors the organisation while the probe runs.
      later.anchors?.keep(
        signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(1n), new Date(AT.getTime() + 1)),
      );
      return Promise.resolve(new Map(chains.map(({ orgId }) => [orgId, { kind: 'same' } as const])));
    });
    later.anchors = anchors;
    await check.run();
    anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(1n, 9), AT));
    await check.run();

    expect(steps.slice(2)).toEqual([`verify ${ORG} 1`]);
  });

  it('runs the probe one at a time: one past its deadline leaves every chain to its turn, this run and the next', async () => {
    let finish: (() => void) | undefined;
    const { check, steps, asked, lines } = probing(
      () =>
        new Promise((resolve) => {
          finish = () => {
            resolve(new Map());
          };
        }),
      50,
      // The probe past its deadline holds its lane until it ends, as any check does: the other lane takes the turns.
      2,
      { probePages: 1 },
    );
    await check.run();
    await check.run();
    await check.run();

    expect(asked).toHaveLength(1);
    expect(steps.slice(2)).toEqual([
      `verify ${ORG} 1`,
      `verify ${OTHER_ORG} 1`,
      `verify ${ORG} 1`,
      `verify ${OTHER_ORG} 1`,
    ]);
    expect(lines('audit.anchor_check_failed')).toEqual([probeWarning(2), probeWarning(2)]);
    finish?.();
  });

  it('says nothing of a probe the stop ended, and the run ends', async () => {
    const stopping = new AbortController();
    const { check, steps, lines } = probing((_chains, signal) => {
      stopping.abort();
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          reject(new Error('stopped'));
        });
      });
    });
    await check.run();
    await check.run(stopping.signal);

    expect(steps).toHaveLength(2);
    expect(lines('audit.anchor_check_failed')).toEqual([]);
  });
});

describe("the probe's pages and its time (4D2e E8 follow-up)", () => {
  const ORGS = Array.from({ length: 6 }, (_, n) => `0199a0f0-0000-7000-8000-${String(n + 10).padStart(12, '0')}`);

  /** A probe that answers the first half of what it is asked, then waits for the run's time to end it: what it reached. */
  const halfThenTimeUp: Probing = (chains, signal) => {
    const answered = new Map(chains.slice(0, chains.length / 2).map(({ orgId }) => [orgId, { kind: 'same' } as const]));
    return new Promise((resolve) => {
      signal.addEventListener('abort', () => {
        resolve(answered);
      });
    });
  };

  it('reads up to four pages at once, never more than the lanes', async () => {
    const answer: Probing = (chains) =>
      Promise.resolve(new Map(chains.map(({ orgId }) => [orgId, { kind: 'same' } as const])));
    for (const [lanes, probePages, given] of [
      [4, undefined, 4],
      [2, undefined, 2],
      [4, 1, 1],
    ] as const) {
      const { check, pagesGiven } = probing(answer, 120_000, lanes, probePages === undefined ? {} : { probePages });
      await check.run();
      await check.run();
      expect(pagesGiven).toEqual([given]);
    }
  });

  it('takes only the lanes free: a check from the last run still under way leaves it the rest, and full, it waits', async () => {
    const answer: Probing = (chains) =>
      Promise.resolve(new Map(chains.map(({ orgId }) => [orgId, { kind: 'same' } as const])));
    // Two lanes, one held by ORG's check past its deadline: the probe reads one page at a time, not four.
    const partly = probing(answer, 50, 2, { held: new Set([ORG]) });
    await partly.check.run();
    await partly.check.run();
    expect(partly.pagesGiven).toEqual([1]);
    partly.release();

    // One lane, held by OTHER_ORG's check after ORG was anchored: the probe waits for it, never starting beside
    // it, until the run's time is up; then, the lane free, takes it.
    const full = probing(answer, 50, 1, { held: new Set([OTHER_ORG]), runWithinMs: 200 });
    await full.check.run();
    await full.check.run();
    expect(full.asked).toEqual([]);
    expect(full.pagesGiven).toEqual([]);
    full.release();
    await full.check.run();
    expect(full.pagesGiven).toEqual([1]);
  });

  it('holds as many of the lanes as it reads pages: past its deadline no turn starts until it ends', async () => {
    let finish: (() => void) | undefined;
    const { check, steps } = probing(
      () =>
        new Promise((resolve) => {
          finish = () => {
            resolve(new Map());
          };
        }),
      50,
      2,
      { runWithinMs: 300 },
    );
    await check.run();
    await check.run();

    expect(steps.slice(2)).toEqual([]);
    finish?.();
  });

  it('cut short by the run, probes first next run those it did not reach: two runs of half cover every one', async () => {
    const { check, asked, lines } = probing(halfThenTimeUp, 120_000, 2, { orgs: ORGS, runWithinMs: 80 });
    await check.run();
    await check.run();
    await check.run();

    const [first = [], second = []] = asked.map((each) => each.map(({ orgId }) => orgId));
    expect(first).toEqual(ORGS);
    expect(second).toEqual([...ORGS.slice(3), ...ORGS.slice(0, 3)]);
    expect(new Set([...first.slice(0, 3), ...second.slice(0, 3)])).toEqual(new Set(ORGS));
    expect(lines('audit.probe_unfinished')).toEqual([
      expect.objectContaining({ level: 'warn', reached: 3, total: 6 }),
      expect.objectContaining({ level: 'warn', reached: 3, total: 6 }),
    ]);
  });

  it('counts what a probe cut short found: unmoved ones checked, a failing one the alarm and its hold', async () => {
    const { check, steps, lines } = probing(
      (chains, signal) => {
        const [first] = chains;
        const answered = new Map<string, ProbeAnswer>([
          [first?.orgId ?? '', { kind: 'failed', problem: { reason: 'head', seq: 1n } }],
          ...chains.slice(1, 3).map(({ orgId }) => [orgId, { kind: 'same' }] as const),
        ]);
        return new Promise((resolve) => {
          signal.addEventListener('abort', () => {
            resolve(answered);
          });
        });
      },
      120_000,
      2,
      { orgs: ORGS, runWithinMs: 80 },
    );
    await check.run();
    await check.run();

    expect(steps.filter((step) => step.startsWith('hold'))).toEqual([`hold ${ORGS[0] ?? ''} head`]);
    expect(lines('audit.anchor_check_done').at(-1)).toMatchObject({ chains: 3, unchanged: 2, failed: 1 });
  });

  it('raises the unchecked alarm, no hold, for one left unprobed past the stale limit', async () => {
    const { check, clock, steps, lines } = probing(halfThenTimeUp, 120_000, 2, { orgs: ORGS, runWithinMs: 80 });
    await check.run();
    await check.run();
    expect(lines('audit.integrity_failed')).toEqual([]);
    clock.advanceBy(900_000);
    await check.run();

    expect(lines('audit.integrity_failed')).toEqual([
      expect.objectContaining({ level: 'error', reason: 'unchecked', organisations: 3, firstFew: ORGS.slice(0, 3) }),
    ]);
    expect(steps.filter((step) => step.startsWith('hold'))).toEqual([]);
  });
});

describe('the organisations the platform chain records, read past the last read (4D2e E8, step 2)', () => {
  it('reads none before the chain is anchored, then all to its anchor, then only past the last read', async () => {
    const reads: string[] = [];
    let anchored: bigint | undefined;
    const rows: Record<string, string[]> = { '0-4': [ORG], '4-9': [OTHER_ORG] };
    const recorded = recordedSince({
      since: (afterSeq, upTo) => {
        const stretch = `${afterSeq.toString()}-${upTo.toString()}`;
        reads.push(stretch);
        return Promise.resolve({ orgIds: rows[stretch] ?? [], seq: afterSeq });
      },
      checkedTo: () => anchored,
    });

    expect(await recorded()).toEqual([]);
    anchored = 4n;
    expect(await recorded()).toEqual([ORG]);
    expect(await recorded()).toEqual([ORG]);
    anchored = 9n;
    expect(await recorded()).toEqual([ORG, OTHER_ORG]);
    expect(reads).toEqual(['0-4', '4-9']);
  });

  it('keeps its place where a read fails, and reads that stretch again', async () => {
    const reads: string[] = [];
    let fail = true;
    const recorded = recordedSince({
      since: (afterSeq, upTo) => {
        reads.push(`${afterSeq.toString()}-${upTo.toString()}`);
        return fail ? Promise.reject(new Error('read timeout')) : Promise.resolve({ orgIds: [ORG], seq: upTo });
      },
      checkedTo: () => 3n,
    });

    await expect(recorded()).rejects.toThrow('read timeout');
    fail = false;
    expect(await recorded()).toEqual([ORG]);
    expect(reads).toEqual(['0-3', '0-3']);
  });
});

describe("the platform chain's check (4D2e E8, each run's step 2)", () => {
  /** A check of the platform chain, each read recorded: from its anchor, or whole. */
  function platformChain(wholeReports: readonly ChainReport[] = [ok(4n)]) {
    const reads: string[] = [];
    let turn = 0;
    const clock = new FixedClock(AT);
    const verify = platformChainCheck({
      fromAnchor: (from) => {
        reads.push(`from ${from.seq.toString()}`);
        return Promise.resolve(ok(from.seq));
      },
      whole: (anchor: AnchorPoint | undefined) => {
        reads.push(`whole ${anchor?.seq.toString() ?? '-'}`);
        const report = wholeReports[Math.min(turn, wholeReports.length - 1)] ?? ok(4n);
        turn += 1;
        return Promise.resolve(report);
      },
      clock,
    });
    return { verify, reads, clock };
  }
  const anchor: CheckedPoint = { seq: 4n, hash: Buffer.alloc(32, 4), macKeyVersion: 1 };

  it('reads it whole first and with no anchor, from its anchor after, and whole again a day on', async () => {
    const { verify, reads, clock } = platformChain();
    await verify(undefined);
    await verify(anchor);
    clock.advanceBy(24 * 3600_000 - 1);
    await verify(anchor);
    clock.advanceBy(1);
    await verify(anchor);
    await verify(anchor);

    expect(reads).toEqual(['whole -', 'from 4', 'from 4', 'whole 4', 'from 4']);
  });

  it('reads it whole while the whole read fails, and with no anchor, whenever its last whole read was', async () => {
    const { verify, reads } = platformChain([{ ok: false, problem: { reason: 'hash', seq: 2n } }, ok(4n)]);
    await verify(anchor);
    await verify(anchor);
    await verify(undefined);
    await verify(anchor);

    expect(reads).toEqual(['whole 4', 'whole 4', 'whole -', 'from 4']);
  });
});
