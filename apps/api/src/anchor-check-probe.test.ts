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

import { createAnchorCheck, type OrganisationChains, type ProbeAnswer } from './anchor-check.ts';
import { platformChainCheck } from './anchor-rotation.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const AT = new Date('2026-11-04T09:00:00.000Z');

const ok = (seq: bigint): ChainReport => ({ ok: true, seq, hash: Buffer.alloc(32, Number(seq)), macKeyVersion: 1 });

type Probing = (
  chains: readonly { readonly orgId: string; readonly from: CheckedPoint }[],
  signal: AbortSignal,
) => Promise<ReadonlyMap<string, ProbeAnswer>>;

/** Two organisations whose chains check out at seq 1, the probe as given, every read, probe and hold recorded. */
function probing(probe: Probing | undefined, deadlineMs = 120_000, lanes = 1) {
  const steps: string[] = [];
  const asked: { orgId: string; seq: bigint }[][] = [];
  const organizations: OrganisationChains = {
    list: () => Promise.resolve([ORG, OTHER_ORG]),
    recorded: () => Promise.resolve([ORG, OTHER_ORG]),
    verify: (orgId, anchor) => {
      steps.push(`verify ${orgId} ${anchor?.seq.toString() ?? '-'}`);
      return Promise.resolve(ok(1n));
    },
    hold: (orgId, failure) => {
      if (failure !== undefined) steps.push(`hold ${orgId} ${failure}`);
      return Promise.resolve();
    },
    ...(probe === undefined
      ? {}
      : {
          probe: (chains, signal) => {
            asked.push(chains.map(({ orgId, from }) => ({ orgId, seq: from.seq })));
            return probe(chains, signal);
          },
        }),
  };
  const capture = new LogCapture();
  const anchors = createMemoryAnchorStore();
  const check = createAnchorCheck({
    chains: [],
    organizations,
    keys,
    clock: new FixedClock(AT),
    logger: testLogger(capture),
    staleAfterMs: 900_000,
    deadlineMs,
    anchors,
    shuffled: (orgIds) => orgIds,
    lanes,
  });
  const lines = (event: string) => capture.lines().filter((line) => line.event === event);
  return { check, steps, asked, anchors, lines };
}

const answering =
  (answers: Record<string, ProbeAnswer>): Probing =>
  () =>
    Promise.resolve(new Map(Object.entries(answers)));

const probeWarning = (chains: number) =>
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
    let anchorsOf: ReturnType<typeof probing>['anchors'] | undefined;
    const { check, steps, anchors } = probing((chains) => {
      // A hand-off anchors the organisation while the probe runs.
      anchorsOf?.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, ok(1n), new Date(AT.getTime() + 1)));
      return Promise.resolve(new Map(chains.map(({ orgId }) => [orgId, { kind: 'same' } as const])));
    });
    anchorsOf = anchors;
    await check.run();
    anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, { ...ok(1n), hash: Buffer.alloc(32, 9) }, AT));
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
      // The probe past its deadline holds a lane until it ends, as any check does: the other lane takes the turns.
      2,
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
