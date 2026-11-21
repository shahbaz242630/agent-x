// The anchor check held to the witness log (TR-1): every probe asks the heads copies witnessed above each chain's
// anchor, a chain cut back below one is the alarm (`check: witness`) and its hold, a walk that missed one anchors
// nothing, the heads are let go once anchored past, and the leader probes at once the chains a refresh gave a head.
import { type Chain, type ChainReport, type CheckedPoint, createMemoryAnchorStore } from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createAnchorCheck, type OrganisationChains, type ProbeAnswer } from './anchor-check.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const OTHER_ORG = '0199a0f0-0000-7000-8000-000000000002';
const AT = new Date('2026-11-04T09:00:00.000Z');

const point = (seq: bigint): CheckedPoint => ({ seq, hash: Buffer.alloc(32, Number(seq)), macKeyVersion: 1 });
const ok = (seq: bigint): ChainReport => ({ ok: true, ...point(seq) });
const witnessed = (seq: bigint) => ({ seq, hash: Buffer.alloc(32, Number(seq)), at: AT.getTime() });

interface Asked {
  readonly orgId: string;
  readonly from: CheckedPoint;
  readonly heldTo?: readonly { seq: bigint }[];
}

/** How a test's check answers. */
interface Answering {
  readonly verified?: () => ChainReport;
  readonly answers?: Readonly<Record<string, ProbeAnswer>>;
  readonly probeFails?: boolean;
}

function withWitness({ verified = () => ok(1n), answers = {}, probeFails = false }: Answering = {}) {
  const steps: string[] = [];
  const asked: { orgId: string; from: bigint; heldTo: bigint[] }[] = [];
  const pending = new Map<string, ReturnType<typeof witnessed>[]>();
  const pruned: [string, bigint][] = [];
  const nameOf = (chain: Chain) => (chain.kind === 'platform' ? 'platform' : chain.orgId);
  const organizations: OrganisationChains = {
    list: () => Promise.resolve([ORG, OTHER_ORG]),
    recorded: () => Promise.resolve([ORG, OTHER_ORG]),
    verify: (orgId) => {
      steps.push(`verify ${orgId}`);
      return Promise.resolve(verified());
    },
    hold: (orgId, failure) => {
      if (failure !== undefined) steps.push(`hold ${orgId} ${failure}`);
      return Promise.resolve();
    },
    probe: (chains: readonly Asked[]) => {
      for (const { orgId, from, heldTo = [] } of chains) {
        asked.push({ orgId, from: from.seq, heldTo: heldTo.map(({ seq }) => seq) });
      }
      if (probeFails) return Promise.reject(new Error('database away'));
      return Promise.resolve(new Map(Object.entries(answers)));
    },
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
    deadlineMs: 120_000,
    anchors,
    shuffled: (orgIds) => orgIds,
    lanes: 1,
    witness: {
      pending: (chain) => pending.get(nameOf(chain)) ?? [],
      prune: (chain, seq) => {
        pruned.push([nameOf(chain), seq]);
      },
    },
  });
  const alarms = () =>
    capture
      .lines()
      .filter((line) => line.event === 'audit.integrity_failed')
      .map(({ check: what, reason, seq }) => ({ what, reason, seq }));
  return { check, steps, asked, pending, pruned, alarms, capture };
}

describe('TR-1 the anchor check held to the witness log', () => {
  it('a walk that holds anchors and lets go the heads at or below it; one that missed a witnessed head is the alarm, never anchored', async () => {
    const run = withWitness();
    await run.check.run();
    expect(run.pruned).toEqual([
      [ORG, 1n],
      [OTHER_ORG, 1n],
    ]);
    let report: ChainReport = { ok: false, problem: { reason: 'cut_back', seq: 7n } };
    const cut = withWitness({ verified: () => report });
    await cut.check.run();
    expect(cut.alarms()).toEqual([
      { what: 'witness', reason: 'cut_back', seq: '7' },
      { what: 'witness', reason: 'cut_back', seq: '7' },
    ]);
    expect(cut.steps).toContain(`hold ${ORG} cut_back`);
    expect(cut.pruned).toEqual([]);
    // Control: any other failure keeps the anchor's own name.
    report = { ok: false, problem: { reason: 'link', seq: 3n } };
    await cut.check.run();
    expect(cut.alarms().at(-1)).toEqual({ what: 'anchor', reason: 'link', seq: '3' });
  });

  it('the run’s probe asks each chain’s witnessed heads; one cut back below them is the alarm and the hold', async () => {
    const run = withWitness({
      answers: { [ORG]: { kind: 'failed', problem: { reason: 'cut_back', seq: 5n } }, [OTHER_ORG]: { kind: 'same' } },
    });
    await run.check.run();
    run.pending.set(ORG, [witnessed(5n), witnessed(3n)]);
    await run.check.run();
    expect(run.asked).toEqual([
      { orgId: ORG, from: 1n, heldTo: [5n, 3n] },
      { orgId: OTHER_ORG, from: 1n, heldTo: [] },
    ]);
    expect(run.alarms()).toEqual([{ what: 'witness', reason: 'cut_back', seq: '5' }]);
    expect(run.steps).toContain(`hold ${ORG} cut_back`);
  });

  it('after a refresh, probes at once only the chains given that hold witnessed heads; a cut is the alarm and the hold, the rest wait', async () => {
    const run = withWitness({
      answers: {
        [ORG]: { kind: 'failed', problem: { reason: 'cut_back', seq: 9n } },
        [OTHER_ORG]: { kind: 'failed', problem: { reason: 'link', seq: 2n } },
      },
    });
    // Nothing witnessed: nothing asked.
    await run.check.probeWitnessed([ORG, OTHER_ORG]);
    expect(run.asked).toEqual([]);
    run.pending.set(ORG, [witnessed(9n)]);
    run.pending.set(OTHER_ORG, [witnessed(2n)]);
    await run.check.probeWitnessed([ORG.toUpperCase(), OTHER_ORG]);
    // Never anchored yet: probed from the chain's start, only its heads judged.
    expect(run.asked).toEqual([
      { orgId: ORG, from: 0n, heldTo: [9n] },
      { orgId: OTHER_ORG, from: 0n, heldTo: [2n] },
    ]);
    // Only the witness's finding here; a chain failing otherwise waits for its run, which reads it whole.
    expect(run.alarms()).toEqual([{ what: 'witness', reason: 'cut_back', seq: '9' }]);
    expect(run.steps).toEqual([`hold ${ORG} cut_back`]);
  });

  it('a quick probe that fails is a warning: the run asks the same of every chain', async () => {
    const run = withWitness({ probeFails: true });
    run.pending.set(ORG, [witnessed(9n)]);
    await run.check.probeWitnessed([ORG]);
    expect(run.alarms()).toEqual([]);
    expect(run.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'audit.anchor_check_failed', check: 'probe', chains: 1 }),
    );
  });
});
