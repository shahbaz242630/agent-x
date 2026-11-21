// The anchor check held to the witness log (TR-1): every probe asks the heads copies witnessed above each chain's
// anchor, a chain cut back below one is the alarm (`check: witness`) and its hold, a walk that missed one anchors
// nothing, the heads are let go once anchored past, and the leader probes at once the chains a refresh gave a head.
import {
  type Chain,
  type ChainReport,
  type ChainStep,
  type CheckedPoint,
  createMemoryAnchorStore,
  signAnchor,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import {
  createAnchorCheck,
  type OrganisationChains,
  type ProbeAnswer,
  type RecentPlaces,
  type WatchedPlaces,
} from './anchor-check.ts';

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
const witnessed = (seq: bigint, fill = Number(seq)) => ({ seq, hash: Buffer.alloc(32, fill), at: AT.getTime() });

interface Asked {
  readonly orgId: string;
  readonly from: CheckedPoint;
  readonly heldTo?: readonly { seq: bigint }[];
}

/** How a test's check answers. */
interface Answering {
  readonly verified?: (orgId: string, recent?: RecentPlaces) => ChainReport;
  /** One step of a walk from a head towards the anchor (the trail's passStep); none, the chains have no `confirm`. */
  readonly stepped?: (cursor: CheckedPoint, target: CheckedPoint, watch?: WatchedPlaces) => ChainStep;
  readonly answers?: Readonly<Record<string, ProbeAnswer>>;
  readonly probeFails?: boolean;
}

function withWitness({ verified = () => ok(1n), answers = {}, probeFails = false, stepped }: Answering = {}) {
  const steps: string[] = [];
  const asked: { orgId: string; from: bigint; heldTo: bigint[] }[] = [];
  const pending = new Map<string, ReturnType<typeof witnessed>[]>();
  const pruned: [string, bigint[]][] = [];
  const walkedWith: bigint[][] = [];
  const reads = { fresh: true, refreshed: 0 };
  const lost = new Set<string>();
  const clock = new FixedClock(AT);
  const nameOf = (chain: Chain) => (chain.kind === 'platform' ? 'platform' : chain.orgId);
  const organizations: OrganisationChains = {
    list: () => Promise.resolve([ORG, OTHER_ORG]),
    recorded: () => Promise.resolve([ORG, OTHER_ORG]),
    verify: (orgId, _anchor, heldTo = [], recent) => {
      steps.push(`verify ${orgId}`);
      walkedWith.push(heldTo.map(({ seq }) => seq));
      return Promise.resolve(verified(orgId, recent));
    },
    hold: (orgId, failure) => {
      if (failure !== undefined) steps.push(`hold ${orgId} ${failure}`);
      return Promise.resolve();
    },
    ...(stepped === undefined
      ? {}
      : {
          confirm: (orgId: string, cursor: CheckedPoint, target: CheckedPoint, watch?: WatchedPlaces) => {
            steps.push(`confirm ${orgId} ${cursor.seq.toString()}`);
            return Promise.resolve(stepped(cursor, target, watch));
          },
        }),
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
    clock,
    logger: testLogger(capture),
    staleAfterMs: 900_000,
    deadlineMs: 120_000,
    anchors,
    shuffled: (orgIds) => orgIds,
    lanes: 1,
    witness: {
      pending: (chain) => pending.get(nameOf(chain)) ?? [],
      prune: (chain, heads) => {
        pruned.push([nameOf(chain), heads.map(({ seq }) => seq)]);
      },
      refresh: () => {
        reads.refreshed += 1;
        return Promise.resolve([]);
      },
      // A read that began with the run, or one from before it (stale).
      freshAt: () => (reads.fresh ? clock.now() : new Date(AT.getTime() - 1)),
      beyondMemory: (chain) => lost.has(nameOf(chain)),
    },
  });
  const alarms = () =>
    capture
      .lines()
      .filter((line) => line.event === 'audit.integrity_failed')
      .map(({ check: what, reason, seq }) => ({ what, reason, seq }));
  return { check, steps, asked, pending, pruned, walkedWith, reads, lost, clock, anchors, alarms, capture };
}

describe('TR-1 the anchor check held to the witness log', () => {
  it('a walk that holds anchors and lets go the heads at or below it; one that missed a witnessed head is the alarm, never anchored', async () => {
    const run = withWitness({ verified: (orgId) => ok(orgId === ORG ? 9n : 1n) });
    // Asked of the walk: 4 and 9, above where it began (the chain's start), at or below where it reached; 2 too.
    run.pending.set(ORG, [witnessed(9n), witnessed(4n), witnessed(2n)]);
    await run.check.run();
    // A read from the run's own start: no read waited for before signing.
    expect(run.reads.refreshed).toBe(0);
    expect(run.walkedWith[0]).toEqual([9n, 4n, 2n]);
    expect(run.pruned).toEqual([
      [ORG, [9n, 4n, 2n]],
      [OTHER_ORG, []],
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

  it('a walk anchors only on a read of the witness log begun after it did: one is waited for before signing, and a stale one anchors and lets go nothing', async () => {
    const run = withWitness();
    run.reads.fresh = false;
    run.pending.set(ORG, [witnessed(1n)]);
    await run.check.run();
    // One read waited for each walk that would anchor anew.
    expect(run.reads.refreshed).toBe(2);
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })).toBeUndefined();
    expect(run.pruned).toEqual([]);
    run.reads.fresh = true;
    await run.check.run();
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })?.seq).toBe(1n);
    expect(run.pruned).toContainEqual([ORG, [1n]]);
  });

  it('a head read in during the walk, at or below where it reached, holds the anchor back to the next run; only those asked are let go', async () => {
    let landed = false;
    const lateHead = witnessed(1n);
    const run = withWitness({
      verified: () => {
        // Another copy's head lands while the walk runs: never asked of it.
        if (!landed) run.pending.set(ORG, [lateHead]);
        landed = true;
        return ok(1n);
      },
    });
    await run.check.run();
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })).toBeUndefined();
    expect(run.pruned).toEqual([[OTHER_ORG, []]]);
    await run.check.run();
    expect(run.walkedWith.at(-2)).toEqual([1n]);
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })?.seq).toBe(1n);
  });

  it('a chain that let a head go for memory is anchored no more, said each time; others anchor', async () => {
    const run = withWitness();
    run.lost.add(ORG);
    await run.check.run();
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })).toBeUndefined();
    expect(run.anchors.latest({ kind: 'organisation', orgId: OTHER_ORG })?.seq).toBe(1n);
    expect(run.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'error', event: 'audit.witness_beyond_memory', orgId: ORG }),
    );
  });

  /** ORG walked to 5 and anchored here, its walk keeping the hashes of 4 and 5 (recorded within its window). */
  const anchoredAtFive = async () => {
    const run = withWitness({
      verified: (orgId, recent) => {
        if (orgId !== ORG) return ok(1n);
        recent?.found.set(4n, Buffer.alloc(32, 4));
        recent?.found.set(5n, Buffer.alloc(32, 5));
        return ok(5n);
      },
    });
    await run.check.run();
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })?.seq).toBe(5n);
    run.pruned.length = 0;
    return run;
  };

  it('a head landing after this copy anchored, at or below the anchor, is held to the hash its walk read there: the same, let go', async () => {
    const run = await anchoredAtFive();
    run.pending.set(ORG, [witnessed(4n)]);
    await run.check.run();
    expect(run.pruned).toContainEqual([ORG, [4n]]);
    expect(run.alarms()).toEqual([]);
  });

  it('another event there is a fork: the alarm and the hold, never let go', async () => {
    const run = await anchoredAtFive();
    run.pending.set(ORG, [witnessed(4n, 44)]);
    await run.check.run();
    expect(run.alarms()).toEqual([{ what: 'witness', reason: 'cut_back', seq: '4' }]);
    expect(run.steps).toContain(`hold ${ORG} cut_back`);
    expect(run.pruned).not.toContainEqual([ORG, [4n]]);
  });

  /**
   * A walk from a head towards the anchor: where `onChain`, at most `most` events a step, each watched place holding its
   * head's own hash (or `forkAt`'s another); else broken at the next place.
   */
  const walkingTo =
    (onChain: (cursor: CheckedPoint) => boolean, most = 2_000n, forkAt?: bigint) =>
    (cursor: CheckedPoint, target: CheckedPoint, watch?: WatchedPlaces): ChainStep => {
      if (!onChain(cursor)) return { ok: false, problem: { reason: 'link', seq: cursor.seq + 1n } };
      const seq = target.seq < cursor.seq + most ? target.seq : cursor.seq + most;
      for (const head of watch?.heads ?? []) {
        if (head.seq <= seq) watch?.found.set(head.seq, head.seq === forkAt ? Buffer.alloc(32, 99) : head.hash);
      }
      return seq === target.seq
        ? { ok: true, seq, hash: target.hash, macKeyVersion: target.macKeyVersion, to: target.seq }
        : { ok: true, seq, hash: Buffer.alloc(32, Number(seq % 200n)), macKeyVersion: 1, to: target.seq };
    };

  /** ORG anchored at 5 by another copy (or before a restart): this process kept no hashes of its walk. */
  const anchoredElsewhere = (stepped?: Answering['stepped']) => {
    const run = withWitness({
      answers: { [ORG]: { kind: 'same' }, [OTHER_ORG]: { kind: 'same' } },
      ...(stepped === undefined ? {} : { stepped }),
    });
    run.anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(5n), AT));
    return run;
  };

  it('a head below an anchor this process didn’t make (a restart, another copy’s) is walked from to the anchor: on the chain, let go', async () => {
    const run = anchoredElsewhere(walkingTo(() => true));
    run.pending.set(ORG, [witnessed(4n)]);
    await run.check.run();
    expect(run.steps).toContain(`confirm ${ORG} 4`);
    expect(run.pruned).toContainEqual([ORG, [4n]]);
    expect(run.alarms()).toEqual([]);
  });

  it('a head older than the walk kept, or below another copy’s anchor, that doesn’t run to the anchor: the alarm and the hold', async () => {
    const run = anchoredElsewhere(walkingTo(() => false));
    run.pending.set(ORG, [witnessed(4n, 44)]);
    await run.check.run();
    expect(run.alarms()).toEqual([{ what: 'witness', reason: 'cut_back', seq: '4' }]);
    expect(run.steps).toContain(`hold ${ORG} cut_back`);
    // Anchored here, its hash older than the walk kept: walked too, never let go as late.
    const here = await anchoredAtFive();
    here.pending.set(ORG, [witnessed(2n)]);
    await here.check.run();
    expect(here.alarms()).toEqual([]);
    expect(here.pruned).not.toContainEqual([ORG, [2n]]);
    expect(here.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'error', event: 'audit.witness_head_unconfirmed', orgId: ORG }),
    );
  });

  it('one that can’t be walked (no way to, or the walk failing) is kept, said, and the chain anchored no more until it is', async () => {
    const run = anchoredElsewhere();
    run.pending.set(ORG, [witnessed(4n)]);
    // A walk to anchor it anew at 9 would otherwise go through.
    const moved = withWitness({ verified: (orgId) => ok(orgId === ORG ? 9n : 1n) });
    moved.anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(5n), AT));
    moved.pending.set(ORG, [witnessed(4n)]);
    await moved.check.run();
    expect(moved.anchors.latest({ kind: 'organisation', orgId: ORG })?.seq).toBe(5n);
    expect(moved.pruned).not.toContainEqual([ORG, [4n]]);
    expect(moved.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'error', event: 'audit.witness_head_unconfirmed', orgId: ORG, heads: 1 }),
    );
    await run.check.run();
    expect(run.pruned).not.toContainEqual([ORG, [4n]]);
    expect(run.alarms()).toEqual([]);
    // A walk that throws: a warning, kept as well.
    const failing = anchoredElsewhere(() => {
      throw new Error('database away');
    });
    failing.pending.set(ORG, [witnessed(4n)]);
    await failing.check.run();
    expect(failing.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'audit.anchor_check_failed', check: 'witness' }),
    );
    expect(failing.pruned).not.toContainEqual([ORG, [4n]]);
  });

  it('one walk a chain, from its lowest held head, checks every other head on the way: a place holding another event is the alarm', async () => {
    const run = anchoredElsewhere(walkingTo(() => true));
    run.pending.set(ORG, [witnessed(5n), witnessed(4n), witnessed(2n)]);
    await run.check.run();
    expect(run.steps.filter((step) => step.startsWith('confirm'))).toEqual([`confirm ${ORG} 2`]);
    expect(run.pruned).toContainEqual([ORG, [5n, 4n, 2n]]);
    const forked = anchoredElsewhere(walkingTo(() => true, 2_000n, 4n));
    forked.pending.set(ORG, [witnessed(4n), witnessed(2n)]);
    await forked.check.run();
    expect(forked.alarms()).toEqual([{ what: 'witness', reason: 'cut_back', seq: '2' }]);
  });

  it('a deep walk goes on from where it reached at the next run, within each run’s budget, and holds the chain unanchored meanwhile', async () => {
    const deep = withWitness({
      answers: { [ORG]: { kind: 'same' }, [OTHER_ORG]: { kind: 'same' } },
      stepped: walkingTo(() => true),
    });
    deep.anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(450_005n), AT));
    deep.pending.set(ORG, [witnessed(5n)]);
    await deep.check.run();
    const confirms = () => deep.steps.filter((step) => step.startsWith(`confirm ${ORG}`));
    // A run's budget: 200,000 events, a hundred steps.
    expect(confirms()).toHaveLength(100);
    expect(deep.capture.lines()).toContainEqual(
      expect.objectContaining({ event: 'audit.witness_head_unconfirmed', walkedTo: '200005' }),
    );
    await deep.check.run();
    expect(confirms().at(100)).toBe(`confirm ${ORG} 200005`);
    expect(deep.pruned).not.toContainEqual([ORG, [5n]]);
    await deep.check.run();
    expect(deep.pruned).toContainEqual([ORG, [5n]]);
    expect(deep.alarms()).toEqual([]);
    // A head below where it reached that came in since starts it afresh, from that head.
    const fresh = withWitness({ answers: { [ORG]: { kind: 'same' } }, stepped: walkingTo(() => true) });
    fresh.anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(450_005n), AT));
    fresh.pending.set(ORG, [witnessed(5n)]);
    await fresh.check.run();
    fresh.pending.set(ORG, [witnessed(5n), witnessed(3n)]);
    await fresh.check.run();
    expect(fresh.steps.filter((step) => step.startsWith(`confirm ${ORG}`)).at(100)).toBe(`confirm ${ORG} 3`);
  });

  /** ORG deep below its anchor, first in the run's order; OTHER_ORG's head `depth` events below its own. */
  const deepThenShallow = (depth: bigint) => {
    const top = 5n + depth;
    const run = withWitness({
      answers: { [ORG]: { kind: 'same' }, [OTHER_ORG]: { kind: 'same' } },
      verified: (orgId) => ok(orgId === ORG ? 450_005n : top),
      stepped: walkingTo(() => true),
    });
    run.anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(450_005n), AT));
    run.anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: OTHER_ORG }, point(top), AT));
    run.pending.set(ORG, [witnessed(5n)]);
    run.pending.set(OTHER_ORG, [witnessed(5n)]);
    return run;
  };

  it('a deep chain early in the run’s order starves none after it: each takes its floor of the budget', async () => {
    const run = deepThenShallow(4_000n);
    await run.check.run();
    expect(run.steps.filter((step) => step.startsWith(`confirm ${ORG}`))).toHaveLength(100);
    expect(run.pruned).toContainEqual([OTHER_ORG, [5n]]);
    expect(run.pruned).not.toContainEqual([ORG, [5n]]);
    // Both deep, both walking as the next run begins: an even share each, whatever the order.
    const both = deepThenShallow(450_000n);
    await both.check.run();
    const count = (orgId: string) => both.steps.filter((step) => step.startsWith(`confirm ${orgId}`)).length;
    expect([count(ORG), count(OTHER_ORG)]).toEqual([100, 3]);
    await both.check.run();
    expect([count(ORG), count(OTHER_ORG)]).toEqual([150, 53]);
  });

  it('a hand-off’s first anchor confirms within its own allowance after the run spent its budget', async () => {
    const run = deepThenShallow(8_000n);
    await run.check.run();
    // The run: its floor, three steps, and no more.
    expect(run.steps.filter((step) => step.startsWith(`confirm ${OTHER_ORG}`))).toHaveLength(3);
    expect(run.pruned).not.toContainEqual([OTHER_ORG, [5n]]);
    await run.check.anchorOrganisation(OTHER_ORG);
    expect(run.pruned).toContainEqual([OTHER_ORG, [5n]]);
    expect(run.alarms()).toEqual([]);
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
