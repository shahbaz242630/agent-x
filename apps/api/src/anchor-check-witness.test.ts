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
  /** The platform chain's probe between runs (TR-3): none, the run checks no platform chain. */
  readonly platformProbe?: (heldTo: readonly { seq: bigint }[]) => Promise<{ seq: bigint; hash: Buffer } | undefined>;
}

function withWitness({
  verified = () => ok(1n),
  answers = {},
  probeFails = false,
  stepped,
  platformProbe,
}: Answering = {}) {
  const steps: string[] = [];
  const asked: { orgId: string; from: bigint; heldTo: bigint[] }[] = [];
  const pending = new Map<string, ReturnType<typeof witnessed>[]>();
  const pruned: [string, bigint[]][] = [];
  // The heads each probe released (TR-3): compact, held to by later walks, never let go outright.
  const released: [string, bigint[]][] = [];
  const walkedWith: bigint[][] = [];
  const reads = { fresh: true, refreshed: 0 };
  const lost = new Set<string>();
  // The heads each chain let go for memory, lowest and highest: a walk from below the one to the other sets it aside.
  const marks = new Map<string, { readonly low: bigint; readonly high: bigint }>();
  // Each chain's fingerprints of heads let go (TR-3), and the fingerprints each walkedPast was told were asked.
  const prints = new Map<string, { seq: bigint; hash: Buffer }[]>();
  const toldAsked: bigint[][] = [];
  // Each chain's heads released on a probe's finding, as the log hands them to a walk.
  const releasedHeads = new Map<string, { seq: bigint; hash: Buffer }[]>();
  // The anchor each chain's compact heads went above, as the log keeps it: where a confirming walk starts.
  const bases = new Map<string, { seq: bigint; hash: Buffer }>();
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
    chains:
      platformProbe === undefined
        ? []
        : [{ chain: { kind: 'platform' }, verify: () => Promise.resolve(ok(1n)), probe: platformProbe }],
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
      release: (chain, heads) => {
        released.push([nameOf(chain), heads.map(({ seq }) => seq)]);
      },
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
      walkedPast: (chain, from, to, askedOf) => {
        toldAsked.push(askedOf.map(({ seq }) => seq));
        const mark = marks.get(nameOf(chain));
        const all = (prints.get(nameOf(chain)) ?? []).every((print) => askedOf.some(({ seq }) => seq === print.seq));
        if (mark !== undefined && all && from < mark.low && to >= mark.high) lost.delete(nameOf(chain));
        return lost.has(nameOf(chain));
      },
      baseBelow: (chain, seq) => {
        const base = bases.get(nameOf(chain));
        return base !== undefined && base.seq <= seq ? base : undefined;
      },
      fingerprints: (chain) => [
        ...(lost.has(nameOf(chain)) ? (prints.get(nameOf(chain)) ?? []) : []),
        ...(releasedHeads.get(nameOf(chain)) ?? []),
      ],
    },
  });
  const alarms = () =>
    capture
      .lines()
      .filter((line) => line.event === 'audit.integrity_failed')
      .map(({ check: what, reason, seq }) => ({ what, reason, seq }));
  return {
    check,
    steps,
    asked,
    pending,
    pruned,
    walkedWith,
    reads,
    lost,
    marks,
    prints,
    toldAsked,
    released,
    releasedHeads,
    bases,
    clock,
    anchors,
    alarms,
    capture,
  };
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

  it('TR-3: one whose walk, held to every head still held, ran from below the lowest let go to past the highest anchors, the mark set aside; one short of it waits', async () => {
    const run = withWitness({ verified: (orgId) => ok(orgId === ORG ? 9n : 1n) });
    run.lost.add(ORG);
    // Let go from 3 to 9: a walk from the chain's start (0) to 9 passes them all.
    run.marks.set(ORG, { low: 3n, high: 10n });
    await run.check.run();
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })).toBeUndefined();
    run.marks.set(ORG, { low: 3n, high: 9n });
    await run.check.run();
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })?.seq).toBe(9n);
    expect(run.lost.has(ORG)).toBe(false);
  });

  it('TR-3: the walk is held to the fingerprints of heads let go as to heads, and told them, so the mark goes only with them all', async () => {
    const run = withWitness({ verified: (orgId) => ok(orgId === ORG ? 9n : 1n) });
    run.lost.add(ORG);
    run.marks.set(ORG, { low: 3n, high: 6n });
    run.prints.set(ORG, [
      { seq: 3n, hash: Buffer.alloc(8, 3) },
      { seq: 6n, hash: Buffer.alloc(8, 6) },
    ]);
    run.pending.set(ORG, [witnessed(8n)]);
    await run.check.run();
    expect(run.walkedWith[0]).toEqual([8n, 3n, 6n]);
    expect(run.toldAsked[0]).toEqual([8n, 3n, 6n]);
    expect(run.anchors.latest({ kind: 'organisation', orgId: ORG })?.seq).toBe(9n);
    expect(run.lost.has(ORG)).toBe(false);
    // Released heads alone (nothing let go for memory): the walk is held to them and told them too, so it lets them go.
    const released = withWitness({ verified: (orgId) => ok(orgId === ORG ? 9n : 1n) });
    released.releasedHeads.set(ORG, [{ seq: 4n, hash: Buffer.alloc(16, 4) }]);
    await released.check.run();
    expect(released.walkedWith[0]).toEqual([4n]);
    expect(released.toldAsked[0]).toEqual([4n]);
    expect(released.anchors.latest({ kind: 'organisation', orgId: ORG })?.seq).toBe(9n);
  });

  it('TR-3: the platform chain is probed between runs too: on the chain, all but its highest head let go; cut below one, the alarm; a miss, a warning', async () => {
    let answer: { seq: bigint; hash: Buffer } | undefined | 'fails';
    const probed: bigint[][] = [];
    const run = withWitness({
      platformProbe: (heldTo) => {
        probed.push(heldTo.map(({ seq }) => seq));
        return answer === 'fails' ? Promise.reject(new Error('database away')) : Promise.resolve(answer);
      },
    });
    // Nothing witnessed on it: not asked.
    await run.check.probeWitnessed([]);
    expect(probed).toEqual([]);
    run.pending.set('platform', [witnessed(9n), witnessed(4n)]);
    await run.check.probeWitnessed([]);
    expect(probed).toEqual([[9n, 4n]]);
    expect(run.released).toEqual([['platform', [4n]]]);
    expect(run.pruned).toEqual([]);
    answer = witnessed(9n);
    await run.check.probeWitnessed([]);
    expect(run.capture.lines()).toContainEqual(
      expect.objectContaining({
        event: 'audit.integrity_failed',
        chain: 'platform',
        check: 'witness',
        reason: 'cut_back',
        seq: '9',
      }),
    );
    expect(run.released).toHaveLength(1);
    answer = 'fails';
    await run.check.probeWitnessed([]);
    expect(run.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'audit.anchor_check_failed', chain: 'platform', check: 'probe' }),
    );
  });

  it('TR-3: after a refresh, a probe that finds every head held on the chain lets go all but the highest; a failed or missed one, none', async () => {
    const run = withWitness({
      answers: {
        [ORG]: { kind: 'moved' },
        [OTHER_ORG]: { kind: 'failed', problem: { reason: 'link', seq: 2n } },
      },
    });
    run.pending.set(ORG, [witnessed(9n), witnessed(4n), witnessed(2n)]);
    run.pending.set(OTHER_ORG, [witnessed(5n), witnessed(2n)]);
    await run.check.probeWitnessed([ORG, OTHER_ORG]);
    expect(run.released).toEqual([[ORG, [4n, 2n]]]);
    expect(run.pruned).toEqual([]);
    // A chain the probe didn't answer for: nothing let go.
    const missed = withWitness({ answers: { [ORG]: { kind: 'missed', error: new Error('away') } } });
    missed.pending.set(ORG, [witnessed(9n), witnessed(4n)]);
    await missed.check.probeWitnessed([ORG]);
    expect(missed.released).toEqual([]);
    // Heads at or below the anchor wait for their own linked walk: never released on a probe.
    const anchored = withWitness({ answers: { [ORG]: { kind: 'moved' } } });
    anchored.anchors.keep(signAnchor(keys, { kind: 'organisation', orgId: ORG }, point(5n), AT));
    anchored.pending.set(ORG, [witnessed(9n), witnessed(7n), witnessed(4n), witnessed(3n)]);
    await anchored.check.probeWitnessed([ORG]);
    expect(anchored.released).toEqual([[ORG, [7n]]]);
    // One head alone: kept, as it stands for the chain's length.
    const one = withWitness({ answers: { [ORG]: { kind: 'same' } } });
    one.pending.set(ORG, [witnessed(9n)]);
    await one.check.probeWitnessed([ORG]);
    expect(one.released).toEqual([]);
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
        // The event's whole hash, as a read gives it: a compact head's (TR-3) its first bytes, the rest the event's own.
        const whole = Buffer.concat([head.hash, Buffer.alloc(32 - head.hash.length, 0xee)]);
        if (head.seq <= seq) watch?.found.set(head.seq, head.seq === forkAt ? Buffer.alloc(32, 99) : whole);
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

  it('TR-3: a head released at or below the anchor that no anchoring walk passed (a restart, a new leader) is walked from the chain’s start to the anchor, by its first bytes: on the chain, let go; another event there, the alarm; not walked, kept and said', async () => {
    const run = anchoredElsewhere(walkingTo(() => true));
    run.releasedHeads.set(ORG, [{ seq: 4n, hash: Buffer.alloc(16, 4) }]);
    await run.check.run();
    expect(run.steps.filter((step) => step.startsWith(`confirm ${ORG}`))).toEqual([`confirm ${ORG} 0`]);
    expect(run.toldAsked).toContainEqual([4n]);
    expect(run.alarms()).toEqual([]);
    const forked = anchoredElsewhere(walkingTo(() => true, 2_000n, 4n));
    forked.releasedHeads.set(ORG, [{ seq: 4n, hash: Buffer.alloc(16, 4) }]);
    await forked.check.run();
    expect(forked.alarms()).toEqual([{ what: 'witness', reason: 'cut_back', seq: '4' }]);
    expect(forked.steps).toContain(`hold ${ORG} cut_back`);
    const waiting = anchoredElsewhere();
    waiting.releasedHeads.set(ORG, [{ seq: 4n, hash: Buffer.alloc(16, 4) }]);
    await waiting.check.run();
    expect(waiting.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'error', event: 'audit.witness_head_unconfirmed', orgId: ORG, heads: 1 }),
    );
    expect(waiting.toldAsked).not.toContainEqual([4n]);
  });

  it('TR-3: the walk confirming a compact head starts from the anchor the log kept it went above, not the chain’s first event; one kept above it, never', async () => {
    const run = anchoredElsewhere(walkingTo(() => true));
    run.releasedHeads.set(ORG, [{ seq: 4n, hash: Buffer.alloc(16, 4) }]);
    run.bases.set(ORG, point(2n));
    await run.check.run();
    expect(run.steps.filter((step) => step.startsWith(`confirm ${ORG}`))).toEqual([`confirm ${ORG} 2`]);
    expect(run.toldAsked).toContainEqual([4n]);
    // A base above the lowest compact head is no start for it: from the chain's start.
    const above = anchoredElsewhere(walkingTo(() => true));
    above.releasedHeads.set(ORG, [{ seq: 4n, hash: Buffer.alloc(16, 4) }]);
    above.bases.set(ORG, point(5n));
    await above.check.run();
    expect(above.steps.filter((step) => step.startsWith(`confirm ${ORG}`))).toEqual([`confirm ${ORG} 0`]);
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
