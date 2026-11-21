// TR-1 F.1 (S209): the path frontier and the walk within a transaction, on a chain sealed in memory. The plan's test:
// a row put back at a witnessed place from another branch fails the walk (row mixing); the positive control, a genuine
// extension, passes. With the frontier's own rules: where a walk starts, how far it is raised, what sets it aside.
import {
  appendEvents,
  type Chain,
  CHAIN_START,
  type ChainEdges,
  type ChainHead,
  type CheckedPoint,
  type HeadSeen,
  LAST_COUNTED,
  type StoredEntry,
} from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { describe, expect, it } from 'vitest';

import {
  createChainFrontier,
  type FrontierStart,
  judgeWitnessed,
  type ReadAhead,
  type WalkedWithin,
  walkWithin,
} from './chain-frontier.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const CHAIN: Chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-00000000f001' };
const AT = new Date('2026-11-21T08:00:00.000Z');

/** A chain's events and head, sealed as the app seals them, grown one event at a time. */
class Sealed {
  head: ChainHead | undefined;
  rows: StoredEntry[] = [];

  async grow(count: number, label = 'event'): Promise<this> {
    for (let n = 0; n < count; n += 1) {
      const seq = (this.head?.seq ?? 0n) + 1n;
      const content = ['action', `${label}.${seq.toString()}`] as const;
      const [sealed] = await appendEvents(
        keys,
        CHAIN,
        {
          lockHead: () => Promise.resolve(this.head && { head: this.head, now: AT }),
          start: (head) => {
            this.head = head;
            return Promise.resolve();
          },
          appendAll: ([event], head) => {
            if (event !== undefined) this.rows.push({ ...event, content: [...content] });
            this.head = head;
            return Promise.resolve(true);
          },
        },
        [{ nextId: () => `0199a0f0-0000-7000-8000-${seq.toString().padStart(12, '0')}`, content: [...content] }],
      );
      if (sealed === undefined) throw new Error('sealed one');
    }
    return this;
  }

  /** The chain as it stood at `seq`, cut back there: its rows to it and the head sealed then. */
  async cutTo(seq: bigint): Promise<Sealed> {
    const cut = new Sealed();
    await cut.grow(Number(seq));
    return cut;
  }

  point(seq: bigint): CheckedPoint {
    if (seq === 0n) return CHAIN_START;
    const row = this.rows.find((each) => each.seq === seq);
    if (row === undefined) throw new Error(`no event ${seq.toString()}`);
    return { seq, hash: row.hash, macKeyVersion: row.macKeyVersion };
  }

  witnessed(seq: bigint): HeadSeen {
    const { hash } = this.point(seq);
    return { seq, hash };
  }

  edges(anchored: bigint): ChainEdges {
    const head = this.head ?? 'none';
    const seqs = this.rows.map(({ seq }) => seq);
    return {
      head,
      lowest: seqs[0] ?? null,
      highest: seqs.at(-1) ?? null,
      headEventHash: typeof head === 'string' ? undefined : this.rows.find(({ seq }) => seq === head.seq)?.hash,
      anchored: this.rows.find(({ seq }) => seq === anchored),
      lastStored: BigInt(
        this.rows.filter(({ seq }) => typeof head !== 'string' && seq > head.seq - BigInt(LAST_COUNTED)).length,
      ),
    };
  }

  /** The events after `from`, as walkWithin's statement reads them. */
  after(from: bigint): ReadAhead[] {
    return this.rows.filter(({ seq }) => seq > from).map((entry) => ({ seq: entry.seq, entry }));
  }

  walk(from: CheckedPoint, most?: number) {
    return walkWithin(keys, CHAIN, this.edges(from.seq), this.after(from.seq), from, most);
  }
}

/** A walk that reached the head, as the test expects. */
function walked(walk: Awaited<ReturnType<Sealed['walk']>>): WalkedWithin {
  if (walk.kind !== 'walked') throw new Error(`the walk should reach the head: ${walk.kind}`);
  return walk;
}

const startAt = (point: CheckedPoint): FrontierStart => ({ base: point, hashes: Buffer.alloc(0), from: point, at: 0 });

describe('TR-1 F.1 the walk within a transaction and the path frontier', () => {
  it('a row put back at a witnessed place from another branch fails the judgement; a genuine extension passes', async () => {
    // The honest chain: an anchor at 4, a stop witnessed at 7 by another copy.
    const honest = await new Sealed().grow(9);
    const stop = honest.witnessed(7n);
    const anchor = honest.point(4n);

    // Positive control: the chain grows on (a genuine extension), and the stop is on the walk from the anchor.
    const extended = walked(await honest.walk(anchor));
    expect(extended.head.seq).toBe(9n);
    expect(judgeWitnessed([stop], startAt(anchor), extended, 'cut')).toEqual({ kind: 'held' });

    // The attack: cut back to 5, a stale copy writes 6'–9', the owner puts the honest row 7 back at 7.
    const forked = await (await honest.cutTo(5n)).grow(4, 'stale');
    const honestSeven = honest.rows.find(({ seq }) => seq === 7n);
    const mixedChain = Object.assign(new Sealed(), {
      head: forked.head,
      rows: forked.rows.map((row) => (row.seq === 7n ? (honestSeven ?? row) : row)),
    });
    // Every one-row check passes: the row at 7 holds the stop's own hash.
    expect(mixedChain.point(7n).hash.equals(stop.hash)).toBe(true);
    // The walk re-hashes 6'→7: 7's link to 6' fails.
    expect(await mixedChain.walk(anchor)).toMatchObject({ kind: 'broken' });
    // Without the row put back, the walk holds, and the stop is off its path: the cut, at the stop.
    const cut = walked(await forked.walk(anchor));
    expect(judgeWitnessed([stop], startAt(anchor), cut, 'cut')).toEqual({ kind: 'cut', seq: 7n });
  });

  it('a head above the head reached is a cut in Tx A, and one to judge in the gate', async () => {
    const chain = await new Sealed().grow(5);
    const above = { seq: 8n, hash: Buffer.alloc(32, 8) };
    const walk = walked(await chain.walk(CHAIN_START));
    expect(judgeWitnessed([above], startAt(CHAIN_START), walk, 'cut')).toEqual({ kind: 'cut', seq: 8n });
    expect(judgeWitnessed([above], startAt(CHAIN_START), walk, 'unjudged')).toEqual({ kind: 'unjudged', seqs: [8n] });
    // A cut and one to judge: the cut stands, at the highest head off the path.
    const offPath = [above, { seq: 3n, hash: Buffer.alloc(32) }, { seq: 4n, hash: Buffer.alloc(32) }];
    expect(judgeWitnessed(offPath, startAt(CHAIN_START), walk, 'unjudged')).toEqual({ kind: 'cut', seq: 4n });
    // The head itself, and where the walk began, judged by their own hashes.
    expect(
      judgeWitnessed([chain.witnessed(5n)], startAt(chain.point(2n)), walked(await chain.walk(chain.point(2n))), 'cut'),
    ).toEqual({ kind: 'held' });
    expect(
      judgeWitnessed(
        [{ seq: 2n, hash: Buffer.alloc(32) }],
        startAt(chain.point(2n)),
        walked(await chain.walk(chain.point(2n))),
        'cut',
      ),
    ).toEqual({ kind: 'cut', seq: 2n });
  });

  it('more than the walk may take is too far, never a walk short of the head', async () => {
    const chain = await new Sealed().grow(6);
    expect(await chain.walk(chain.point(2n), 3)).toEqual({ kind: 'too_far' });
    expect(walked(await chain.walk(chain.point(2n), 4)).head.seq).toBe(6n);
    // An event missing in the middle: a gap, not a shorter walk.
    const holed = Object.assign(new Sealed(), { head: chain.head, rows: chain.rows.filter(({ seq }) => seq !== 4n) });
    expect(await holed.walk(chain.point(2n))).toMatchObject({ kind: 'broken' });
  });

  it('starts at the anchor, is raised by a walk, judges heads below F on the stretch it kept, and trims to a later anchor', async () => {
    const chain = await new Sealed().grow(12);
    const latest: { anchor: CheckedPoint | undefined } = { anchor: undefined };
    const frontier = createChainFrontier({
      anchors: { latest: () => latest.anchor, rebasedAfter: () => false },
      now: () => AT,
      mostKept: 6,
    });
    expect(frontier.startOf(CHAIN)).toBeUndefined();
    latest.anchor = chain.point(3n);
    const first = frontier.startOf(CHAIN);
    expect(first?.from.seq).toBe(3n);
    if (first === undefined) throw new Error('started');
    frontier.raise(CHAIN, first, walked(await chain.walk(first.from)));
    const second = frontier.startOf(CHAIN);
    expect(second?.from.seq).toBe(12n);
    if (second === undefined) throw new Error('raised');
    // A head below F is judged on the stretch kept: on it, held; another hash there, the cut.
    const nothingNew = walked(await chain.walk(second.from));
    expect(judgeWitnessed([chain.witnessed(6n)], second, nothingNew, 'cut')).toEqual({ kind: 'held' });
    expect(judgeWitnessed([{ seq: 6n, hash: Buffer.alloc(32) }], second, nothingNew, 'cut')).toEqual({
      kind: 'cut',
      seq: 6n,
    });
    // A later anchor on the stretch, the stretch past what it keeps: trimmed to the anchor, F kept.
    latest.anchor = chain.point(8n);
    const trimmed = frontier.startOf(CHAIN);
    expect(trimmed).toMatchObject({ base: { seq: 8n }, from: { seq: 12n } });
    expect(trimmed?.hashes.length).toBe(4 * 32);
    // A lower raise never moves F back.
    if (trimmed === undefined) throw new Error('trimmed');
    frontier.raise(CHAIN, first, walked(await (await chain.cutTo(10n)).walk(first.from)));
    expect(frontier.startOf(CHAIN)?.from.seq).toBe(12n);
  });

  it('goes back to the anchor once it moves past F, is off the stretch, or a rebase is dated after the stretch began', async () => {
    const chain = await new Sealed().grow(10);
    const latest: { anchor: CheckedPoint | undefined; rebasedAt: number | undefined } = {
      anchor: chain.point(2n),
      rebasedAt: undefined,
    };
    const clock = { at: AT.getTime() };
    const frontier = createChainFrontier({
      anchors: {
        latest: () => latest.anchor,
        rebasedAfter: (_chain, at) => latest.rebasedAt !== undefined && latest.rebasedAt > at.getTime(),
      },
      now: () => new Date(clock.at),
    });
    const raise = async (): Promise<void> => {
      const start = frontier.startOf(CHAIN);
      if (start === undefined) throw new Error('anchored');
      frontier.raise(CHAIN, start, walked(await chain.walk(start.from)));
    };
    await raise();
    // A rebase dated at the stretch's start sets nothing aside (strictly after); a moment later, it does.
    latest.rebasedAt = clock.at;
    expect(frontier.startOf(CHAIN)?.from.seq).toBe(10n);
    latest.rebasedAt = clock.at + 1;
    clock.at += 10;
    expect(frontier.startOf(CHAIN)?.from.seq).toBe(2n);
    // Raised again after the rebase: it stands, its stretch begun after.
    await raise();
    expect(frontier.startOf(CHAIN)?.from.seq).toBe(10n);
    // An anchor off the stretch: another walk read another chain there.
    latest.anchor = { ...chain.point(5n), hash: Buffer.alloc(32, 7) };
    expect(frontier.startOf(CHAIN)?.from.seq).toBe(5n);
    // An anchor past F.
    latest.anchor = chain.point(2n);
    await raise();
    const grown = await new Sealed().grow(14);
    latest.anchor = grown.point(13n);
    expect(frontier.startOf(CHAIN)?.from.seq).toBe(13n);
  });

  it('keeps its stretch below a later anchor while it is short: a head witnessed late below the anchor is judged on it', async () => {
    const chain = await new Sealed().grow(10);
    const latest = { anchor: chain.point(2n) };
    const frontier = createChainFrontier({
      anchors: { latest: () => latest.anchor, rebasedAfter: () => false },
      now: () => AT,
    });
    const first = frontier.startOf(CHAIN);
    if (first === undefined) throw new Error('anchored');
    frontier.raise(CHAIN, first, walked(await chain.walk(first.from)));
    latest.anchor = chain.point(8n);
    const start = frontier.startOf(CHAIN);
    expect(start).toMatchObject({ base: { seq: 2n }, from: { seq: 10n } });
    if (start === undefined) throw new Error('kept');
    const walk = walked(await chain.walk(start.from));
    expect(judgeWitnessed([chain.witnessed(5n)], start, walk, 'cut')).toEqual({ kind: 'held' });
    expect(judgeWitnessed([{ seq: 5n, hash: Buffer.alloc(32) }], start, walk, 'cut')).toEqual({ kind: 'cut', seq: 5n });
    // Below where the stretch began: nothing to place it on.
    expect(judgeWitnessed([chain.witnessed(1n)], start, walk, 'cut')).toEqual({ kind: 'unjudged', seqs: [1n] });
  });

  it('keeps no stretch past its memory, and none with a hole: the next walk starts from the anchor again', async () => {
    const chain = await new Sealed().grow(8);
    const frontier = createChainFrontier({
      anchors: { latest: () => chain.point(1n), rebasedAfter: () => false },
      now: () => AT,
      mostBytes: 4 * 32,
    });
    const start = frontier.startOf(CHAIN);
    if (start === undefined) throw new Error('anchored');
    const walk = walked(await chain.walk(start.from));
    frontier.raise(CHAIN, start, walk);
    expect(frontier.startOf(CHAIN)?.from.seq).toBe(1n);
    const roomy = createChainFrontier({
      anchors: { latest: () => chain.point(1n), rebasedAfter: () => false },
      now: () => AT,
    });
    const holed = new Map(walk.path);
    holed.delete(5n);
    const from = roomy.startOf(CHAIN);
    if (from === undefined) throw new Error('anchored');
    roomy.raise(CHAIN, from, { ...walk, path: holed });
    expect(roomy.startOf(CHAIN)?.from.seq).toBe(1n);
    roomy.raise(CHAIN, from, walk);
    expect(roomy.startOf(CHAIN)?.from.seq).toBe(8n);
  });
});
