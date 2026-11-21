// The path frontier (TR-1 F.1): for each chain, the highest place the jobs copy has proven, by re-hashing every event,
// to descend from a signed anchor, with the hash of each event on the way (`F`, the stretch from the anchor to it).
// A head another copy witnessed (witness-log.ts) is judged against that path, never against one row read on its own:
// the owner can cut a chain back to 100, let a stale copy write 101'–106', and put the original row 105 back at 105,
// and every one-row check then passes (row mixing). Only the walk that re-hashed 101'…106' from the anchor knows that
// 105' and not 105 is on the chain.
//
// Tx A walks from F to the head it locked (walkWithin, on the trip it makes anyway) and raises F there; the next Tx A
// walks only what was written since. F starts at the chain's latest anchor and goes back to it whenever the anchor
// moves past it, is no longer on the stretch kept, or a rebase (chain-rebase --after-restore) is dated after the
// stretch began. The stretch reaches below the latest anchor too, back to where it began, until it holds more than
// `mostKept` events: the jobs copy holds a head witnessed late below the anchor until confirmed (witness-log.ts), and
// one on the stretch is judged at once, not left to wait for the anchor check. Memory: 32 bytes an event, for chains a
// hand-off walked; past `mostBytes` a chain's stretch is not kept (its next Tx A walks from the anchor again: slower,
// never less safe).
import {
  type Chain,
  type ChainEdges,
  type ChainProblem,
  type CheckedPoint,
  type HeadSeen,
  type StoredEntry,
  verifyFromAnchor,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';

/** An event's hash: every stretch keeps them back to back. */
const HASH_BYTES = 32;

/** The most events one walk within Tx A or the gate re-hashes: past it, the chain waits for the anchor check. */
export const MOST_WALKED_WITHIN = 50_000;

/** What the frontier keeps by default, across every chain: past it a chain's stretch is not kept. */
const MOST_FRONTIER_BYTES = 32 * 1024 * 1024;

/**
 * Where a walk starts: F, and the stretch proven from an anchor (`base`) to it, each event's hash after `base`, and
 * when the stretch began (a rebase dated after it sets it aside).
 */
export interface FrontierStart {
  readonly base: CheckedPoint;
  readonly hashes: Buffer;
  readonly from: CheckedPoint;
  readonly at: number;
}

/** What a walk within a transaction found: the head it reached with every hash on the way, or why not. */
export type WithinWalk =
  | { readonly kind: 'walked'; readonly head: CheckedPoint; readonly path: ReadonlyMap<bigint, Buffer> }
  | { readonly kind: 'broken'; readonly problem: ChainProblem }
  | { readonly kind: 'too_far' };

/** The walk's answer once it reached the head. */
export type WalkedWithin = Extract<WithinWalk, { readonly kind: 'walked' }>;

/** How the heads copies witnessed stand against a walk: all on it, one off it (a cut), or some it can't judge. */
export type WitnessJudgement =
  | { readonly kind: 'held' }
  | { readonly kind: 'cut'; readonly seq: bigint }
  | { readonly kind: 'unjudged'; readonly seqs: readonly bigint[] };

/** What the frontier asks of the anchors: each chain's latest, and whether a rebase is dated after a time. */
export interface FrontierAnchors {
  latest(chain: Chain): CheckedPoint | undefined;
  rebasedAfter(chain: Chain, at: Date): boolean;
}

export interface ChainFrontier {
  /** Where the chain's next walk starts: F where it stands, else the latest anchor. None with no anchor yet. */
  startOf(chain: Chain): FrontierStart | undefined;
  /** F raised to where a walk from `start` reached, the stretch kept with it, where that is higher than F now. */
  raise(chain: Chain, start: FrontierStart, walk: WalkedWithin): void;
}

/** A chain's key here: the platform's, or an organisation's ID in lower case, as the chains' writers name it. */
const chainName = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : chain.orgId.toLowerCase());

/** The hash a stretch holds at `seq`, if it reaches it. */
function hashIn(start: FrontierStart, seq: bigint): Buffer | undefined {
  if (seq === start.base.seq) return start.base.hash;
  if (seq === start.from.seq) return start.from.hash;
  if (seq < start.base.seq || seq > start.from.seq) return undefined;
  const at = Number(seq - start.base.seq - 1n) * HASH_BYTES;
  return start.hashes.subarray(at, at + HASH_BYTES);
}

export function createChainFrontier({
  anchors,
  now,
  mostBytes = MOST_FRONTIER_BYTES,
  mostKept = MOST_WALKED_WITHIN,
}: {
  readonly anchors: FrontierAnchors;
  readonly now: () => Date;
  readonly mostBytes?: number;
  /** How many events a chain's stretch keeps before it is trimmed to the latest anchor. */
  readonly mostKept?: number;
}): ChainFrontier {
  const byChain = new Map<string, FrontierStart>();
  let heldBytes = 0;

  const set = (name: string, kept: FrontierStart | undefined): void => {
    heldBytes -= byChain.get(name)?.hashes.length ?? 0;
    if (kept === undefined) {
      byChain.delete(name);
      return;
    }
    byChain.set(name, kept);
    heldBytes += kept.hashes.length;
  };

  /** The stretch kept for the chain, where it still stands: trimmed to its latest anchor once past `mostKept`. */
  const standing = (chain: Chain, name: string, anchor: CheckedPoint): FrontierStart | undefined => {
    const kept = byChain.get(name);
    if (kept === undefined) return undefined;
    // The anchor past F, or a rebase dated after the stretch began: it says nothing of the chain now.
    if (anchor.seq > kept.from.seq || anchor.seq < kept.base.seq) return undefined;
    if (anchors.rebasedAfter(chain, new Date(kept.at))) return undefined;
    // The anchor not on the stretch walked: another walk read another chain there. Start over from the anchor.
    if (hashIn(kept, anchor.seq)?.equals(anchor.hash) !== true) return undefined;
    if (anchor.seq === kept.base.seq || kept.hashes.length <= mostKept * HASH_BYTES) return kept;
    const cut = Number(anchor.seq - kept.base.seq) * HASH_BYTES;
    const trimmed: FrontierStart = { ...kept, base: anchor, hashes: Buffer.from(kept.hashes.subarray(cut)) };
    set(name, trimmed);
    return trimmed;
  };

  return Object.freeze({
    startOf(chain: Chain): FrontierStart | undefined {
      const anchor = anchors.latest(chain);
      const name = chainName(chain);
      if (anchor === undefined) {
        set(name, undefined);
        return undefined;
      }
      const kept = standing(chain, name, anchor);
      if (kept !== undefined) return kept;
      const fresh: FrontierStart = { base: anchor, hashes: Buffer.alloc(0), from: anchor, at: now().getTime() };
      set(name, fresh);
      return fresh;
    },

    raise(chain: Chain, start: FrontierStart, { head, path }: WalkedWithin): void {
      const name = chainName(chain);
      const kept = byChain.get(name);
      if (kept !== undefined && kept.from.seq >= head.seq) return;
      const added: Buffer[] = [];
      for (let seq = start.from.seq + 1n; seq <= head.seq; seq += 1n) {
        const hash = path.get(seq);
        // A stretch with a hole is no stretch: kept as it was.
        if (hash?.length !== HASH_BYTES) return;
        added.push(hash);
      }
      const hashes = Buffer.concat([start.hashes, ...added]);
      if (heldBytes - (kept?.hashes.length ?? 0) + hashes.length > mostBytes) {
        set(name, undefined);
        return;
      }
      // The stretch's own start time: a rebase dated after it, however often it is raised, still sets it aside.
      set(name, { base: start.base, hashes, from: head, at: start.at });
    },
  });
}

/**
 * The heads copies witnessed against a walk from `start` to `walk.head`: each must be the chain's own event at its
 * place, read on the stretch from the anchor or on the walk. One above the head is a cut where `above` says so (the
 * heads were asked before the walk's statement, so each was committed before it), else left to judge (the gate's,
 * after Tx A's commit). The highest head off the path is the one named.
 */
export function judgeWitnessed(
  witnessed: readonly HeadSeen[],
  start: FrontierStart,
  walk: WalkedWithin,
  above: 'cut' | 'unjudged',
): WitnessJudgement {
  let cut: bigint | undefined;
  const unjudged: bigint[] = [];
  for (const { seq, hash } of witnessed) {
    // Above the head with no cut to call, or below the stretch: nothing here to place it on.
    if ((seq > walk.head.seq && above === 'unjudged') || seq < start.base.seq) {
      unjudged.push(seq);
      continue;
    }
    if (hashOnPath(seq, start, walk)?.equals(hash) !== true && (cut === undefined || seq > cut)) cut = seq;
  }
  if (cut !== undefined) return { kind: 'cut', seq: cut };
  return unjudged.length === 0 ? { kind: 'held' } : { kind: 'unjudged', seqs: unjudged };
}

/** The hash at `seq` on the stretch from the anchor and the walk on from it: none above the head the walk reached. */
function hashOnPath(seq: bigint, start: FrontierStart, walk: WalkedWithin): Buffer | undefined {
  if (seq > walk.head.seq) return undefined;
  if (seq === walk.head.seq) return walk.head.hash;
  return seq > start.from.seq ? walk.path.get(seq) : hashIn(start, seq);
}

/** An event row read ahead, its place and its entry as the chain checks it (undefined where its row can't be read). */
export interface ReadAhead {
  readonly seq: bigint;
  readonly entry: StoredEntry | undefined;
}

/**
 * A walk from `from` over events already read (walkWithin's statements, sent on a trip the transaction makes anyway):
 * verifyFromAnchor's checks, every event re-hashed and linked, the head's own hash at the end. More than `most` events
 * past `from` is `too_far`, never a walk short of the head.
 */
export async function walkWithin(
  keys: KeyProvider,
  chain: Chain,
  edges: ChainEdges,
  events: readonly ReadAhead[],
  from: CheckedPoint,
  most: number = MOST_WALKED_WITHIN,
): Promise<WithinWalk> {
  const path = new Map<bigint, Buffer>();
  let next = 0;
  const step = await verifyFromAnchor(
    keys,
    chain,
    {
      edges: () => Promise.resolve(edges),
      countBetween: () => Promise.reject(new Error('A walk within reads no count')),
      events(after, upTo, limit) {
        while (next < events.length && (events[next]?.seq ?? 0n) <= after) next += 1;
        const batch: (StoredEntry | undefined)[] = [];
        for (let at = next; at < events.length && batch.length < limit; at += 1) {
          const read = events[at];
          if (read === undefined || read.seq > upTo) break;
          if (read.entry !== undefined) path.set(read.seq, read.entry.hash);
          batch.push(read.entry);
        }
        return Promise.resolve(batch);
      },
    },
    from,
    most,
  );
  if (!step.ok) return { kind: 'broken', problem: step.problem };
  if (step.seq !== step.to) return { kind: 'too_far' };
  return { kind: 'walked', head: { seq: step.seq, hash: step.hash, macKeyVersion: step.macKeyVersion }, path };
}
