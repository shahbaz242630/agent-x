// An organisation's chain recovery plan (4D2e E9, PL-29; playbook H): given its
// chain damaged on the live server (wound back, an event deleted or edited) and
// a restored copy of the database from before the damage (the restore drill's
// copy, a point-in-time restore), which original rows would be put back or put
// in place of the damaged ones, each with its original MAC. Read only on both
// sides: it plans, and E10's job applies.
//
// PL-29's key property: recovery writes only original rows, never a new MAC or
// key, so it can't bless a forgery. So the plan is refused, never bent, when:
// - `copy_unsigned`: the copy was restored from before 0079 (PL-57), so holds no
//   operator's signatures, and none of its operator's events could be checked:
//   a copy from after 0079 is needed
// - `copy_broken`: the copy fails its own whole check, or holds no chain for the
//   organisation: nothing in it can be believed; or (`signing_start`) where
//   operator signing starts on the chain differs from the live server's: the
//   copy's own start, moved, would let it vouch for an operator's event unsigned
// - `fork`: the live server holds an event sealed by us, in a place the copy
//   holds another: the app wrote on after the damage (a wound-back head grown
//   again). Putting the copy's back would throw those away, so only the named
//   flag `--discard-fork` allows it (E10, `discardFork`): then the copy's
//   events take those places, every live row past the copy is removed (its
//   columns kept as evidence), and the copy's head is put back
// - `new_seal`: the result would need an event or a head no original row holds:
//   an event past the copy's head missing or damaged, a sealed live head past
//   where the plan could end, or no head row for the plan's end
// - `behind_anchor`, `anchor`: the result wouldn't hold the store's anchor: it
//   would end before it, or hold another event where it was anchored
// - `moved`: a head changed while the chains were read; run it again
// - `too_large`: more rows than one plan writes
//
// Where the copy ends, the live chain may have grown on whole from it: those
// events and the live head stay as they are.
//
// An operator's event is judged as every reader judges it (PL-57): from where
// signing started on its chain, one without the operator's own signature is
// unsealed. So one past the copy is never kept as grown on, and one in the
// copy's stretch whose signature is gone or another is no original: the copy's
// event is planned back with its signature (a row's columns carry it). A live row numbered below 1, or
// past a sealed live head at exactly the plan's end, was never the app's: it is
// planned removed, which writes nothing new either.
import { createHash } from 'node:crypto';

import {
  type AuditTables,
  chainRowsAlone,
  createAuditTrail,
  holdsOperatorSignatures,
  operatorSigningStart,
  type StoredColumns,
  type StoredRow,
  type StoredValues,
} from '@agentx/core/modules/audit';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import {
  type Chain,
  type ChainHead,
  type CheckedPoint,
  createChainWalker,
  entryIsSealed,
  headIsSealed,
  type StoredEntry,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Database } from '@agentx/platform/db';

/** How many rows a page of either chain reads. */
const PAGE = 1000;

/** The most rows one plan writes: its file is made in memory, and a chain lost wider than this is past one plan. */
const MOST_PLANNED_ROWS = 100_000;

type RecoveryRefusal =
  'copy_unsigned' | 'copy_broken' | 'fork' | 'new_seal' | 'behind_anchor' | 'anchor' | 'moved' | 'too_large';

/** A row the plan writes: the copy's original put back where it is missing, or in place of a damaged one; or one removed. */
export type PlannedRow =
  | { readonly action: 'put_back'; readonly seq: bigint; readonly columns: StoredColumns }
  | {
      readonly action: 'replace';
      readonly seq: bigint;
      readonly columns: StoredColumns;
      /** Every column as the live row holds it: evidence of what the original replaces (E10). */
      readonly replaced: StoredValues;
    }
  | {
      readonly action: 'remove';
      readonly seq: bigint;
      /** Every column as the live row holds it: evidence of what was added, kept before it is deleted. */
      readonly stored: StoredValues;
    };

export type RecoveryPlan =
  | {
      readonly ok: true;
      /** Where the copy's chain ends, and where the recovered chain would. */
      readonly copySeq: bigint;
      readonly endsAt: CheckedPoint;
      readonly rows: readonly PlannedRow[];
      /** The copy's head row, to put in place of the live one; undefined where the live head stays. */
      readonly head: ChainHead | undefined;
      /** Live events past the copy, kept as they are. */
      readonly keptPastCopy: bigint;
      /** Whether a fork was found and its live branch planned away, under `discardFork` alone (E10). */
      readonly forkDiscarded: boolean;
      /** The live chain as the plan read it, every row and the head (fingerprintOf): a repair writes only onto this. */
      readonly liveFingerprint: string;
    }
  | {
      readonly ok: false;
      readonly reason: RecoveryRefusal;
      /** Where: the event's number, or the anchor's. */
      readonly seq: bigint;
      /** For `copy_broken`, the copy's own check's reason. */
      readonly problem?: string;
    };

type Refused = Extract<RecoveryPlan, { ok: false }>;

const refused = (reason: RecoveryRefusal, seq: bigint, problem?: string): Refused =>
  problem === undefined ? { ok: false, reason, seq } : { ok: false, reason, seq, problem };

/** A head changed between pages of one read. */
class ChainMoved extends Error {}

const sameHead = (a: ChainHead | string, b: ChainHead | string): boolean =>
  typeof a === 'string' || typeof b === 'string'
    ? a === b
    : a.seq === b.seq && a.hash.equals(b.hash) && a.mac.equals(b.mac) && a.macKeyVersion === b.macKeyVersion;

/** A chain's rows in number order, a page at a time, each page's head the first's or ChainMoved. */
async function* rowsOf(
  { readPage = chainRowsAlone, pageSize = PAGE, keys }: Pick<RecoverySides, 'readPage' | 'pageSize' | 'keys'>,
  db: Database<AuditTables>,
  orgId: string,
  heads: { first?: ChainHead | string },
  fingerprint?: Fingerprint,
): AsyncGenerator<StoredRow> {
  let after: bigint | null = null;
  for (;;) {
    const page = await readPage(db, keys, orgId, after, pageSize);
    heads.first ??= page.head;
    if (!sameHead(heads.first, page.head)) throw new ChainMoved();
    for (const row of page.rows) fingerprint?.row(row);
    yield* page.rows;
    const last = page.rows.at(-1);
    if (last === undefined || page.rows.length < pageSize) return;
    after = last.seq;
  }
}

/** Both chains' rows side by side, by number. */
async function* sideBySide(
  copy: AsyncGenerator<StoredRow>,
  live: AsyncGenerator<StoredRow>,
): AsyncGenerator<{ readonly seq: bigint; readonly copy?: StoredRow; readonly live?: StoredRow }> {
  let [onCopy, onLive] = await Promise.all([copy.next(), live.next()]);
  while (onCopy.done !== true || onLive.done !== true) {
    const c = onCopy.done === true ? undefined : onCopy.value;
    const l = onLive.done === true ? undefined : onLive.value;
    // The lower number first; both where they share one. One side at least has a row, or the loop has ended.
    const seq = [c, l].flatMap((row) => (row === undefined ? [] : [row.seq])).reduce((a, b) => (b < a ? b : a));
    const takeCopy = c?.seq === seq;
    const takeLive = l?.seq === seq;
    yield { seq, ...(takeCopy ? { copy: c } : {}), ...(takeLive ? { live: l } : {}) };
    [onCopy, onLive] = await Promise.all([takeCopy ? copy.next() : onCopy, takeLive ? live.next() : onLive]);
  }
}

export interface RecoverySides {
  /** The restored copy and the live server, each as the app's role, read-only. */
  readonly copy: Database<AuditTables>;
  readonly live: Database<AuditTables>;
  readonly keys: KeyProvider;
  readonly orgId: string;
  /** The store's latest anchor for the organisation's chain, its signature checked; undefined where it has none. */
  readonly anchor: CheckedPoint | undefined;
  readonly mostRows?: number;
  /** The named flag (E10): a fork's live branch planned away rather than the plan refused. */
  readonly discardFork?: boolean;
  /** How a page is read, and its size: the module's own read, but for a test that moves a chain between pages. */
  readonly readPage?: typeof chainRowsAlone;
  readonly pageSize?: number;
}

/** Plans the recovery of one organisation's chain from the copy: never writes, and never throws for what it finds. */
export async function planChainRecovery(sides: RecoverySides): Promise<RecoveryPlan> {
  const orgId = sides.orgId.toLowerCase();
  if (!(await holdsOperatorSignatures(sides.copy))) return refused('copy_unsigned', 0n, COPY_UNSIGNED);
  // The copy is judged by the live server's cut-over, never by its own (PL-29: no operator's event put back unsigned).
  const [copyStart, liveStart] = await Promise.all([
    operatorSigningStart(sides.copy, orgId),
    operatorSigningStart(sides.live, orgId),
  ]);
  if (copyStart !== liveStart) return refused('copy_broken', 0n, 'signing_start');
  // The IDs are never used: nothing is written. The trail needs a source all the same.
  const copied = await createAuditTrail({ keys: sides.keys, ids: uuidV7Ids }).verifyAlone(sides.copy, orgId, undefined);
  if (!copied.ok) return refused('copy_broken', copied.problem.seq, copied.problem.reason);
  const copyHeads: { first?: ChainHead | string } = {};
  const liveHeads: { first?: ChainHead | string } = {};
  const fingerprint = createFingerprint();
  const planner = createPlanner({ ...sides, orgId }, copied, liveHeads);
  try {
    for await (const { seq, copy, live } of sideBySide(
      rowsOf(sides, sides.copy, orgId, copyHeads),
      rowsOf(sides, sides.live, orgId, liveHeads, fingerprint),
    )) {
      const refusal = planner.take(seq, copy, live);
      if (refusal !== undefined) return refusal;
    }
  } catch (error) {
    if (error instanceof ChainMoved) return refused('moved', 0n);
    throw error;
  }
  const copyHead = copyHeads.first;
  if (copyHead === undefined || typeof copyHead === 'string') return refused('copy_broken', 0n, 'head');
  // The copy's check and its rows' read must have seen one chain.
  if (copyHead.seq !== copied.seq || !copyHead.hash.equals(copied.hash)) return refused('moved', copied.seq);
  return planner.finish(copyHead, fingerprint.finish(liveHeads.first));
}

/** A running SHA-256 of a chain's rows as stored, in number order, then its head: the same read, the same bytes. */
interface Fingerprint {
  row(row: StoredRow): void;
  finish(head: ChainHead | string | undefined): string;
}

function createFingerprint(): Fingerprint {
  const hash = createHash('sha256');
  return {
    row(row) {
      // Every column, in the read's fixed order, as text: two reads of the same rows give the same line.
      hash.update(`${JSON.stringify(row.stored)}\n`);
    },
    finish(head) {
      const line =
        head === undefined || typeof head === 'string'
          ? (head ?? null)
          : { seq: head.seq.toString(), hash: hex(head.hash), mac: hex(head.mac), macKeyVersion: head.macKeyVersion };
      hash.update(JSON.stringify(line));
      return hash.digest('hex');
    },
  };
}

/**
 * The live chain's fingerprint as a plan takes it, read with `readPage` (a
 * repair's own read, in its transaction under the head's lock, 4D2e E10), or
 * null where its head moved between pages.
 */
export async function fingerprintOf(
  read: Pick<RecoverySides, 'readPage' | 'pageSize' | 'keys'>,
  db: Database<AuditTables>,
  orgId: string,
): Promise<string | null> {
  const heads: { first?: ChainHead | string } = {};
  const fingerprint = createFingerprint();
  try {
    // Each row is taken into the fingerprint as it is read; nothing else is done with it.
    for await (const _row of rowsOf(read, db, orgId.toLowerCase(), heads, fingerprint));
  } catch (error) {
    if (error instanceof ChainMoved) return null;
    throw error;
  }
  return fingerprint.finish(heads.first);
}

/** What a copy from before 0079 is refused with, in plain words. */
const COPY_UNSIGNED =
  'the copy was restored from before operator signing (migration 0079); a copy restored from after 0079 is needed';

/** The plan's row by row judgement, then its end. */
function createPlanner(
  { keys, orgId, anchor, mostRows = MOST_PLANNED_ROWS, discardFork = false }: RecoverySides,
  copied: CheckedPoint,
  liveHeads: { first?: ChainHead | string },
) {
  const chain: Chain = { kind: 'organisation', orgId };
  const sealedHere = (row: StoredRow): boolean => row.read !== undefined && entryIsSealed(keys, chain, row.read.entry);
  /**
   * Whether a live row is the copy's own: sealed, hashing the same, so the same in every column the hash covers, under
   * the same key version, so its MAC is the same bytes too (a MAC is the same for the same message and key).
   */
  const isOriginal = (live: StoredRow, copy: StoredEntry): boolean => {
    const entry = live.read?.entry;
    return (
      entry !== undefined &&
      entryIsSealed(keys, chain, entry) &&
      entry.hash.equals(copy.hash) &&
      entry.macKeyVersion === copy.macKeyVersion
    );
  };
  const liveHead = (): ChainHead | undefined => {
    const head = liveHeads.first;
    return head !== undefined && typeof head !== 'string' && headIsSealed(keys, chain, head) ? head : undefined;
  };

  const rows: PlannedRow[] = [];
  const walker = createChainWalker(keys, chain, copied);
  let end: CheckedPoint = copied;
  let broken = false;
  // A fork's live branch, found and planned away under discardFork alone.
  let forked = false;
  let atAnchor: CheckedPoint | undefined;

  const plan = (row: PlannedRow): Refused | undefined => {
    rows.push(row);
    return rows.length > mostRows ? refused('too_large', row.seq) : undefined;
  };

  /** A live row in the copy's stretch: the same, missing, damaged, or another sealed by us. */
  const inCopy = (
    seq: bigint,
    { entry, columns }: NonNullable<StoredRow['read']>,
    live: StoredRow | undefined,
  ): Refused | undefined => {
    if (seq === anchor?.seq) atAnchor = entry;
    if (live === undefined) return plan({ action: 'put_back', seq, columns });
    if (isOriginal(live, entry)) return undefined;
    const fork = sealedHere(live);
    if (fork && !discardFork) return refused('fork', seq);
    forked ||= fork;
    return plan({ action: 'replace', seq, columns, replaced: live.stored });
  };

  /** A live row past the copy: the chain grown on from it, or what can't be kept. */
  const pastCopy = (seq: bigint, live: StoredRow): Refused | undefined => {
    if (!broken) {
      const problem = live.read === undefined ? walker.unreadable() : walker.check(live.read.entry);
      if (problem === undefined) {
        end = live.read?.entry ?? end;
        if (seq === anchor?.seq) atAnchor = end;
        return undefined;
      }
      broken = true;
      // Sealed by us, but not on from the copy's event before it: the app wrote on another branch.
      const fork = problem.reason === 'link' && sealedHere(live);
      if (fork && !discardFork) return refused('fork', seq);
      forked ||= fork;
    }
    // The fork's branch, past the copy: every row of it goes, the copy's head put back in finish.
    if (forked) return plan({ action: 'remove', seq, stored: live.stored });
    const head = liveHead();
    // Never the app's: not sealed by us, and past a sealed head that stands exactly where the plan ends (every row
    // here is past that end).
    if (!sealedHere(live) && head?.seq === end.seq) {
      return plan({ action: 'remove', seq, stored: live.stored });
    }
    return refused('new_seal', end.seq + 1n);
  };

  return {
    take(seq: bigint, copy: StoredRow | undefined, live: StoredRow | undefined): Refused | undefined {
      // The copy holds nothing below 1 (its whole check counted every row), so a row there is live and never the app's.
      if (seq < 1n && live !== undefined) return plan({ action: 'remove', seq, stored: live.stored });
      // The copy's whole check read every row up to its head, so each of its rows here is read and sealed.
      if (copy?.read !== undefined) return inCopy(seq, copy.read, live);
      return live === undefined ? undefined : pastCopy(seq, live);
    },

    finish(copyHead: ChainHead, liveFingerprint: string): RecoveryPlan {
      const head = liveHead();
      // The live head is sealed past where the plan can end: events the copy doesn't hold are lost. A fork's
      // branch is discarded whole, the plan ending at the copy's head.
      if (head !== undefined && head.seq > end.seq && !forked) return refused('new_seal', end.seq + 1n);
      let replaceHead: ChainHead | undefined;
      if (end.seq === copied.seq) {
        const live = liveHeads.first;
        replaceHead = live !== undefined && sameHead(live, copyHead) ? undefined : copyHead;
      } else if (head?.hash.equals(end.hash) !== true) {
        // Grown on past the copy, but no original head row stands at its end (a hash names its event's number too).
        return refused('new_seal', end.seq);
      }
      if (anchor !== undefined && anchor.seq > end.seq) return refused('behind_anchor', anchor.seq);
      if (
        anchor !== undefined &&
        anchor.seq > 0n &&
        (atAnchor === undefined ||
          !atAnchor.hash.equals(anchor.hash) ||
          atAnchor.macKeyVersion !== anchor.macKeyVersion)
      ) {
        return refused('anchor', anchor.seq);
      }
      return {
        ok: true,
        copySeq: copied.seq,
        endsAt: { seq: end.seq, hash: end.hash, macKeyVersion: end.macKeyVersion },
        rows,
        head: replaceHead,
        keptPastCopy: end.seq - copied.seq,
        forkDiscarded: forked,
        liveFingerprint,
      };
    },
  };
}

/** What a plan's file says about it, beside its rows. */
export interface PlanFacts {
  readonly planId: string;
  readonly orgId: string;
  readonly release: string;
  readonly run: string | null;
  readonly anchor: CheckedPoint | undefined;
}

const hex = (bytes: Buffer): string => bytes.toString('hex');

const pointLine = (point: CheckedPoint | undefined) =>
  point === undefined ? null : { seq: point.seq.toString(), hash: hex(point.hash), macKeyVersion: point.macKeyVersion };

/**
 * The plan's lines as its file holds them, but for who made it and when (the
 * plan's ID, the release, the run): its summary, each row it would write, the
 * head it would put back. What its digest covers.
 */
function planLines(plan: RecoveryPlan, orgId: string, anchor: CheckedPoint | undefined): object[] {
  const about = { k: 'plan', orgId, anchor: pointLine(anchor) };
  if (!plan.ok) {
    const { reason, seq, problem } = plan;
    return [{ ...about, ok: false, reason, seq: seq.toString(), problem }];
  }
  return [
    {
      ...about,
      ok: true,
      copySeq: plan.copySeq.toString(),
      endsAt: pointLine(plan.endsAt),
      rows: plan.rows.length,
      headReplaced: plan.head !== undefined,
      keptPastCopy: plan.keptPastCopy.toString(),
      forkDiscarded: plan.forkDiscarded,
      liveFingerprint: plan.liveFingerprint,
    },
    ...plan.rows.map((row) => {
      const at = { k: 'row', action: row.action, seq: row.seq.toString() };
      if (row.action === 'remove') return { ...at, stored: row.stored };
      return row.action === 'replace'
        ? { ...at, columns: row.columns, replaced: row.replaced }
        : { ...at, columns: row.columns };
    }),
    ...(plan.head === undefined
      ? []
      : [
          {
            k: 'head',
            seq: plan.head.seq.toString(),
            hash: hex(plan.head.hash),
            mac: hex(plan.head.mac),
            macKeyVersion: plan.head.macKeyVersion,
          },
        ]),
  ];
}

const ndjson = (lines: readonly object[]): string => lines.map((line) => `${JSON.stringify(line)}\n`).join('');

/**
 * A plan's digest (4D2e E10): SHA-256, in hex, of its lines but for who made
 * it and when. A repair is asked with the digest of the plan the operator read,
 * makes the plan again and applies it only if the digest is the same: the
 * same rows, the same head, the same live chain read, under the same anchor.
 */
export const planDigest = (plan: RecoveryPlan, orgId: string, anchor: CheckedPoint | undefined): string =>
  createHash('sha256')
    .update(ndjson(planLines(plan, orgId, anchor)))
    .digest('hex');

/**
 * The plan as the evidence store keeps it, NDJSON: its summary first, then each
 * row it would write, then the head it would put back. A refused plan is its
 * summary alone, naming why. The summary names its digest, which a repair is
 * asked with (chain-restore.ts).
 */
export function planFile(plan: RecoveryPlan, facts: PlanFacts): Buffer {
  const [summary, ...rest] = planLines(plan, facts.orgId, facts.anchor);
  const made = { planId: facts.planId, release: facts.release, run: facts.run };
  const digest = planDigest(plan, facts.orgId, facts.anchor);
  return Buffer.from(ndjson([{ ...summary, ...made, digest }, ...rest]));
}
