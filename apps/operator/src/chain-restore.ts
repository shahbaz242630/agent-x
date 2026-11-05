// An organisation's chain repaired from its recovery plan (4D2e E10, PL-29;
// playbook H). The operator reads a plan (chain-recovery.ts) and asks for it
// by its digest; this makes the plan again, against the drill's copy and the
// live server as they stand now, and applies it only if it is the same plan:
// a plan file is never trusted, and one gone stale is refused.
//
// PL-29's key property holds here as in the plan: what is written is only the
// copy's original rows, each with its original MAC and its operator's
// signature, as read; nothing here makes a MAC, a signature or a hash, and the
// job holds the MAC key to check with alone. Every write is in one
// transaction, as the owner (the only role that may change or delete an
// event), under the chain head's lock, onto the live chain exactly as the plan
// read it (its fingerprint, read again under the lock), and the whole chain
// is checked in that transaction before it commits: ending where the plan
// ends, holding the store's anchor. Any difference rolls everything back.
//
// Refused, nothing written:
// - `plan`: the plan made now is itself refused (chain-recovery.ts's reasons);
//   a fork among them unless the named flag `--discard-fork` was given
// - `stale`: the plan made now isn't the one asked for (its digest differs):
//   either chain, or the anchor, changed since it was read
// - `signing_start`: where operator signing starts on the chain (PL-57)
//   changed on the live server after the plan held the copy to it, so an
//   operator's event would be judged otherwise than the plan judged it
// - `moved`: the live chain changed between the plan and the head's lock
// - `unverified`: the chain as written fails its whole check, or ends
//   elsewhere: rolled back
//
// The organisation's integrity hold is left as it is: its admin clears it
// with a step-up once the investigation is recorded, as for any hold.
import {
  type AuditTables,
  type AuditTransaction,
  chainRowsIn,
  createAuditTrail,
  lockChainHead,
  operatorSigningStart,
  operatorSigningStartIn,
  writeOriginalRows,
} from '@agentx/core/modules/audit';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import type { ChainProblem, CheckedPoint } from '@agentx/platform/audit-chain';
import { type Database, JOB_ANSWER_WITHIN_MS, withTenant } from '@agentx/platform/db';

import {
  fingerprintOf,
  planChainRecovery,
  planDigest,
  type RecoveryPlan,
  type RecoverySides,
} from './chain-recovery.ts';

type Planned = Extract<RecoveryPlan, { ok: true }>;

export type RestoreOutcome =
  | { readonly ok: true; readonly plan: Planned }
  | { readonly ok: false; readonly reason: 'plan'; readonly plan: Extract<RecoveryPlan, { ok: false }> }
  | { readonly ok: false; readonly reason: 'stale'; readonly digest: string }
  | {
      readonly ok: false;
      readonly reason: 'signing_start';
      readonly copyStart: string | null;
      readonly liveStart: string | null;
    }
  | { readonly ok: false; readonly reason: 'moved' }
  | {
      readonly ok: false;
      readonly reason: 'unverified';
      /** The whole check's problem, or where the chain as written ended instead of the plan's end. */
      readonly problem: ChainProblem | { readonly reason: 'end'; readonly seq: bigint };
    };

export interface RestoreSides extends Pick<RecoverySides, 'keys' | 'orgId' | 'anchor' | 'mostRows' | 'pageSize'> {
  /** The drill's copy, read-only. */
  readonly copy: Database<AuditTables>;
  /** The live server as the owner: read for the plan, written in the repair's transaction. */
  readonly live: Database<AuditTables>;
  /** The digest of the plan the operator read (planDigest). */
  readonly digest: string;
  /** The named flag: a fork's live branch discarded rather than the repair refused. */
  readonly discardFork: boolean;
}

/** The chain as written failed its check: thrown to roll the repair back. */
class Unverified extends Error {
  readonly problem: Extract<RestoreOutcome, { reason: 'unverified' }>['problem'];

  constructor(problem: Unverified['problem']) {
    super('the chain as written failed its check');
    this.problem = problem;
  }
}

/** A job's transaction: each statement limited, each trip's answer too. */
const JOB_LIMITS = { limited: true, answeredWithinMs: JOB_ANSWER_WITHIN_MS } as const;

const samePoint = (a: CheckedPoint, b: CheckedPoint): boolean =>
  a.seq === b.seq && a.hash.equals(b.hash) && a.macKeyVersion === b.macKeyVersion;

/** Makes the plan again and applies it if it is the one asked for: never throws for what it finds. */
export async function restoreChain(sides: RestoreSides): Promise<RestoreOutcome> {
  const { copy, live, anchor, digest, discardFork } = sides;
  const orgId = sides.orgId.toLowerCase();
  const plan = await planChainRecovery({ ...sides, orgId, discardFork });
  if (!plan.ok) return { ok: false, reason: 'plan', plan };
  const madeNow = planDigest(plan, orgId, anchor);
  if (madeNow !== digest) return { ok: false, reason: 'stale', digest: madeNow };
  // The copy is a fixed point in time: read before the repair's transaction, which can't hold a second.
  const copyStart = await operatorSigningStart(copy, orgId);
  try {
    return await withTenant(live, orgId, (tx) => repairIn(tx, { ...sides, orgId }, plan, copyStart), JOB_LIMITS);
  } catch (error) {
    if (error instanceof Unverified) return { ok: false, reason: 'unverified', problem: error.problem };
    throw error;
  }
}

/** The repair's one transaction: locked, compared, written, checked; Unverified rolls it back. */
async function repairIn(
  tx: AuditTransaction,
  { live, keys, orgId, anchor, pageSize }: RestoreSides,
  plan: Planned,
  copyStart: bigint | null,
): Promise<RestoreOutcome> {
  await lockChainHead(tx, orgId);
  // The plan held the copy to the live server's start (PL-57); read again under the lock, as the rows are.
  const liveStart = await operatorSigningStartIn(tx, orgId);
  if (liveStart !== copyStart) {
    return {
      ok: false,
      reason: 'signing_start',
      copyStart: copyStart?.toString() ?? null,
      liveStart: liveStart?.toString() ?? null,
    };
  }
  // The live chain read again, now that nothing can add to it: exactly what the plan read, or nothing is written.
  const seen = await fingerprintOf(
    {
      keys,
      ...(pageSize === undefined ? {} : { pageSize }),
      readPage: (_db, rowKeys, org, after, limit) => chainRowsIn(tx, rowKeys, org, after, limit),
    },
    live,
    orgId,
  );
  if (seen !== plan.liveFingerprint) return { ok: false, reason: 'moved' };
  await writeOriginalRows(tx, orgId, plan.rows, plan.head);
  // The trail's IDs are never used: the check writes nothing.
  const report = await createAuditTrail({ keys, ids: uuidV7Ids }).verify(tx, orgId, anchor);
  if (!report.ok) throw new Unverified(report.problem);
  if (!samePoint(report, plan.endsAt)) throw new Unverified({ reason: 'end', seq: report.seq });
  return { ok: true, plan };
}

/** What the evidence store keeps of a repair's run, beside its plan's own file. */
export interface RestoreFacts {
  readonly restoreId: string;
  readonly planId: string;
  readonly orgId: string;
  readonly digest: string;
  readonly discardFork: boolean;
  readonly release: string;
  readonly run: string | null;
}

/** How many of a plan's rows are of each action. */
const rowCounts = (plan: Planned) => {
  const count = (action: string): number => plan.rows.filter((row) => row.action === action).length;
  return { putBack: count('put_back'), replaced: count('replace'), removed: count('remove') };
};

/** The outcome as one line of plain facts: no row's contents (the plan's file holds them). */
export function outcomeLine(outcome: RestoreOutcome): Readonly<Record<string, unknown>> {
  if (outcome.ok) {
    const { plan } = outcome;
    return {
      ok: true,
      ...rowCounts(plan),
      headReplaced: plan.head !== undefined,
      forkDiscarded: plan.forkDiscarded,
      endsAt: plan.endsAt.seq.toString(),
      // The repaired head's hash: with endsAt, the place a rebase names (4D2e E11).
      endsAtHash: plan.endsAt.hash.toString('hex'),
    };
  }
  switch (outcome.reason) {
    case 'plan': {
      const { reason, seq, problem } = outcome.plan;
      return { ok: false, reason: 'plan', planRefused: reason, seq: seq.toString(), problem: problem ?? null };
    }
    case 'stale':
      return { ok: false, reason: 'stale', digestNow: outcome.digest };
    case 'signing_start':
      return { ok: false, reason: 'signing_start', copyStart: outcome.copyStart, liveStart: outcome.liveStart };
    case 'moved':
      return { ok: false, reason: 'moved' };
    case 'unverified':
      return {
        ok: false,
        reason: 'unverified',
        problem: outcome.problem.reason,
        seq: outcome.problem.seq.toString(),
      };
  }
}

/** The repair's record in the evidence store: one NDJSON line, the run's facts and its outcome. */
export const restoreFile = (outcome: RestoreOutcome, facts: RestoreFacts): Buffer =>
  Buffer.from(`${JSON.stringify({ k: 'restore', ...facts, ...outcomeLine(outcome) })}\n`);
