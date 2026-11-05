// A chain's rebase (4D2e E11; playbook H): after a sanctioned change to an
// audit chain (an organisation's chain repaired, E10; the platform chain begun
// again), its anchor in the store can't be met, and the API's check would raise
// the alarm for good. This moves the anchor on: it reads the anchors' store
// (rebases first, as the API does), checks the live chain whole from its first
// event, holds its head to the place the request names (the place the repair
// ended at), and writes one signed rebase line naming the chain, that place,
// the anchor it moves on from, why and the incident's reference, to
// `e<epoch>/rebases/<ID>`, dated by the database's clock.
//
// Refused, never bent:
// - `store`: the anchors' store couldn't be read whole, so there is nothing to
//   judge the chain against
// - `not_needed`: the chain still holds its anchor (or has none): the API's
//   check finds nothing wrong, and a rebase would only set its point aside
// - `broken`: the chain fails its own whole check (a seal, a link, a MAC, an
//   operator's signature): a rebase moves an anchor, it never blesses a chain
//   the app didn't write. Only `anchor` (wound back, or another event where it
//   was anchored) is what a rebase is for
// - `head_differs`: the chain's head isn't the place named. A rebase takes the
//   head a person has checked, never whatever the head is now: a chain cut
//   short since the repair would otherwise be blessed with it
// - `done_before`: a rebase of this ID is in the store already
// A rebase that leaves the chain shorter than its old anchor is said, in plain
// words, before it is signed, and on its line: that many trusted events are given up.
//
// Then, so the chain's owner can read it (everything logged, both sides), the
// operator's own signed event on that chain, after the rebase's place:
// `audit_chain.rebased` on an organisation's chain, or on the platform chain.
// The next anchor covers it. A run stopped between the two is run again: it
// finds its rebase in the store and records only the event.
//
// Signed with `audit-rebase`, which only the operator's job holds (OPERATOR_ONLY).
// Read-only on the database but for that one event; the store's file is added once.
import {
  type AuditTables,
  createAuditTrail,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import {
  type AnchorLog,
  type AnchorPoint,
  type Chain,
  type ChainReport,
  type Rebase,
  type RebaseReason,
  rebaseFile,
  rebaseFileName,
  readRebaseFile,
  signRebase,
} from '@agentx/platform/audit-chain';
import { type Database, databaseNow, holdTransactionLock } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { OverwriteRefused, type WriteOnceStore } from '@agentx/platform/storage';

import { OPERATOR } from './create-organization.ts';

/** Why a rebase is refused. */
type RebaseRefusal = 'store' | 'not_needed' | 'broken' | 'head_differs' | 'done_before';

/** Whether the chain's owner can read of the rebase on its chain: written now, by a run before, or not written. */
type RebaseRecorded = 'recorded' | 'already' | 'failed';

export type RebaseOutcome =
  | {
      readonly ok: true;
      readonly rebase: Rebase;
      /** How many events of the old anchor the rebase gives up: 0 unless the chain is now shorter than it. */
      readonly shorterBy: bigint;
      readonly recorded: RebaseRecorded;
    }
  | {
      readonly ok: false;
      readonly reason: RebaseRefusal;
      /** For `broken`, the chain's own check's reason. */
      readonly problem?: string;
      /** Where: the problem's event; for `not_needed` the anchor's; for `head_differs` the head's. */
      readonly seq?: bigint;
      /** For `done_before`: the rebase's event on its chain, finished by this run if the one before stopped short. */
      readonly recorded?: RebaseRecorded;
    };

/** What a rebase is asked for: the place the repair ended at, why, the incident and the rebase's ID. */
export interface RebaseAsked {
  readonly id: string;
  readonly seq: bigint;
  readonly hash: Buffer;
  readonly reason: RebaseReason;
  readonly evidence: string;
  /** The release and the job's run, recorded with the event, as every operator act is. */
  readonly release: string;
  readonly run: string | null;
}

/** The tables a rebase reads, and the one event it records: either chain's. */
export type RebaseTables = AuditTables & PlatformControlsTables;

/** The event a rebase records on the chain it moved. */
const REBASED = 'audit_chain.rebased';

/** The lock two runs of one rebase take before looking for its event, so only one writes it (lockName's scope). */
export const REBASE_LOCK = 'audit-chain-rebase';

/** The chain's whole check, from its first event, against `anchor` where given. */
function checkWhole(
  live: Database<RebaseTables>,
  keys: KeyProvider,
  chain: Chain,
  anchor: AnchorPoint | undefined,
): Promise<ChainReport> {
  return chain.kind === 'platform'
    ? createPlatformChain({ keys, ids: uuidV7Ids }).verifyAlone(live, anchor)
    : createAuditTrail({ keys, ids: uuidV7Ids }).verifyAlone(live, chain.orgId, anchor);
}

/** The chain's name as the store names it. */
const nameOf = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : `organisation:${chain.orgId}`);

/** Whether an error is the platform chain refusing an event ID it holds already: the rebase's, recorded before. */
const heldAlready = (error: unknown): boolean =>
  error instanceof Error && 'constraint' in error && error.constraint === 'audit_events_id_key';

/**
 * The rebase's event on the chain it moved, once: about the rebase (its ID), on an organisation's chain through the
 * signed states as every operator's act there; on the platform chain under the rebase's own ID.
 */
async function recordRebase(
  writer: Database<RebaseTables>,
  services: SignedStatesServices,
  chain: Chain,
  rebase: Rebase,
  { release, run }: Pick<RebaseAsked, 'release' | 'run'>,
): Promise<'recorded' | 'already'> {
  const details = {
    rebaseId: rebase.id,
    seq: rebase.seq.toString(),
    headHash: rebase.hash.toString('hex'),
    fromSeq: rebase.from === null ? null : rebase.from.toString(),
    reason: rebase.reason,
    evidence: rebase.evidence,
    release,
    run,
  };
  if (chain.kind === 'platform') {
    try {
      await createPlatformChain({ keys: services.keys, ids: { next: () => rebase.id } }).recordAlone(writer, {
        actor: OPERATOR,
        action: REBASED,
        details,
      });
      return 'recorded';
    } catch (error) {
      if (heldAlready(error)) return 'already';
      throw error;
    }
  }
  const trail = createAuditTrail({ keys: services.keys, ids: services.ids });
  return withSignedStates(writer, chain.orgId, services, async (tx, states) => {
    // Before the look, not only the head's lock in record: two runs could each find no event and each write one.
    await holdTransactionLock(tx, REBASE_LOCK, rebase.id);
    const subject = { type: 'audit_chain', id: rebase.id };
    const before = await states.eventOf(tx, chain.orgId, { onlyAbout: subject });
    if (before.outcome === 'tampered') throw new Error("the organisation's audit log can't be verified");
    if (before.event !== undefined) return 'already';
    await trail.record(tx, chain.orgId, {
      actor: OPERATOR,
      action: REBASED,
      subject: { ...subject, version: 1 },
      details,
    });
    return 'recorded';
  });
}

/** The event recorded, or `failed`, said: the rebase stands, and the same request run again records it. */
async function recorded(
  record: () => Promise<'recorded' | 'already'>,
  logger: Logger,
  rebaseId: string,
): Promise<RebaseRecorded> {
  try {
    return await record();
  } catch (error) {
    logger.error('operator.rebase_not_recorded', { rebaseId, err: error });
    return 'failed';
  }
}

/**
 * This rebase in the store from a run before, for this chain and the head asked: none if there is none, or `other`
 * where it is no rebase of this one. An ID reused for another head is `other`, so a run never says done for a head
 * that was never rebased (E11b review).
 */
async function storedBefore(
  store: WriteOnceStore,
  keys: KeyProvider,
  { epoch, chain, asked }: { readonly epoch: number; readonly chain: Chain; readonly asked: RebaseAsked },
): Promise<Rebase | 'other' | undefined> {
  const name = rebaseFileName(epoch, asked.id);
  if (!(await store.list(name, 1)).names.includes(name)) return undefined;
  const read = await readRebaseFile(keys, { bytes: await store.get(name), name, epoch });
  if (!('rebase' in read)) return 'other';
  const { rebase } = read;
  const same = rebase.chain === nameOf(chain) && rebase.seq === asked.seq && rebase.hash.equals(asked.hash);
  return same ? rebase : 'other';
}

/**
 * Moves the chain's anchor on to the place asked, its head checked whole, once the store's anchor can't be met: the
 * outcome. The store read through `anchors`, which must check rebases with this process's own key (main.ts); the
 * chain read through `live`, read-only; the one event written through `writer`.
 */
export async function rebaseChain({
  live,
  writer,
  services,
  store,
  anchors,
  chain,
  asked,
}: {
  readonly live: Database<RebaseTables>;
  readonly writer: Database<RebaseTables>;
  readonly services: SignedStatesServices;
  readonly store: WriteOnceStore;
  readonly anchors: AnchorLog;
  readonly chain: Chain;
  readonly asked: RebaseAsked;
}): Promise<RebaseOutcome> {
  const { keys, logger } = services;
  const record = (rebase: Rebase) =>
    recorded(() => recordRebase(writer, services, chain, rebase, asked), logger, rebase.id);
  await anchors.read();
  if (anchors.state() !== 'read') return { ok: false, reason: 'store' };
  const before = await storedBefore(store, keys, { epoch: anchors.epoch, chain, asked });
  if (before === 'other') return { ok: false, reason: 'done_before' };
  if (before !== undefined) return { ok: false, reason: 'done_before', recorded: await record(before) };

  const anchor = anchors.latest(chain);
  const held = await checkWhole(live, keys, chain, anchor);
  if (held.ok) return { ok: false, reason: 'not_needed', ...(anchor === undefined ? {} : { seq: anchor.seq }) };
  // Only a chain failing against its anchor is what a rebase is for: with no anchor, a failure is the chain's own.
  if (held.problem.reason !== 'anchor' || anchor === undefined) {
    return { ok: false, reason: 'broken', problem: held.problem.reason, seq: held.problem.seq };
  }
  // Whole but for the anchor: checked again without it, for the head it reaches, which must be the place asked.
  const whole = await checkWhole(live, keys, chain, undefined);
  if (!whole.ok) return { ok: false, reason: 'broken', problem: whole.problem.reason, seq: whole.problem.seq };
  if (whole.seq !== asked.seq || !whole.hash.equals(asked.hash)) {
    return { ok: false, reason: 'head_differs', seq: whole.seq };
  }
  const shorterBy = anchor.seq > whole.seq ? anchor.seq - whole.seq : 0n;
  if (shorterBy > 0n) {
    logger.warn('operator.chain_rebase_shorter', {
      rebaseId: asked.id,
      seq: whole.seq,
      anchorSeq: anchor.seq,
      shorterBy,
    });
  }
  const rebase = signRebase(keys, anchors.epoch, {
    id: asked.id,
    chain: nameOf(chain),
    seq: whole.seq,
    hash: whole.hash,
    macKeyVersion: whole.macKeyVersion,
    // The database's clock, not this job's: one clock on Azure's side, which the API's is held near (anchor-log.ts allows
    // a rebase 20 s ahead of it at most).
    at: await databaseNow(live),
    reason: asked.reason,
    evidence: asked.evidence,
    from: anchor.seq,
  });
  try {
    await store.put(rebaseFileName(anchors.epoch, asked.id), rebaseFile(rebase));
  } catch (error) {
    if (error instanceof OverwriteRefused) return { ok: false, reason: 'done_before' };
    throw error;
  }
  return { ok: true, rebase, shorterBy, recorded: await record(rebase) };
}
