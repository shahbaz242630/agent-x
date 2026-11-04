// A chain's rebase (4D2e E11; playbook H): after a sanctioned change to an
// audit chain (an organisation's chain repaired, E10; the platform chain begun
// again), its anchor in the store can't be met, and the API's check would raise
// the alarm for good. This moves the anchor on: it reads the anchors' store
// (rebases first, as the API does), checks the live chain whole from its first
// event, and writes one signed rebase line naming the chain, the head it
// reached, why and the incident's reference, to `e<epoch>/rebases/<ID>`.
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
// - `done_before`: a rebase of this ID is in the store already
//
// Signed with `audit-rebase`, which only the operator's job holds (OPERATOR_ONLY).
// Read-only on the database; the store's file is its one write, added once.
import { type AuditTables, createAuditTrail } from '@agentx/core/modules/audit';
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
  signRebase,
} from '@agentx/platform/audit-chain';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { OverwriteRefused, type WriteOnceStore } from '@agentx/platform/storage';

/** Why a rebase is refused. */
type RebaseRefusal = 'store' | 'not_needed' | 'broken' | 'done_before';

export type RebaseOutcome =
  | {
      readonly ok: true;
      readonly rebase: Rebase;
      /** The anchor it moves on from, if the chain had one. */
      readonly anchorSeq: bigint | undefined;
    }
  | {
      readonly ok: false;
      readonly reason: RebaseRefusal;
      /** For `broken`, the chain's own check's reason. */
      readonly problem?: string;
      /** Where: the problem's event, or for `not_needed` the anchor's. */
      readonly seq?: bigint;
    };

/** The tables a rebase reads: either chain's. */
export type RebaseTables = AuditTables & PlatformControlsTables;

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

/**
 * Moves the chain's anchor on to its head, checked whole, once the store's anchor can't be met: the outcome. The store
 * read through `anchors`, which must check rebases with this process's own key (main.ts).
 */
export async function rebaseChain({
  live,
  keys,
  store,
  anchors,
  chain,
  asked,
  now,
}: {
  readonly live: Database<RebaseTables>;
  readonly keys: KeyProvider;
  readonly store: WriteOnceStore;
  readonly anchors: AnchorLog;
  readonly chain: Chain;
  readonly asked: { readonly id: string; readonly reason: RebaseReason; readonly evidence: string };
  readonly now: () => Date;
}): Promise<RebaseOutcome> {
  await anchors.read();
  if (anchors.state() !== 'read') return { ok: false, reason: 'store' };
  const anchor = anchors.latest(chain);
  const held = await checkWhole(live, keys, chain, anchor);
  if (held.ok) return { ok: false, reason: 'not_needed', ...(anchor === undefined ? {} : { seq: anchor.seq }) };
  if (held.problem.reason !== 'anchor') {
    return { ok: false, reason: 'broken', problem: held.problem.reason, seq: held.problem.seq };
  }
  // Whole but for the anchor: checked again without it, for the head it reaches.
  const whole = await checkWhole(live, keys, chain, undefined);
  if (!whole.ok) return { ok: false, reason: 'broken', problem: whole.problem.reason, seq: whole.problem.seq };
  const rebase = signRebase(keys, anchors.epoch, {
    id: asked.id,
    chain: nameOf(chain),
    seq: whole.seq,
    hash: whole.hash,
    macKeyVersion: whole.macKeyVersion,
    at: now(),
    reason: asked.reason,
    evidence: asked.evidence,
  });
  try {
    await store.put(rebaseFileName(anchors.epoch, asked.id), rebaseFile(rebase));
  } catch (error) {
    if (error instanceof OverwriteRefused) return { ok: false, reason: 'done_before' };
    throw error;
  }
  return { ok: true, rebase, anchorSeq: anchor?.seq };
}
