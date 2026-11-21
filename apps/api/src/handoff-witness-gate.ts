// The hand-off's witness gate (TR-1 F.6): the last thing between Tx A's commit and the bank's call, in the jobs copy.
// Tx A held the chains to every head the witness log knew of before its walk (handoff.ts `chainStops`, the pause's
// walk); a stop another copy acknowledged a moment before Tx A committed may still have been on its way to the store.
// So once Tx A has committed, and before the partner is called:
//   - Tx A's own head (`H_A`) goes out to the witness store (`witness.now`), and a refresh that begins after the commit
//     reads every other copy's, both at once;
//   - each organisation head witnessed is found on the path Tx A walked (the frontier to the head it locked), is its own
//     head, or, above the head it locked, on a read-only walk from that head (a later write, linked: fine; a fork: the
//     chain cut back below a stop, and the organisation held);
//   - each platform head witnessed is found on the platform walk Tx A made (to `P`), or above it on a walk from `P`:
//     a fork is a cut, and a pause among the events after `P` is a pause after all (fail safe).
// On any doubt (a fork, a pause, the store not answering within GATE_DEADLINE_MS, a read that didn't end whole, a walk
// past its reach, a head it can't place, the log past its memory) the partner is never called: the payment stays
// SUBMISSION_PENDING, marked UNKNOWN after UNKNOWN_AFTER_MS, and the bank check settles it; it is never resent.
// The error `handoff.held_before_sending` says why. One trip to the store and one refresh in the usual case: no walk
// unless a head was written after Tx A's walk.
import {
  type AuditTables,
  createAuditTrail,
  type FrontierStart,
  holdOrganisation,
  judgeWitnessed,
  MOST_WALKED_WITHIN,
  type WalkedWithin,
} from '@agentx/core/modules/audit';
import {
  createPlatformChain,
  HANDOFF_PAUSED,
  type PlatformControlsTables,
} from '@agentx/core/modules/platform-controls';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Chain, HeadSeen, WitnessLog } from '@agentx/platform/audit-chain';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** How long the gate waits for the store and its walks before it gives up, the payment not sent. */
export const GATE_DEADLINE_MS = 10_000;

/** What Tx A walked and wrote, for the gate: its head, and each chain's walk from where it started. */
export interface WitnessedTxA {
  readonly orgId: string;
  readonly requestId: string;
  /** The head Tx A moved the organisation's chain to (`H_A`); none where its write left none to witness. */
  readonly head: { readonly seq: bigint; readonly hash: Buffer } | undefined;
  readonly org: { readonly start: FrontierStart; readonly walk: WalkedWithin };
  readonly platform: { readonly start: FrontierStart; readonly walk: WalkedWithin };
}

export interface HandoffWitnessGate {
  /** Whether the payment may go to the partner now. Never throws: any failure is a doubt, said, and nothing sent. */
  clear(txA: WitnessedTxA, log: Logger): Promise<boolean>;
}

/** Why the gate held a payment: and, for a fork, where, and on which chain. */
interface Doubt {
  readonly reason: string;
  readonly fork?: { readonly chain: Chain['kind']; readonly seq: bigint };
}

/** The platform's pause, as the gate's walk notes it: one walked past `P` holds the payment. */
const PAUSE_STARTED = ['platform.handoff_pause', 'paused'] as const;

const PLATFORM: Chain = { kind: 'platform' };

export function createHandoffWitnessGate({
  witness,
  database,
  keys,
  ids,
  deadlineMs = GATE_DEADLINE_MS,
  most = MOST_WALKED_WITHIN,
}: {
  readonly witness: Pick<WitnessLog, 'now' | 'settled' | 'refreshWhole' | 'pending' | 'beyondMemory'>;
  readonly database: Database<AuditTables & PlatformControlsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly deadlineMs?: number;
  readonly most?: number;
}): HandoffWitnessGate {
  const trail = createAuditTrail({ keys, ids });
  // Only the pause marked: any one among the events walked past `P` is the platform pausing hand-offs after Tx A.
  const platform = createPlatformChain({
    keys,
    ids,
    subjectOf: (action) => (action === HANDOFF_PAUSED ? PAUSE_STARTED : undefined),
  });

  /** The organisation's witnessed heads against Tx A's walk, its own head and, above, a walk from the head it locked. */
  const orgDoubt = async ({ orgId, head, org }: WitnessedTxA): Promise<Doubt | undefined> => {
    if (head === undefined) return { reason: 'no_head' };
    const chain: Chain = { kind: 'organisation', orgId };
    const others: HeadSeen[] = [];
    for (const seen of witness.pending(chain)) {
      if (seen.seq !== head.seq) others.push(seen);
      else if (!seen.hash.equals(head.hash))
        return { reason: 'cut_back', fork: { chain: 'organisation', seq: seen.seq } };
    }
    const judged = judgeWitnessed(others, org.start, org.walk, 'unjudged');
    if (judged.kind === 'cut') return { reason: 'cut_back', fork: { chain: 'organisation', seq: judged.seq } };
    if (judged.kind === 'held') return undefined;
    // Below where Tx A's stretch began: nothing here to place it on.
    if (judged.seqs.some((seq) => seq <= org.walk.head.seq)) return { reason: 'unjudged' };
    const above = others.filter(({ seq }) => seq > org.walk.head.seq);
    const step = await trail.checkFromAnchor(database, orgId, org.walk.head, most, [...above, head]);
    if (!step.ok) return { reason: step.problem.reason, fork: { chain: 'organisation', seq: step.problem.seq } };
    return step.seq === step.to ? undefined : { reason: 'too_far' };
  };

  /** The platform's witnessed heads against Tx A's walk to `P`, and above it a walk from `P` that must hold no pause. */
  const platformDoubt = async ({ platform: walked }: WitnessedTxA): Promise<Doubt | undefined> => {
    const pending = witness.pending(PLATFORM);
    const judged = judgeWitnessed(pending, walked.start, walked.walk, 'unjudged');
    if (judged.kind === 'cut') return { reason: 'platform_cut_back', fork: { chain: 'platform', seq: judged.seq } };
    if (judged.kind === 'held') return undefined;
    if (judged.seqs.some((seq) => seq <= walked.walk.head.seq)) return { reason: 'unjudged' };
    const above = pending.filter(({ seq }) => seq > walked.walk.head.seq);
    const step = await platform.checkFromAnchor(database, walked.walk.head, most, above);
    if (!step.ok)
      return { reason: `platform_${step.problem.reason}`, fork: { chain: 'platform', seq: step.problem.seq } };
    if (step.seq !== step.to) return { reason: 'too_far' };
    return step.signed === undefined || step.signed.size === 0 ? undefined : { reason: 'paused' };
  };

  /** The gate's own judgement: a doubt, or none and the payment goes. */
  const doubtOf = async (txA: WitnessedTxA): Promise<Doubt | undefined> => {
    const chain: Chain = { kind: 'organisation', orgId: txA.orgId };
    if (txA.head === undefined) return { reason: 'no_head' };
    // Tx A's head out, and a read of the store begun after the commit, at once. Its commit noted it already (`now`,
    // its Put under way): waited for, never a second line; one not noted is noted now.
    const { seq, hash } = txA.head;
    const noted = witness.pending(chain).some((seen) => seen.seq === seq && seen.hash.equals(hash));
    const out = noted ? witness.settled([chain]) : witness.now(chain, txA.head);
    const [put, read] = await Promise.allSettled([out, witness.refreshWhole()]);
    if (put.status === 'rejected') return { reason: 'witness_unconfirmed' };
    if (read.status === 'rejected' || !read.value) return { reason: 'witness_unread' };
    if (witness.beyondMemory(chain) || witness.beyondMemory(PLATFORM)) return { reason: 'witness_pending' };
    return (await orgDoubt(txA)) ?? (await platformDoubt(txA));
  };

  /** doubtOf within the deadline: past it, or failing, a doubt of its own. */
  const withinDeadline = async (txA: WitnessedTxA): Promise<Doubt | undefined> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<Doubt>((resolve) => {
      timer = setTimeout(() => {
        resolve({ reason: 'deadline' });
      }, deadlineMs);
      timer.unref();
    });
    try {
      return await Promise.race([doubtOf(txA), late]);
    } catch {
      return { reason: 'gate_failed' };
    } finally {
      clearTimeout(timer);
    }
  };

  return Object.freeze({
    async clear(txA: WitnessedTxA, log: Logger): Promise<boolean> {
      const doubt = await withinDeadline(txA);
      if (doubt === undefined) return true;
      const { fork } = doubt;
      log.error('handoff.held_before_sending', {
        requestId: txA.requestId,
        reason: doubt.reason,
        ...(fork === undefined ? {} : { chain: fork.chain, seq: String(fork.seq) }),
      });
      if (fork !== undefined) {
        log.error('audit.integrity_failed', {
          chain: fork.chain,
          check: 'witness',
          reason: 'cut_back',
          seq: String(fork.seq),
        });
      }
      // A fork of the organisation's own chain holds it, as the anchor check would (never throws).
      if (fork?.chain === 'organisation') {
        await holdOrganisation(database, txA.orgId, { keys, ids, logger: log }, 'cut_back');
      }
      return false;
    },
  });
}
