// Every committed chain write's head to the witness log (TR-1, @agentx/platform/audit-chain's witness-log.ts): the
// organisations' chains (audit-trail.ts) and the platform's (platform-chain.ts) each note the head their transaction
// moved the chain to once it commits, in the afterCommit hook the head's raise already has (AT13h): no trip. Whether or
// not the write ran through the head this process held to: a write on a cut chain is still a head someone may later
// cut, and noting it raises no read here (the digest's own raise decides that).
//
// One transaction notes each chain once, at the highest head it moved it to, as `now` if any of its writes there is
// (witness-class.ts). Only where nothing that could undo part of the transaction was sent after the write (afterCommit's
// rule): a head that may not have committed is never noted, as a head noted but never committed would read as a cut and
// hold the organisation for nothing. Such a transaction leaves its head unwitnessed: protection missing, never an alarm.
//
// withSignedStates waits, after its transaction, for its `now` heads and any this process holds unconfirmed for the
// organisation (`waitWitnessed`): WitnessUnconfirmed is the request's 503, its change saved, the head still queued.
import {
  type Chain,
  type ChainWitness,
  headFields,
  headIsSealed,
  type WitnessClass,
} from '@agentx/platform/audit-chain';
import { afterCommit, type HeadKept, type KeptHead } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { sql, type Transaction } from 'kysely';

import { strongerClass } from './witness-class.ts';

/** The witness log this process notes to, given at boot; none in a process with no witness store. */
let witness: ChainWitness | undefined;

/** The witness log every chain write here is noted to from now on, or (undefined) none: once, at boot. */
export function witnessWith(given: ChainWitness | undefined): void {
  witness = given;
}

/** The witness log given at boot, if any: for the chains' writes and reads held to it outside this module. */
export const chainWitness = (): ChainWitness | undefined => witness;

/** What one transaction wrote to each chain: the highest head and the class so far, by the chain's name. */
interface Written {
  readonly chain: Chain;
  klass: WitnessClass;
  highest?: { readonly seq: bigint; readonly hash: Buffer };
}

const writtenIn = new WeakMap<object, Map<string, Written>>();

/** A chain's key here: the platform's, or an organisation's ID in lower case, as the chains' writers name it. */
const chainNameOf = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : chain.orgId.toLowerCase());

/** A write of `chain` in `tx` beginning, of class `klass`: merged into the transaction's for that chain. */
export function witnessedWrite(tx: object, chain: Chain, klass: WitnessClass): void {
  const byChain = writtenIn.get(tx) ?? new Map<string, Written>();
  writtenIn.set(tx, byChain);
  const name = chainNameOf(chain);
  const held = byChain.get(name);
  if (held === undefined) byChain.set(name, { chain, klass });
  else held.klass = strongerClass(held.klass, klass);
}

/** A write of `chain` in `tx` that moved its head to `head`: kept as the transaction's highest there. */
export function wroteTo(tx: object, chain: Chain, head: { readonly seq: bigint; readonly hash: Buffer }): void {
  const held = writtenIn.get(tx)?.get(chainNameOf(chain));
  if (held !== undefined && (held.highest === undefined || head.seq > held.highest.seq)) held.highest = head;
}

/**
 * The highest head `tx` moved `chain` to, once it committed: what the hand-off's gate witnesses before the bank's call
 * (TR-1 F.5, `H_A`). None where nothing was written there, or no witness log is given.
 */
export const headWrittenIn = (tx: object, chain: Chain): { readonly seq: bigint; readonly hash: Buffer } | undefined =>
  writtenIn.get(tx)?.get(chainNameOf(chain))?.highest;

/** From a write's afterCommit: its head noted, where it is the highest the transaction moved the chain to. */
export function noteCommitted(
  tx: object,
  chain: Chain,
  head: { readonly seq: bigint; readonly hash: Buffer } | undefined,
): void {
  const held = writtenIn.get(tx)?.get(chainNameOf(chain));
  if (witness === undefined || head === undefined || held?.highest?.seq !== head.seq) return;
  witness.note(chain, head, held.klass);
}

/**
 * The head `tx` moved `chain` to, noted again once it commits (TR-3): for a write whose afterCommit note a later
 * savepoint's rollback dropped (a hold's own head, after its mark gave way), though the write itself stands. Nothing
 * where nothing was written there, or no witness log is given.
 */
export async function noteAgainOnCommit(tx: Transaction<unknown>, chain: Chain): Promise<void> {
  const head = headWrittenIn(tx, chain);
  if (witness === undefined || head === undefined) return;
  await afterCommit(tx, () => {
    noteCommitted(tx, chain, head);
  });
}

/** The chains `tx` wrote with a `now` write: its answer waits for them (withSignedStates). */
export const nowChainsOf = (tx: object): readonly Chain[] =>
  [...(writtenIn.get(tx)?.values() ?? [])].filter(({ klass }) => klass === 'now').map(({ chain }) => chain);

/**
 * A replay's write cut out of a chain (TR-1): a head the earlier write left is no longer its chain's (missing, not
 * sealed, below its head, another event at its place, or the next event not linked to it), or the row's record of the
 * heads doesn't hold. Never answered as done: 503, the alarm and the hold.
 */
export class WriteCutBack extends Error {
  readonly seq: bigint | undefined;
  /** Where the row's record of the heads failed rather than a chain: rewritten (`forged`) or taken away (`missing`). */
  readonly record: 'forged' | 'missing' | undefined;
  /** The chain the write was cut from. */
  readonly chain: 'organisation' | 'platform';

  constructor(
    seq: bigint | undefined,
    record?: 'forged' | 'missing',
    chain: 'organisation' | 'platform' = 'organisation',
  ) {
    super('The write this request repeats is no longer on the audit chain');
    this.name = 'WriteCutBack';
    this.seq = seq;
    this.record = record;
    this.chain = chain;
  }
}

/** A chain's head and, where a kept head is asked, what stands at its place and the next: one statement's columns. */
interface HeadAndKept {
  readonly head: { readonly seq: bigint; readonly hash: Buffer } | undefined;
  readonly keptHash: unknown;
  readonly nextPrev: unknown;
}

/**
 * Whether the chain still holds the head a write left (`kept`): the chain's head sealed and at or past it, the event at
 * its place with its hash, and the next event, where there is one, linked to it (so a row put back beside a cut branch
 * stands alone, and fails); at the head's own place, the head itself.
 */
const stillHolds = ({ head, keptHash, nextPrev }: HeadAndKept, kept: KeptHead): boolean => {
  if (head === undefined || head.seq < kept.seq) return false;
  if (!(keptHash instanceof Buffer) || !keptHash.equals(kept.hash)) return false;
  if (head.seq === kept.seq) return head.hash.equals(kept.hash);
  return nextPrev instanceof Buffer && nextPrev.equals(kept.hash);
};

/** The organisation's head, sealed or none, and what stands at the kept place and after it: one statement. */
async function orgHeadRead(
  tx: Transaction<unknown>,
  keys: KeyProvider,
  chain: Chain & { readonly kind: 'organisation' },
  kept: KeptHead | undefined,
): Promise<HeadAndKept> {
  const at = kept?.seq ?? null;
  const { rows } = await sql<Record<string, unknown>>`
    select h.seq, h.hash, h.mac, h.mac_key_version,
      (select e.hash from audit.events e where e.org_id = ${chain.orgId} and e.seq = ${at}::bigint and e.seq <= h.seq)
        as kept_hash,
      (select e.prev_hash from audit.events e
       where e.org_id = ${chain.orgId} and e.seq = ${at}::bigint + 1 and e.seq <= h.seq) as next_prev
    from audit.heads h where h.org_id = ${chain.orgId}
  `.execute(tx);
  const [row] = rows;
  const head = row === undefined ? undefined : headFields(row);
  return {
    head: head !== undefined && headIsSealed(keys, chain, head) ? { seq: head.seq, hash: head.hash } : undefined,
    keptHash: row?.kept_hash,
    nextPrev: row?.next_prev,
  };
}

/** The platform's head, sealed and the one row or none, and what stands at the kept place and after it: one statement. */
async function platformHeadRead(
  tx: Transaction<unknown>,
  keys: KeyProvider,
  kept: KeptHead | undefined,
): Promise<HeadAndKept> {
  const at = kept?.seq ?? null;
  const { rows } = await sql<Record<string, unknown>>`
    select h.seq, h.hash, h.mac, h.mac_key_version,
      (select pg_catalog.count(*) from platform_controls.audit_head) as heads,
      (select e.hash from platform_controls.audit_events e where e.seq = ${at}::bigint and e.seq <= h.seq limit 1)
        as kept_hash,
      (select e.prev_hash from platform_controls.audit_events e
       where e.seq = ${at}::bigint + 1 and e.seq <= h.seq limit 1) as next_prev
    from platform_controls.audit_head h
  `.execute(tx);
  const [row, ...more] = rows;
  const head = row === undefined || more.length > 0 ? undefined : headFields(row);
  return {
    head:
      head !== undefined && headIsSealed(keys, { kind: 'platform' }, head)
        ? { seq: head.seq, hash: head.hash }
        : undefined,
    keptHash: row?.kept_hash,
    nextPrev: row?.next_prev,
  };
}

/** The chain's head as it stands witnessed `now` once `tx` commits: the answer waits for it (withSignedStates). */
async function witnessOnCommit(
  tx: Transaction<unknown>,
  chain: Chain,
  head: { readonly seq: bigint; readonly hash: Buffer },
): Promise<void> {
  if (witness === undefined) return;
  witnessedWrite(tx, chain, 'now');
  wroteTo(tx, chain, head);
  await afterCommit(tx, () => {
    noteCommitted(tx, chain, head);
  });
}

/**
 * For an answer that writes nothing but tells of an earlier write (an idempotent replay, TR-1), whose own heads may never
 * have gone out (its answer was the 503 for that): each chain held to the head that write left there (`kept`, from its
 * row: the organisation's, and the platform's where it recorded there), then that chain's head as it stands witnessed
 * `now`, so the answer waits for it. A head at or above the write's, with the write's event at its place linked onward,
 * covers it: every read is held to it, and a walk re-hashes through it. Throws WriteCutBack where a kept head is gone
 * from its chain (its head missing or not sealed among those), or the row's record of the heads fails. A head not sealed
 * where nothing is kept on its chain (a legacy row, or a write that recorded nothing there) is left to every read's own
 * alarm, witnessed never: witnessing a head the owner planted would hold the organisation to it for good.
 */
export async function witnessReplayedWrite(
  tx: Transaction<unknown>,
  orgId: string,
  keys: KeyProvider,
  kept: HeadKept,
): Promise<void> {
  if (kept.kind === 'forged') throw new WriteCutBack(undefined, kept.missing === true ? 'missing' : 'forged');
  const chain = { kind: 'organisation', orgId: orgId.toLowerCase() } as const;
  const org = kept.kind === 'sealed' ? kept.org : undefined;
  const orgRead = await orgHeadRead(tx, keys, chain, org);
  if (org !== undefined && !stillHolds(orgRead, org)) throw new WriteCutBack(org.seq);
  if (kept.kind === 'sealed' && kept.platform !== undefined) {
    const platformRead = await platformHeadRead(tx, keys, kept.platform);
    if (!stillHolds(platformRead, kept.platform)) throw new WriteCutBack(kept.platform.seq, undefined, 'platform');
    if (platformRead.head !== undefined) await witnessOnCommit(tx, { kind: 'platform' }, platformRead.head);
  }
  if (orgRead.head !== undefined) await witnessOnCommit(tx, chain, orgRead.head);
}

/**
 * Waits for every `now` head this process noted for the chains, those of `tx` among them: WitnessUnconfirmed past the
 * witness log's wait. Nothing without a witness log.
 */
export async function waitWitnessed(chains: readonly Chain[]): Promise<void> {
  if (witness === undefined || chains.length === 0) return;
  await witness.settled(chains);
}
