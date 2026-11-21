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
import { afterCommit, type HeadKept } from '@agentx/platform/db';
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
  highest?: bigint;
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

/** A write of `chain` in `tx` that moved its head to `seq`: kept as the transaction's highest there. */
export function wroteTo(tx: object, chain: Chain, seq: bigint): void {
  const held = writtenIn.get(tx)?.get(chainNameOf(chain));
  if (held !== undefined && (held.highest === undefined || seq > held.highest)) held.highest = seq;
}

/** From a write's afterCommit: its head noted, where it is the highest the transaction moved the chain to. */
export function noteCommitted(
  tx: object,
  chain: Chain,
  head: { readonly seq: bigint; readonly hash: Buffer } | undefined,
): void {
  const held = writtenIn.get(tx)?.get(chainNameOf(chain));
  if (witness === undefined || head === undefined || held?.highest !== head.seq) return;
  witness.note(chain, head, held.klass);
}

/** The chains `tx` wrote with a `now` write: its answer waits for them (withSignedStates). */
export const nowChainsOf = (tx: object): readonly Chain[] =>
  [...(writtenIn.get(tx)?.values() ?? [])].filter(({ klass }) => klass === 'now').map(({ chain }) => chain);

/**
 * A replay's write cut out of the chain (TR-1): the head the earlier write left is no longer the chain's (below its head,
 * or another event at its place), or its row's record of it doesn't hold. Never answered as done: 503, the alarm and the
 * hold.
 */
export class WriteCutBack extends Error {
  readonly seq: bigint | undefined;

  constructor(seq: bigint | undefined) {
    super("The write this request repeats is no longer on the organisation's audit chain");
    this.name = 'WriteCutBack';
    this.seq = seq;
  }
}

/**
 * For an answer that writes nothing but tells of an earlier write (an idempotent replay, TR-1), whose own head may never
 * have gone out (its answer was the 503 for that): the chain held to the head that write left (`kept`, from its row),
 * then the chain's head as it stands witnessed `now` once `tx` commits, so the answer waits for it (withSignedStates). A
 * head at or above the write's, with the write's event at its place, covers it: every read is held to it, and a walk
 * re-hashes through it. Throws WriteCutBack where the write's head is gone from the chain, or its record is forged. A
 * head not sealed is left to every read's own alarm, witnessed never: witnessing a head the owner planted would hold the
 * organisation to it for good. One statement.
 */
export async function witnessReplayedWrite(
  tx: Transaction<unknown>,
  orgId: string,
  keys: KeyProvider,
  kept: HeadKept,
): Promise<void> {
  if (kept.kind === 'forged') throw new WriteCutBack(undefined);
  const chain: Chain = { kind: 'organisation', orgId: orgId.toLowerCase() };
  const keptAt = kept.kind === 'head' ? kept.seq : null;
  const { rows } = await sql<Record<string, unknown>>`
    select h.seq, h.hash, h.mac, h.mac_key_version,
           (select e.hash from audit.events e
            where e.org_id = ${chain.orgId} and e.seq = ${keptAt}::bigint and e.seq <= h.seq) as kept_hash
    from audit.heads h where h.org_id = ${chain.orgId}
  `.execute(tx);
  const [row] = rows;
  const head = row === undefined ? undefined : headFields(row);
  if (head === undefined || !headIsSealed(keys, chain, head)) return;
  if (kept.kind === 'head') {
    const there = row?.kept_hash;
    if (!(there instanceof Buffer) || !there.equals(kept.hash)) throw new WriteCutBack(kept.seq);
  }
  if (witness === undefined) return;
  const sealed = { seq: head.seq, hash: head.hash };
  witnessedWrite(tx, chain, 'now');
  wroteTo(tx, chain, sealed.seq);
  await afterCommit(tx, () => {
    noteCommitted(tx, chain, sealed);
  });
}

/**
 * Waits for every `now` head this process noted for the chains, those of `tx` among them: WitnessUnconfirmed past the
 * witness log's wait. Nothing without a witness log.
 */
export async function waitWitnessed(chains: readonly Chain[]): Promise<void> {
  if (witness === undefined || chains.length === 0) return;
  await witness.settled(chains);
}
