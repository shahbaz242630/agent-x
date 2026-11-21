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
import type { Chain, ChainWitness, WitnessClass } from '@agentx/platform/audit-chain';
import { afterCommit } from '@agentx/platform/db';
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

/** The chains `tx` wrote with a `now` write: its answer waits for them (withSignedStates). */
export const nowChainsOf = (tx: object): readonly Chain[] =>
  [...(writtenIn.get(tx)?.values() ?? [])].filter(({ klass }) => klass === 'now').map(({ chain }) => chain);

/**
 * The organisation's chain head as it stands, witnessed `now` once `tx` commits (TR-1): for an answer that writes
 * nothing but tells of an earlier write (an idempotent replay), whose own head may never have been witnessed. A head
 * witnessed at or above that write's covers it: every read is held to it, and a walk re-hashes through it. One statement.
 */
export async function witnessHeadAsItStands(tx: Transaction<unknown>, orgId: string): Promise<void> {
  if (witness === undefined) return;
  const chain: Chain = { kind: 'organisation', orgId: orgId.toLowerCase() };
  const { rows } = await sql<{ seq: unknown; hash: unknown }>`
    select h.seq, h.hash from audit.heads h where h.org_id = ${chain.orgId}
  `.execute(tx);
  const [row] = rows;
  if (row === undefined || typeof row.seq !== 'bigint' || !(row.hash instanceof Buffer)) return;
  const head = { seq: row.seq, hash: row.hash };
  witnessedWrite(tx, chain, 'now');
  wroteTo(tx, chain, head);
  await afterCommit(tx, () => {
    noteCommitted(tx, chain, head);
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
