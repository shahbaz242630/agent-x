// The operator's own signature on its events (PL-57), on the platform chain and
// every organisation's alike. An event whose actor is the operator's command is
// sealed by the chains' MAC as every event is (any writer seals), and also
// signed with `operator-signing`, a key only the operator's job holds: the MAC
// says the event is the chain's, the signature that the operator wrote it. The
// signature covers the event's chain, place, ID and hash, so one moved onto
// another event, or another chain, doesn't check.
//
// A store reads each event with its signature, if any, and where signing
// started on its chain (`signed_from`, written by 0079 as the owner, which no
// running role can move). An operator's event before it needs none (it was
// recorded before PL-57); one from it on needs its own, or reads as unsealed:
// its MAC is taken as missing, so every check reports it where a MAC's failure
// would be.
import { KeyError, type KeyProvider, type Signature } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { type Chain, chainName, type StoredEntry } from './chain.ts';
import { sealedFields } from './store.ts';

/** The operator's command's process name (apps/operator): its events are believed only signed with its own key. */
export const OPERATOR_ID = 'operator';

/** What the operator's key signs for one of its events: its chain, place, ID and hash, which covers the rest. */
const operatorEventMessage = (chain: Chain, seq: bigint, id: string, hash: Uint8Array): Message => [
  'operator-event',
  chainName(chain),
  seq.toString(),
  id,
  hash,
];

/**
 * The operator's signature for an event it is recording, or nothing for any
 * other actor's. A process without the operator's key (the API) can't make
 * one: the key provider refuses, and so the event is never written.
 */
export function operatorSignature(
  keys: KeyProvider,
  chain: Chain,
  actorId: string,
  sealed: { readonly seq: bigint; readonly id: string; readonly hash: Uint8Array },
): Signature | undefined {
  return actorId === OPERATOR_ID
    ? keys.sign('operator-signing', operatorEventMessage(chain, sealed.seq, sealed.id, sealed.hash))
    : undefined;
}

/**
 * Whether a stored event has the signature it needs: none for an event not
 * the operator's, nor for one recorded before signing started on its chain;
 * otherwise its own, by the operator's key. A row read without the signature's
 * columns has none to show, and an operator's event in it isn't believed.
 */
function operatorSigned(
  keys: KeyProvider,
  chain: Chain,
  row: Readonly<Record<string, unknown>>,
  sealed: Omit<StoredEntry, 'content'>,
): boolean {
  if (row.actor_id !== OPERATOR_ID) return true;
  if (!('signed_from' in row)) return false;
  const { signature, signature_key_version: version, signed_from: from } = row;
  // Unsigned: believed only before signing started; with no start to read, never.
  if (signature === null) return typeof from === 'bigint' && sealed.seq < from;
  if (!Buffer.isBuffer(signature) || typeof version !== 'number') return false;
  try {
    const message = operatorEventMessage(chain, sealed.seq, sealed.id, sealed.hash);
    return keys.verifySignature('operator-signing', version, message, signature);
  } catch (error) {
    // A version the process has no public half for is simply not the operator's.
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/** sealedFields, its MAC taken as missing when the event lacks the operator's signature it needs. */
export function sealedSigned(
  keys: KeyProvider,
  chain: Chain,
  row: Readonly<Record<string, unknown>>,
): Omit<StoredEntry, 'content'> | undefined {
  const sealed = sealedFields(row);
  if (sealed === undefined) return undefined;
  return operatorSigned(keys, chain, row, sealed) ? sealed : { ...sealed, mac: Buffer.alloc(0) };
}
