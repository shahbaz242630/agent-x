// The audit chains' mechanics (ADR-011 §3, ADR-012 §2): one chain per
// organisation, kept by the audit module, and the platform's own, kept by
// platform-controls. Both store their events their own way and seal and check
// them here, so the two can't drift apart.
//
// Each event is linked to the one before it: its hash is SHA-256 of the
// previous event's hash and its own content. The hash alone can be recomputed
// by anyone who can read the rows, the database owner included, so every event
// also carries a MAC made with the `audit-mac` key, which the database never
// holds: an event edited, or appended correctly chained, by someone without
// the key fails its MAC. The chain's head (its last sequence number and hash)
// carries a MAC too. What the MACs can't catch is a chain wound back to an
// older state that was valid at the time; that is the anchor check's job.
//
// Every hash and MAC names its chain, so an event or head copied into another
// chain fails, and starts with a label naming what it is, so a MAC made for
// one thing can never stand for another. Along a chain the MAC key's version
// never goes down: an event is sealed with the chain's version when this
// process's current one is older (a release rolled back, or an old one still
// running during a rotation), and the check refuses an event older than the
// one before it. So once a key is rotated out, whoever may have copied it
// can't add events after the rotation. Every process that records needs every
// version the chains have reached: new keys are installed before one is made
// current.
import { createHash } from 'node:crypto';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import { encodeMessage, type Message } from '../keys/message.ts';

/** Which chain: an organisation's, or the platform's own. */
export type Chain = { readonly kind: 'organisation'; readonly orgId: string } | { readonly kind: 'platform' };

/** SHA-256: every hash is 32 bytes. */
const HASH_BYTES = 32;

/** The hash a chain starts from, before its first event. */
export const GENESIS_HASH: Buffer = Buffer.alloc(HASH_BYTES);

/** An event to seal, as its module gives it. */
export interface ChainEntry {
  /** Its place in the chain: 1 for the first event, then one more each time. */
  readonly seq: bigint;
  readonly id: string;
  readonly recordedAt: Date;
  /** The module's own fields, as a list of parts, each group starting with a label (`actor`, `action`, …). */
  readonly content: Message;
}

/** What sealing adds to an event, all of it stored with the event. */
export interface ChainLink {
  /** The previous event's hash, or GENESIS_HASH for the first. */
  readonly prevHash: Buffer;
  readonly hash: Buffer;
  readonly mac: Buffer;
  readonly macKeyVersion: number;
}

/** An event as it was read back, to be checked. */
export interface StoredEntry extends ChainEntry, ChainLink {}

/** The chain's last sequence number and hash (0 and GENESIS_HASH while it is empty), with their MAC. */
export interface ChainHead {
  readonly seq: bigint;
  readonly hash: Buffer;
  readonly mac: Buffer;
  readonly macKeyVersion: number;
}

/** Sealing refused: the event isn't the next one after the head it was given. */
export class ChainSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChainSealError';
  }
}

/** The chain's name in every hash, MAC and signature: `platform`, or `organisation:` and its ID. */
export function chainName(chain: Chain): string {
  return chain.kind === 'platform' ? 'platform' : `organisation:${chain.orgId}`;
}

/** SHA-256 over the chain, the previous hash and the event. */
export function linkHash(chain: Chain, prevHash: Uint8Array, entry: ChainEntry): Buffer {
  const message: Message = [
    'audit-link',
    chainName(chain),
    prevHash,
    entry.seq.toString(),
    entry.id,
    entry.recordedAt.toISOString(),
    ...entry.content,
  ];
  return createHash('sha256').update(encodeMessage(message)).digest();
}

const eventMacMessage = (chain: Chain, seq: bigint, id: string, hash: Uint8Array): Message => [
  'audit-event',
  chainName(chain),
  seq.toString(),
  id,
  hash,
];

const headMacMessage = (chain: Chain, seq: bigint, hash: Uint8Array): Message => [
  'audit-head',
  chainName(chain),
  seq.toString(),
  hash,
];

/** A head with its MAC, made with the current key. */
function sealHead(keys: KeyProvider, chain: Chain, seq: bigint, hash: Buffer, atLeast?: number): ChainHead {
  const { mac, keyVersion } = keys.mac('audit-mac', headMacMessage(chain, seq, hash), atLeast);
  return Object.freeze({ seq, hash, mac, macKeyVersion: keyVersion });
}

/** The head of a chain with no events yet. */
export function genesisHead(keys: KeyProvider, chain: Chain): ChainHead {
  return sealHead(keys, chain, 0n, GENESIS_HASH);
}

/**
 * Whether a MAC is the one for the message under that key version. A MAC that
 * isn't 32 bytes, or a version the app doesn't hold, is simply wrong: what the
 * database hands back can't be trusted to be well formed.
 */
function macMatches(keys: KeyProvider, keyVersion: number, message: Message, mac: Uint8Array): boolean {
  try {
    return keys.verifyMac('audit-mac', keyVersion, message, mac);
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/** Whether the head's MAC is right for its sequence number and hash. */
export function headIsSealed(keys: KeyProvider, chain: Chain, head: ChainHead): boolean {
  return macMatches(keys, head.macKeyVersion, headMacMessage(chain, head.seq, head.hash), head.mac);
}

/**
 * Seals the event that follows `head`: its link and MAC, and the chain's new
 * head, with the head's key version where it is newer than the current one.
 * The caller checks the head first (headIsSealed) and holds its lock, so no
 * other event can take the same place.
 */
export function sealNext(
  keys: KeyProvider,
  chain: Chain,
  head: ChainHead,
  entry: ChainEntry,
): { readonly link: ChainLink; readonly head: ChainHead } {
  if (entry.seq !== head.seq + 1n) {
    throw new ChainSealError(
      `the event is numbered ${entry.seq.toString()}, but the next place after the head is ${(head.seq + 1n).toString()}`,
    );
  }
  const hash = linkHash(chain, head.hash, entry);
  const { mac, keyVersion } = keys.mac(
    'audit-mac',
    eventMacMessage(chain, entry.seq, entry.id, hash),
    head.macKeyVersion,
  );
  return Object.freeze({
    link: Object.freeze({ prevHash: head.hash, hash, mac, macKeyVersion: keyVersion }),
    head: sealHead(keys, chain, entry.seq, hash, keyVersion),
  });
}

/**
 * Why a chain fails its check, at the first place it does:
 * - `gap`: the event numbered `seq` is missing
 * - `link`: the event doesn't point at the one before it
 * - `hash`: the event's content doesn't match its hash
 * - `mac`: the event's MAC is missing or wrong, made with a key the app doesn't hold, or made with an
 *   older key version than an event before it
 * - `unreadable`: the stored event can't be read as an event at all
 * - `head`: the head's MAC is wrong, it isn't at the last event, or the store holds events it doesn't count
 * - `anchor`: the chain no longer holds what was last anchored: the head is behind the anchor, or the
 *   anchored event isn't the one anchored (a chain wound back, or grown again on a wound-back head)
 */
export type ChainProblemReason = 'gap' | 'link' | 'hash' | 'mac' | 'unreadable' | 'head' | 'anchor';

/** A place in a chain the app has seen and signed (ADR-012 §2): the chain must still hold it. */
export interface AnchorPoint {
  readonly seq: bigint;
  readonly hash: Buffer;
}

export interface ChainProblem {
  readonly reason: ChainProblemReason;
  /** Where: the event's sequence number, or for `head`, the head's. */
  readonly seq: bigint;
}

/** A chain that checks out, up to its head, or the first problem found. */
export type ChainReport =
  | { readonly ok: true; readonly seq: bigint; readonly hash: Buffer }
  | { readonly ok: false; readonly problem: ChainProblem };

/**
 * Where a chain's store stands: its head, and how many events it holds, read
 * in one statement so both come from the same moment. An event and the head
 * that points at it are written in one transaction, so the head's number is
 * the count unless someone went round the app: an event added past the head,
 * or at a number the check never reads, or the tail deleted and the head left.
 * With the count equal to the head's number and events 1 to that number all
 * found in turn, there is no room for any other.
 */
export interface ChainState {
  readonly head: ChainHead;
  readonly stored: bigint;
  /** The last anchor, if the chain has one: the chain must still hold it (ADR-012 §2). */
  readonly anchor?: AnchorPoint | undefined;
}

/**
 * Checks a chain's events one at a time, in order, against the state read
 * before them. Reading that first matters: events keep being added while a
 * chain is checked, and those past the head are simply not read. Events up to
 * it can't change, so the chain checked is the one the head described.
 */
export interface ChainVerifier {
  /** Checks the next event; the first problem ends the check. */
  check(entry: StoredEntry): ChainProblem | undefined;
  /** The next event's row can't be read as an event (a field missing or of the wrong type): a problem at its place. */
  unreadable(): ChainProblem;
  /** Once every event up to the head has been given: the verdict. */
  finish(): ChainReport;
}

export function createChainVerifier(
  keys: KeyProvider,
  chain: Chain,
  { head, stored, anchor }: ChainState,
): ChainVerifier {
  let seq = 0n;
  let hash: Buffer = GENESIS_HASH;
  let keyVersion = 0;
  let problem: ChainProblem | undefined = headIsSealed(keys, chain, head)
    ? undefined
    : { reason: 'head', seq: head.seq };

  const problemWith = (entry: StoredEntry): ChainProblem | undefined => {
    const expected = seq + 1n;
    if (entry.seq !== expected) return { reason: 'gap', seq: expected };
    if (!entry.prevHash.equals(hash)) return { reason: 'link', seq: expected };
    if (!linkHash(chain, entry.prevHash, entry).equals(entry.hash)) return { reason: 'hash', seq: expected };
    const message = eventMacMessage(chain, entry.seq, entry.id, entry.hash);
    if (entry.macKeyVersion < keyVersion || !macMatches(keys, entry.macKeyVersion, message, entry.mac)) {
      return { reason: 'mac', seq: expected };
    }
    // Sealed and in place, but not the event anchored there: this is a chain grown again on a wound-back head.
    if (anchor?.seq === entry.seq && !anchor.hash.equals(entry.hash)) return { reason: 'anchor', seq: expected };
    return undefined;
  };

  return {
    check(entry) {
      if (problem !== undefined) return problem;
      problem = problemWith(entry);
      if (problem === undefined) {
        seq = entry.seq;
        hash = entry.hash;
        keyVersion = entry.macKeyVersion;
      }
      return problem;
    },
    unreadable() {
      problem ??= { reason: 'unreadable', seq: seq + 1n };
      return problem;
    },
    finish() {
      // Compared last, so a missing event is reported where it is missing. The hash settles where the chain
      // ended (it covers its event's number, and a head can't be sealed without the key); the count, that
      // the store holds nothing else.
      if (problem === undefined && (stored !== head.seq || !hash.equals(head.hash))) {
        problem = { reason: 'head', seq: head.seq };
      }
      // A whole chain can be wound back to an earlier head it once had: only the anchor, held apart, shows it.
      if (problem === undefined && anchor !== undefined && head.seq < anchor.seq) {
        problem = { reason: 'anchor', seq: anchor.seq };
      }
      return problem === undefined ? { ok: true, seq, hash } : { ok: false, problem };
    },
  };
}
