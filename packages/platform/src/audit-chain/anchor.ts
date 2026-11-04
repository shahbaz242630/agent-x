// Anchors (ADR-011 §3, ADR-012 §2): a chain's head as the app last found it,
// whole and checked, signed with the `audit-anchor` key. The chain's own seals
// can't show a chain wound back to an earlier state, since every earlier head
// was genuinely sealed once; an anchor held apart from the database can. The
// check compares each chain with its last anchor (verifyChain), then anchors
// it again.
//
// Deployed, every anchor is also kept in a write-once store apart from the
// database (anchor-log.ts, PL-58), so a rollback made while no process ran shows
// too. In development and test with no store, the last anchor stays in memory
// alone, as `createMemoryAnchorStore` here. The signature is what the store
// keeps: anyone can check it with the public key the API logs at start
// (`api.starting`, keys).
import type { KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { type Chain, chainName, type CheckedPoint } from './chain.ts';

export interface Anchor extends CheckedPoint {
  /** The chain's name, as its hashes and MACs name it. */
  readonly chain: string;
  /** When the app anchored it. */
  readonly at: Date;
  /** The signing key's version; `macKeyVersion` is the audit MAC key's at the anchored event, signed with the rest. */
  readonly keyVersion: number;
  /** Ed25519 over `['audit-anchor', epoch, chain, seq, hash, macKeyVersion, at]`, as length-prefixed parts. */
  readonly signature: Buffer;
}

/** Where the last anchor of each chain is kept. */
export interface AnchorStore {
  latest(chain: Chain): Anchor | undefined;
  keep(anchor: Anchor): void;
}

/** The epoch of an anchor kept in memory alone: real ones count from 1, and it's never written, so never read back. */
const NO_EPOCH = 0;

/** What an anchor's signature covers: the epoch too, so a line copied from one into another fails. */
export const anchorMessage = (chain: string, point: CheckedPoint, at: Date, epoch: number): Message => [
  'audit-anchor',
  String(epoch),
  chain,
  point.seq.toString(),
  point.hash,
  point.macKeyVersion.toString(),
  at.toISOString(),
];

/** A place in a chain signed with the `audit-anchor` key, over the message `messageOf` makes for it. */
function signedLine(
  keys: KeyProvider,
  chain: Chain,
  point: CheckedPoint,
  at: Date,
  epoch: number,
  messageOf: typeof anchorMessage,
): Anchor {
  const name = chainName(chain);
  const { signature, keyVersion } = keys.sign('audit-anchor', messageOf(name, point, at, epoch));
  const { seq, hash, macKeyVersion } = point;
  return Object.freeze({ chain: name, seq, hash, macKeyVersion, at, keyVersion, signature });
}

/** Signs a chain's checked head as its new anchor, for the store's epoch where it will be kept there. */
export function signAnchor(keys: KeyProvider, chain: Chain, point: CheckedPoint, at: Date, epoch = NO_EPOCH): Anchor {
  return signedLine(keys, chain, point, at, epoch, anchorMessage);
}

/**
 * What a finished full pass's line signs (4D2e E7): a chain read whole from its first event to this place, at `at`.
 * Its own label, so a pass line can never stand for an anchor, nor an anchor for a pass.
 */
export const passMessage = (chain: string, point: CheckedPoint, at: Date, epoch: number): Message => [
  'audit-anchor-pass',
  ...anchorMessage(chain, point, at, epoch).slice(1),
];

/**
 * A pass under way (4D2e E7): read from the chain's first event to this place by a pass that began at `began`. Its
 * `at` is when the chain's pass has been owed since: for a chain never passed, when it was first taken in, carried
 * from line to line until a pass finishes, so no restart moves its lateness on.
 */
export interface Progress extends Anchor {
  readonly began: Date;
}

/** What a pass under way's line signs: its place, when its pass was owed and when it began. Its own label. */
export const progressMessage = (chain: string, point: CheckedPoint, at: Date, epoch: number, began: Date): Message => [
  'audit-anchor-progress',
  ...anchorMessage(chain, point, at, epoch).slice(1),
  began.toISOString(),
];

/** Signs the place a chain's full pass has reached, for the store's epoch, so a restart goes on from it. */
export function signProgress(
  keys: KeyProvider,
  chain: Chain,
  point: CheckedPoint,
  { at, began }: { readonly at: Date; readonly began: Date },
  epoch = NO_EPOCH,
): Progress {
  const signed = signedLine(keys, chain, point, at, epoch, (name, place, when, version) =>
    progressMessage(name, place, when, version, began),
  );
  return Object.freeze({ ...signed, began });
}

/** Signs a chain's finished full pass, to the place it set out for, `at` the time that pass began, for the store's epoch. */
export function signPass(keys: KeyProvider, chain: Chain, point: CheckedPoint, at: Date, epoch = NO_EPOCH): Anchor {
  return signedLine(keys, chain, point, at, epoch, passMessage);
}

/**
 * Where each chain's last finished full pass is kept, as signPass made it, and the place a pass under way has reached,
 * as signProgress made it: none once a pass finishes after it.
 */
export interface PassRecord {
  lastPass(chain: Chain): Anchor | undefined;
  keepPass(line: Anchor): void;
  lastProgress(chain: Chain): Progress | undefined;
  keepProgress(line: Progress): void;
}

/** The last full pass of each chain, in this process's memory, where no store keeps them. */
export function createMemoryPassRecord(): PassRecord {
  const passes = new Map<string, Anchor>();
  const progress = new Map<string, Progress>();
  return Object.freeze({
    lastPass: (chain: Chain) => passes.get(chainName(chain)),
    keepPass: (line: Anchor) => {
      passes.set(line.chain, line);
      progress.delete(line.chain);
    },
    lastProgress: (chain: Chain) => progress.get(chainName(chain)),
    keepProgress: (line: Progress) => {
      progress.set(line.chain, line);
    },
  });
}

/** The last anchor of each chain, in this process's memory. */
export function createMemoryAnchorStore(): AnchorStore {
  const anchors = new Map<string, Anchor>();
  return Object.freeze({
    latest: (chain: Chain) => anchors.get(chainName(chain)),
    keep: (anchor: Anchor) => {
      anchors.set(anchor.chain, anchor);
    },
  });
}
