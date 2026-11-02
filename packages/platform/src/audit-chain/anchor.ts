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
export const NO_EPOCH = 0;

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

/** Signs a chain's checked head as its new anchor, for the store's epoch where it will be kept there. */
export function signAnchor(keys: KeyProvider, chain: Chain, point: CheckedPoint, at: Date, epoch = NO_EPOCH): Anchor {
  const name = chainName(chain);
  const { signature, keyVersion } = keys.sign('audit-anchor', anchorMessage(name, point, at, epoch));
  const { seq, hash, macKeyVersion } = point;
  return Object.freeze({ chain: name, seq, hash, macKeyVersion, at, keyVersion, signature });
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
