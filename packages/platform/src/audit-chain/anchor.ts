// Anchors (ADR-011 §3, ADR-012 §2): a chain's head as the app last found it,
// whole and checked, signed with the `audit-anchor` key. The chain's own seals
// can't show a chain wound back to an earlier state, since every earlier head
// was genuinely sealed once; an anchor held apart from the database can. The
// check compares each chain with its last anchor (verifyChain), then anchors
// it again.
//
// Phase 1 keeps the last anchor in the app's memory, which ADR-012 §2 allows.
// It is lost when the process stops, so a rollback made while no process ran
// is left to the write-once store that comes before production. The signature
// is what that store will keep: anyone can check it with the public key the
// API logs at start (`api.starting`, keys).
import type { KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { type AnchorPoint, type Chain, chainName } from './chain.ts';

export interface Anchor extends AnchorPoint {
  /** The chain's name, as its hashes and MACs name it. */
  readonly chain: string;
  /** When the app anchored it. */
  readonly at: Date;
  readonly keyVersion: number;
  /** Ed25519 over `['audit-anchor', chain, seq, hash, at]`, as length-prefixed parts. */
  readonly signature: Buffer;
}

/** Where the last anchor of each chain is kept. */
export interface AnchorStore {
  latest(chain: Chain): Anchor | undefined;
  keep(anchor: Anchor): void;
}

const anchorMessage = (chain: string, point: AnchorPoint, at: Date): Message => [
  'audit-anchor',
  chain,
  point.seq.toString(),
  point.hash,
  at.toISOString(),
];

/** Signs a chain's checked head as its new anchor. */
export function signAnchor(keys: KeyProvider, chain: Chain, point: AnchorPoint, at: Date): Anchor {
  const name = chainName(chain);
  const { signature, keyVersion } = keys.sign('audit-anchor', anchorMessage(name, point, at));
  return Object.freeze({ chain: name, seq: point.seq, hash: point.hash, at, keyVersion, signature });
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
