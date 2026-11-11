// A rebase (4D2e E11; playbook H): after a sanctioned change to a chain (an
// organisation's chain repaired, E10; the platform chain begun again), the
// chain no longer holds the anchor last signed, and the anchor check would say
// so for good. A rebase moves the anchor on, to a place the operator's command
// has checked the chain whole to, naming why and the incident's evidence.
//
// It is a line of its own (`k:"r"`) in a file of its own, under
// `e<epoch>/rebases/<rebase ID>` in the anchors' store, signed with the
// `audit-rebase` key, which only the operator's job holds (OPERATOR_ONLY): the
// API checks it with the public half alone, so a foothold in the API, which
// can add files to the store, can't move an anchor back. A rebase with a bad
// signature, or for a key version the process has no half for, is refused and
// is the alarm.
//
// The newest rebase of a chain, by its time, stands in for its anchor: every
// anchor or pass place of that chain dated before it is passed over, in memory
// and in every file read after (anchor-log.ts). Whoever holds the `audit-rebase`
// key can move any chain's anchor: it is kept with the operator for that.
import { createGunzip, gzipSync } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import type { CheckedPoint } from './chain.ts';

/** Why a chain was moved on: a sanctioned repair (E10), or the platform chain begun again (playbook H). */
export const REBASE_REASONS = ['repaired', 'recovered'] as const;
export type RebaseReason = (typeof REBASE_REASONS)[number];

/** The incident's reference, as a case reference is written: 3 to 64 letters, digits and `. _ / -`. */
export const EVIDENCE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$/;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^(?:0|[1-9]\d{0,18})$/;
const HASH = /^[0-9a-f]{64}$/;

/** A rebase file holds one line of about 450 bytes, a cutover marker less: anything past this isn't one. */
export const MOST_FILE_BYTES = 4096;

export interface Rebase extends CheckedPoint {
  /** The rebase's own ID (a UUID), which its file is named by. */
  readonly id: string;
  /** The chain's name, as its hashes and MACs name it. */
  readonly chain: string;
  /** When the operator wrote it: what dates the anchors it stands over. */
  readonly at: Date;
  readonly reason: RebaseReason;
  /** The incident's reference, where the evidence is kept. */
  readonly evidence: string;
  /** The anchor it moves on from, if the chain had one: shorter than it where `seq` is lower. */
  readonly from: bigint | null;
  readonly keyVersion: number;
  /** Ed25519 with `audit-rebase` over rebaseMessage. */
  readonly signature: Buffer;
}

/** What a rebase signs: its epoch, ID, chain, place, time, reason, evidence and the anchor before. Its own label and key. */
export const rebaseMessage = (
  epoch: number,
  { id, chain, seq, hash, macKeyVersion, at, reason, evidence, from }: Omit<Rebase, 'keyVersion' | 'signature'>,
): Message => [
  'audit-rebase',
  String(epoch),
  id,
  chain,
  seq.toString(),
  hash,
  macKeyVersion.toString(),
  at.toISOString(),
  reason,
  evidence,
  from === null ? '' : from.toString(),
];

/** Where a rebase's file goes in the store: its epoch's folder, by its ID. */
export const rebaseFolder = (epoch: number): string => `e${String(epoch)}/rebases/`;
export const rebaseFileName = (epoch: number, id: string): string => `${rebaseFolder(epoch)}${id}`;

/**
 * Signs a rebase with the `audit-rebase` key. Only the operator's job holds it: a process without it (the API) gets
 * the key provider's KeyError, and nothing is made.
 */
export function signRebase(
  keys: KeyProvider,
  epoch: number,
  unsigned: Omit<Rebase, 'keyVersion' | 'signature'>,
): Rebase {
  const { signature, keyVersion } = keys.sign('audit-rebase', rebaseMessage(epoch, unsigned));
  return Object.freeze({ ...unsigned, keyVersion, signature });
}

/** A rebase's file: its one line, gzipped as every file in the store is. */
export function rebaseFile(rebase: Rebase): Buffer {
  const line = JSON.stringify({
    k: 'r',
    id: rebase.id,
    chain: rebase.chain,
    seq: rebase.seq.toString(),
    hash: rebase.hash.toString('hex'),
    mk: rebase.macKeyVersion,
    at: rebase.at.toISOString(),
    why: rebase.reason,
    ev: rebase.evidence,
    fr: rebase.from === null ? null : rebase.from.toString(),
    kv: rebase.keyVersion,
    sig: rebase.signature.toString('base64'),
  });
  return gzipSync(`${line}\n`);
}

/** Why a rebase file is refused: not one line of the form, or not signed by the key for it. */
export type RebaseProblem = 'file' | 'signature';

/** A whole number from 0, as a line writes a key version. Shared with anchor-log.ts's lines. */
export const isCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

/** A time as a line writes it, or nothing if it isn't one exactly. Shared with anchor-log.ts's lines. */
export const timeIn = (value: unknown): Date | undefined => {
  if (typeof value !== 'string') return undefined;
  const when = new Date(value);
  return Number.isNaN(when.getTime()) || when.toISOString() !== value ? undefined : when;
};

const isReason = (value: unknown): value is RebaseReason => (REBASE_REASONS as readonly unknown[]).includes(value);

/** The rebase a parsed line says, if it is one in every field; its signature is checked after. */
function rebaseFrom(fields: Record<string, unknown>): Rebase | undefined {
  const { k, id, chain, seq, hash, mk, at, why, ev, fr, kv, sig } = fields;
  if (k !== 'r' || typeof id !== 'string' || !UUID.test(id)) return undefined;
  if (typeof chain !== 'string' || !CHAIN.test(chain)) return undefined;
  if (typeof seq !== 'string' || !SEQ.test(seq) || typeof hash !== 'string' || !HASH.test(hash)) return undefined;
  if (!isCount(mk) || !isCount(kv) || typeof sig !== 'string' || !isReason(why)) return undefined;
  if (typeof ev !== 'string' || !EVIDENCE_REFERENCE.test(ev)) return undefined;
  if (fr !== null && (typeof fr !== 'string' || !SEQ.test(fr))) return undefined;
  const when = timeIn(at);
  if (when === undefined) return undefined;
  return {
    id,
    chain,
    seq: BigInt(seq),
    hash: Buffer.from(hash, 'hex'),
    macKeyVersion: mk,
    at: when,
    reason: why,
    evidence: ev,
    from: fr === null ? null : BigInt(fr),
    keyVersion: kv,
    signature: Buffer.from(sig, 'base64'),
  };
}

/** A file's bytes opened, or nothing past MOST_FILE_BYTES either way, or for bytes that aren't gzip. Shared with cutover.ts. */
export async function openedSmallFile(bytes: Buffer, most = MOST_FILE_BYTES): Promise<string | undefined> {
  if (bytes.length > most) return undefined;
  const opening = createGunzip();
  opening.end(bytes);
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of opening as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > most) return undefined;
      chunks.push(chunk);
    }
  } catch {
    // Not gzip, or cut short: no file of ours.
    return undefined;
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function parsedJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    // Not JSON: no file of ours, which the caller refuses.
    return undefined;
  }
}

/**
 * The rebase a file named `name` holds, signed with `audit-rebase` for this epoch, or why it is refused: one line, for
 * the ID its name ends in. A key version this process has no public half for is a bad signature.
 */
export async function readRebaseFile(
  keys: KeyProvider,
  { bytes, name, epoch }: { readonly bytes: Buffer; readonly name: string; readonly epoch: number },
): Promise<{ readonly rebase: Rebase } | { readonly problem: RebaseProblem }> {
  const text = await openedSmallFile(bytes);
  const lines = text?.endsWith('\n') === true ? text.slice(0, -1).split('\n') : [];
  const fields = lines.length === 1 ? parsedJson(lines[0] ?? '') : undefined;
  const rebase =
    typeof fields === 'object' && fields !== null ? rebaseFrom(fields as Record<string, unknown>) : undefined;
  if (rebase === undefined || name !== rebaseFileName(epoch, rebase.id)) return { problem: 'file' };
  const { keyVersion, signature, ...unsigned } = rebase;
  try {
    if (keys.verifySignature('audit-rebase', keyVersion, rebaseMessage(epoch, unsigned), signature)) return { rebase };
  } catch (error) {
    if (!(error instanceof KeyError)) throw error;
  }
  return { problem: 'signature' };
}
