// The sharded store's cutover marker (4D2e PL-65): the one file that says the anchors' store has moved on to a later
// layout, so a version from before it (anchor-log.ts) must read none of the store. The migration writes it FIRST, before
// any shard file, then the shards, then a separate signed record that the migration is done.
//
// It is one line in a file of its own, under `e<epoch>/cutover/<inverted-ms>-<id>` like the anchors' files, signed with
// the `audit-anchor` key for its own name, epoch, layout and time, as a file's closing line is. Only a marker so signed
// counts: anyone holding no more than the store's add token can add a file there, and must not be able to stop payments by
// it. Anything else under the folder is the alarm and moves nothing.
import { gzipSync } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { isCount, openedSmallFile, parsedJson, timeIn } from './rebase.ts';

/** The layout the marker moves the store on to: the sharded store's first. */
export const SHARDED_LAYOUT = 'shards-v1';

/** What a file's name counts down from, as the anchors' files do, so the newest lists first. */
const LAST_MS = 9_999_999_999_999;

export const cutoverFolder = (epoch: number): string => `e${String(epoch)}/cutover/`;

/** What a marker signs: its own name, its epoch, the layout and when. */
const cutoverMessage = (name: string, epoch: number, layout: string, at: Date): Message => [
  'audit-anchor-cutover',
  name,
  String(epoch),
  layout,
  at.toISOString(),
];

/** A marker's name and bytes, signed with the `audit-anchor` key: what the migration writes first (PR2). */
export function cutoverFile(
  keys: KeyProvider,
  { epoch, at, id, layout = SHARDED_LAYOUT }: { epoch: number; at: Date; id: string; layout?: string },
): { readonly name: string; readonly bytes: Buffer } {
  const name = `${cutoverFolder(epoch)}${String(LAST_MS - at.getTime()).padStart(13, '0')}-${id}`;
  const { signature, keyVersion } = keys.sign('audit-anchor', cutoverMessage(name, epoch, layout, at));
  const line = JSON.stringify({
    k: 'cutover',
    name,
    epoch,
    layout,
    at: at.toISOString(),
    kv: keyVersion,
    sig: signature.toString('base64'),
  });
  return { name, bytes: gzipSync(`${line}\n`) };
}

/** Why a file under the folder is no marker: not one of the form, another epoch's or layout's, or not signed for it. */
export type CutoverProblem = 'file' | 'epoch' | 'layout' | 'signature';

/**
 * Whether the file named `name` is a marker of the sharded layout for this epoch, signed for its name with a version of
 * the `audit-anchor` key this process holds; or why not.
 */
export async function readCutoverFile(
  keys: KeyProvider,
  { bytes, name, epoch }: { readonly bytes: Buffer; readonly name: string; readonly epoch: number },
): Promise<{ readonly marker: true } | { readonly problem: CutoverProblem }> {
  const text = await openedSmallFile(bytes);
  const lines = text?.endsWith('\n') === true ? text.slice(0, -1).split('\n') : [];
  const fields = lines.length === 1 ? parsedJson(lines[0] ?? '') : undefined;
  if (typeof fields !== 'object' || fields === null) return { problem: 'file' };
  const said = fields as Record<string, unknown>;
  const at = timeIn(said.at);
  if (said.k !== 'cutover' || said.name !== name || at === undefined) return { problem: 'file' };
  if (!isCount(said.kv) || typeof said.sig !== 'string' || typeof said.layout !== 'string') return { problem: 'file' };
  if (said.epoch !== epoch) return { problem: 'epoch' };
  if (said.layout !== SHARDED_LAYOUT) return { problem: 'layout' };
  try {
    const message = cutoverMessage(name, epoch, said.layout, at);
    if (keys.verifySignature('audit-anchor', said.kv, message, Buffer.from(said.sig, 'base64')))
      return { marker: true };
  } catch (error) {
    if (!(error instanceof KeyError)) throw error;
  }
  return { problem: 'signature' };
}
