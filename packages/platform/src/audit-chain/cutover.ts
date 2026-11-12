// The sharded store's cutover marker (4D2e PL-65): the one file that says the anchors' store has moved on to a later
// layout, so a version from before it (anchor-log.ts) must read none of the store. The migration writes it FIRST, before
// any shard file, then the shards, then a separate signed record that the migration is done.
//
// It is one line in a file of its own, at a name fixed for its epoch and layout, `e<epoch>/cutover/shards-v1`, so a reader
// asks for that one name and never lists through what anyone may have added beside it. It is signed with the
// `audit-anchor` key for its own name, epoch, layout and time, as a file's closing line is. Only a marker so signed counts:
// anyone holding no more than the store's add token can add a file there, and must not be able to stop payments by it.
// Anything else at the name or under the folder is the alarm and moves nothing. Someone who takes the name first only
// makes the migration's write of it refused as an overwrite, which stops the migration loudly before it writes a shard.
//
// The migration's last step is a second record of the same form, `e<epoch>/shards/done-shards-v1` (PR2): every shard
// holds a snapshot of its own, made after a read begun an hour past the marker, when no older version still writes the
// old files. Only once it is there does a reader trust the shards alone and leave the old files unread. It sits under
// `shards/`, never `cutover/`, so a version from before the shards, mid-read as both land, says at most the one
// `reason: shards` alarm, never a second one about `cutover/`.
import { gzipSync } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import { isCount, openedSmallFile, parsedJson, timeIn } from './rebase.ts';

/** The layout the marker moves the store on to: the sharded store's first. */
export const SHARDED_LAYOUT = 'shards-v1';

export const cutoverFolder = (epoch: number): string => `e${String(epoch)}/cutover/`;

/** Where the marker of a layout is, in an epoch: one name, fixed. */
export const cutoverName = (epoch: number, layout = SHARDED_LAYOUT): string => `${cutoverFolder(epoch)}${layout}`;

/** Where the record that the migration to a layout is done is, in an epoch: one name, fixed, beside the shards. */
export const shardsDoneName = (epoch: number, layout = SHARDED_LAYOUT): string =>
  `e${String(epoch)}/shards/done-${layout}`;

/** The two records: the marker the migration writes first, and the one it writes last. Each signed under its own label. */
const RECORDS = {
  cutover: { label: 'audit-anchor-cutover', named: cutoverName },
  done: { label: 'audit-anchor-shards-done', named: shardsDoneName },
} as const;

type RecordKind = keyof typeof RECORDS;

/** What a record signs: its own name, its epoch, the layout and when. */
const recordMessage = (kind: RecordKind, name: string, epoch: number, layout: string, at: Date): Message => [
  RECORDS[kind].label,
  name,
  String(epoch),
  layout,
  at.toISOString(),
];

/** What a record is made from: its epoch, when, and the layout (the sharded one unless a test says). */
interface Made {
  readonly epoch: number;
  readonly at: Date;
  readonly layout?: string;
}

function recordFile(
  kind: RecordKind,
  keys: KeyProvider,
  { epoch, at, layout = SHARDED_LAYOUT }: Made,
): { readonly name: string; readonly bytes: Buffer } {
  const name = RECORDS[kind].named(epoch, layout);
  const { signature, keyVersion } = keys.sign('audit-anchor', recordMessage(kind, name, epoch, layout, at));
  const line = JSON.stringify({
    k: kind,
    name,
    epoch,
    layout,
    at: at.toISOString(),
    kv: keyVersion,
    sig: signature.toString('base64'),
  });
  return { name, bytes: gzipSync(`${line}\n`) };
}

/** A marker's name and bytes, signed with the `audit-anchor` key: what the migration writes first (PR2). */
export const cutoverFile = (keys: KeyProvider, made: Made): { readonly name: string; readonly bytes: Buffer } =>
  recordFile('cutover', keys, made);

/** The record that the migration is done, signed the same way: what it writes last. */
export const shardsDoneFile = (keys: KeyProvider, made: Made): { readonly name: string; readonly bytes: Buffer } =>
  recordFile('done', keys, made);

/** Why a file under the folder is no marker: not one of the form, another epoch's or layout's, or not signed for it. */
type CutoverProblem = 'file' | 'epoch' | 'layout' | 'signature';

/** What a record read says: signed for its name, with when; or why it is none. */
export type RecordRead = { readonly marker: true; readonly at: Date } | { readonly problem: CutoverProblem };

interface Named {
  readonly bytes: Buffer;
  readonly name: string;
  readonly epoch: number;
}

/**
 * Whether the file named `name` is a marker of the sharded layout for this epoch, signed for its name with a version of
 * the `audit-anchor` key this process holds; or why not.
 */
export const readCutoverFile = (keys: KeyProvider, file: Named): Promise<RecordRead> =>
  readRecordFile('cutover', keys, file);

/** Whether the file named `name` is the record that the migration to the sharded layout is done, as a marker is read. */
export const readShardsDoneFile = (keys: KeyProvider, file: Named): Promise<RecordRead> =>
  readRecordFile('done', keys, file);

async function readRecordFile(kind: RecordKind, keys: KeyProvider, { bytes, name, epoch }: Named): Promise<RecordRead> {
  const text = await openedSmallFile(bytes);
  const lines = text?.endsWith('\n') === true ? text.slice(0, -1).split('\n') : [];
  const fields = lines.length === 1 ? parsedJson(lines[0] ?? '') : undefined;
  if (typeof fields !== 'object' || fields === null) return { problem: 'file' };
  const said = fields as Record<string, unknown>;
  const at = timeIn(said.at);
  if (said.k !== kind || said.name !== name || at === undefined) return { problem: 'file' };
  if (!isCount(said.kv) || typeof said.sig !== 'string' || typeof said.layout !== 'string') return { problem: 'file' };
  if (said.epoch !== epoch) return { problem: 'epoch' };
  if (said.layout !== SHARDED_LAYOUT) return { problem: 'layout' };
  try {
    const message = recordMessage(kind, name, epoch, said.layout, at);
    if (keys.verifySignature('audit-anchor', said.kv, message, Buffer.from(said.sig, 'base64')))
      return { marker: true, at };
  } catch (error) {
    if (!(error instanceof KeyError)) throw error;
  }
  return { problem: 'signature' };
}
