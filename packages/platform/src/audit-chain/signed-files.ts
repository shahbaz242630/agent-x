// The signed files the digest (digest-log.ts) and the witness log (witness-log.ts) keep in their write-once stores: gzipped
// lines, the last a closing line signed for the file's own name, its epoch, how many lines it holds and the hash of every
// byte before it, under a label of the file's kind, so no file of one kind (nor an anchor file) can pass for another's.
// Named `<inverted-ms>-<uuid>` under a folder, so the newest lists first, as the anchors' files.
//
// A file is sound only whole: closed for its own name, by the key its folder allows, and every line before the closing one
// one of its kind's. A pass of its own reads a line at a time, so nothing of a file is taken before that is known, and a
// large one is never held parsed whole.
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip, createGzip } from 'node:zlib';

import { KeyError, type KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import type { SigningPurpose } from '../keys/purposes.ts';
import type { WriteOnceStore } from '../storage/write-once.ts';
import { isCount } from './rebase.ts';
import { bodyHash } from './shards.ts';

/** A line past this is no line of ours. */
export const MOST_LINE_BYTES = 64 * 1024;

/** What a file's name counts down from, so the newest lists first, as the anchors' files. */
const LAST_MS = 9_999_999_999_999;

/** A file's name after its folder. */
const FILE = /^\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** How many names a list asks. */
const NAMES_A_PAGE = 100;

/** A file's place in its folder, counted down from its time. */
export const countedDown = (ms: number): string => String(LAST_MS - ms).padStart(13, '0');

/** The time a name's countdown stands for. */
export const timeOfName = (countdown: string): number => LAST_MS - Number(countdown);

/** A new file's name in `folder` (ending `/`), dated `at`. */
export const fileName = (folder: string, at: number): string => `${folder}${countedDown(at)}-${randomUUID()}`;

/** A line as JSON, or undefined where it isn't. */
export function parsed(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
}

/** A file's lines, as gunzip gives them, never the whole as one string. */
export async function* linesIn(bytes: Buffer): AsyncGenerator<string> {
  const opening = createGunzip();
  opening.end(bytes);
  let rest: Buffer = Buffer.alloc(0);
  for await (const chunk of opening as AsyncIterable<Buffer>) {
    const joined = rest.length > 0 ? Buffer.concat([rest, chunk]) : chunk;
    let from = 0;
    for (let end = joined.indexOf(10, from); end >= 0; end = joined.indexOf(10, from)) {
      yield joined.toString('utf8', from, end);
      from = end + 1;
    }
    rest = joined.subarray(from);
    if (rest.length > MOST_LINE_BYTES) throw new RangeError('a line longer than any of ours');
  }
  if (rest.length > 0) yield rest.toString('utf8');
}

/** Text gzipped as it is made: a snapshot is never one string. */
export async function gzipped(text: Iterable<string>): Promise<Buffer> {
  const made: Buffer[] = [];
  await pipeline(Readable.from(text), createGzip(), async (chunks: AsyncIterable<Buffer>) => {
    for await (const chunk of chunks) made.push(chunk);
  });
  return Buffer.concat(made);
}

/** A kind of signed file: the label its closing line signs under, and the key it is signed with. */
export interface FileKind {
  readonly label: string;
  readonly purpose: SigningPurpose;
}

/** What a file's closing line signs: its kind's label, its own name, epoch, line count and body. */
const closingMessage = (label: string, name: string, epoch: number, lines: number, body: string): Message => [
  label,
  name,
  String(epoch),
  String(lines),
  body,
];

/** A file of the lines, closed and signed with its kind's key, named `name`: made a line at a time, its closing line last. */
export async function signedFile(
  keys: KeyProvider,
  { label, purpose }: FileKind,
  name: string,
  epoch: number,
  lines: Iterable<string>,
): Promise<Buffer> {
  function* closed(): Generator<string> {
    const body = bodyHash();
    for (const line of lines) {
      body.add(line);
      yield `${line}\n`;
    }
    const { signature, keyVersion } = keys.sign(purpose, closingMessage(label, name, epoch, body.lines, body.digest()));
    yield JSON.stringify({ k: 'z', lines: body.lines, kv: keyVersion, sig: signature.toString('base64') });
  }
  return gzipped(closed());
}

/** Whether a closing line's signature closes the file for its kind, name, epoch, lines and body. A version not held is simply wrong. */
function closes(
  keys: KeyProvider,
  { label, purpose }: FileKind,
  fields: unknown,
  name: string,
  epoch: number,
  lines: number,
  body: string,
): boolean {
  if (typeof fields !== 'object' || fields === null) return false;
  const { k, kv, sig } = fields as Record<string, unknown>;
  if (k !== 'z' || !isCount(kv) || typeof sig !== 'string') return false;
  try {
    return keys.verifySignature(
      purpose,
      kv,
      closingMessage(label, name, epoch, lines, body),
      Buffer.from(sig, 'base64'),
    );
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/** Whether a file is sound: closed for its own name by its kind's key, and every line before it one `isLine` takes. */
export async function isSoundFile(
  keys: KeyProvider,
  kind: FileKind,
  bytes: Buffer,
  name: string,
  epoch: number,
  isLine: (fields: unknown) => boolean,
): Promise<boolean> {
  const body = bodyHash();
  let last: string | undefined;
  try {
    for await (const text of linesIn(bytes)) {
      if (last !== undefined) {
        if (!isLine(parsed(last))) return false;
        body.add(last);
      }
      last = text;
    }
  } catch {
    // Not gzip, or a line longer than any of ours.
    return false;
  }
  return last !== undefined && closes(keys, kind, parsed(last), name, epoch, body.lines, body.digest());
}

/** Every line of a sound file but its closing one, parsed. */
export async function* bodyLines(bytes: Buffer): AsyncGenerator<unknown> {
  let last: string | undefined;
  for await (const text of linesIn(bytes)) {
    if (last !== undefined) yield parsed(last);
    last = text;
  }
}

/**
 * Every well-named file in `folder`, newest first. A name dated past `mostAt` is said (`future`) and passed over: no
 * honest clock names one so far ahead.
 */
export async function* namesIn(
  from: WriteOnceStore,
  folder: string,
  mostAt: () => number,
  future: (at: number) => void,
): AsyncGenerator<{ readonly name: string; readonly at: number }> {
  let after: string | undefined;
  do {
    const page = await from.list(folder, NAMES_A_PAGE, after);
    for (const name of page.names) {
      const rest = name.slice(folder.length);
      if (!FILE.test(rest)) continue;
      const at = timeOfName(rest.slice(0, 13));
      if (at > mostAt()) {
        future(at);
        continue;
      }
      yield { name, at };
    }
    after = page.next;
  } while (after !== undefined);
}
