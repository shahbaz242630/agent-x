// Which files a Bicep deployment reads, as the pinned compiler itself says
// (T1): `bicep jsonrpc --stdio`, the interface Bicep offers other programs,
// asked `bicep/getFileReferences` for each parameters file. Each answer lists
// every file that deployment reads: the parameters file, its template, each
// module and import, each file a load function reads, and bicepconfig.json.
//
// - messages are framed as in the Language Server Protocol: a Content-Length
//   header, a blank line, then the JSON
// - Bicep answers nothing once its input closes (tried on 0.47.16: every
//   question written at once and the input closed got no answer at all), so
//   the line stays open until every answer is in, with one deadline on the
//   whole, and the server is stopped however it ends
// - anything unexpected is an error, never a partial answer: a list missing a
//   file would say a deployment doesn't read it
import { spawn } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';

import { installedBicep } from './bicep.ts';

/** How long Bicep may take to answer every question, all told (it answers four in about a second). */
const DEADLINE_MS = 60_000;

/** The most one message may hold: far more than any list of files. */
const MOST_BYTES = 1 << 20;

/** The most a header may hold before its blank line. */
const MOST_HEADER_BYTES = 1024;

/** The most of Bicep's own error output kept to say why it stopped. */
const MOST_STDERR = 2000;

const HEADER_END = '\r\n\r\n';

/** A running JSON-RPC server, as `spawn` gives one; tests give a stand-in. */
export interface Server {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  on(event: 'error', listener: (error: Error) => void): unknown;
  /** Once it has exited and its output has all been read. */
  on(event: 'close', listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  kill(signal: NodeJS.Signals): unknown;
}

/** The pinned Bicep, checked against its pin, listening on stdin and stdout. */
const startBicep = (): Server =>
  spawn(installedBicep(), ['jsonrpc', '--stdio'], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });

export interface ReferenceOptions {
  readonly start?: () => Server;
  readonly deadlineMs?: number;
}

const record = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};

/** One question, framed. */
function framed(id: number, file: string): string {
  const body = JSON.stringify({ jsonrpc: '2.0', id, method: 'bicep/getFileReferences', params: { path: file } });
  return `Content-Length: ${String(Buffer.byteLength(body))}\r\n\r\n${body}`;
}

/** The length a header gives its message, or an error saying why it gives none. */
function contentLength(header: string): number {
  const lengths = header
    .split('\r\n')
    .map((line) => /^content-length:\s*(\d+)\s*$/i.exec(line)?.[1])
    .filter((length) => length !== undefined);
  if (lengths.length !== 1) throw new Error("a message from Bicep didn't give one Content-Length");
  const length = Number(lengths[0]);
  if (length > MOST_BYTES) throw new Error(`a message from Bicep would hold ${String(length)} bytes, too many`);
  return length;
}

/**
 * Each parameters file (by the full path given) with the full path of every
 * file its deployment reads, as Bicep says, or an error saying why Bicep
 * didn't say.
 */
export async function fileReferences(
  paramsFiles: readonly string[],
  options: ReferenceOptions = {},
): Promise<ReadonlyMap<string, readonly string[]>> {
  if (paramsFiles.length === 0) return new Map();
  const server = (options.start ?? startBicep)();
  const deadlineMs = options.deadlineMs ?? DEADLINE_MS;
  return new Promise((resolve, reject) => {
    const found = new Map<string, readonly string[]>();
    let buffered = Buffer.alloc(0);
    let stderr = '';
    let settled = false;
    const end = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.stdin.end();
      // Killed outright: it holds nothing to save, and one that ignored a
      // polite stop would hold CI's release open until the job's own limit.
      server.kill('SIGKILL');
      if (error === undefined) resolve(new Map(paramsFiles.map((file) => [file, found.get(file) ?? []])));
      else reject(error);
    };
    const timer = setTimeout(() => {
      end(new Error(`Bicep didn't answer within ${String(deadlineMs / 1000)} s`));
    }, deadlineMs);

    const answered = (message: Readonly<Record<string, unknown>>): void => {
      const { id, error, result } = message;
      // A notification (a method and no ID) asks nothing of us.
      if (id === undefined && typeof message.method === 'string') return;
      const file = typeof id === 'number' ? paramsFiles[id - 1] : undefined;
      if (file === undefined || found.has(file)) throw new Error("Bicep answered a question it wasn't asked");
      if (error !== undefined) {
        const why = record(error).message;
        throw new Error(
          `Bicep couldn't say what ${file} reads: ${typeof why === 'string' ? why : 'it gave no reason'}`,
        );
      }
      const read = record(result).filePaths;
      if (!Array.isArray(read) || !read.every((each) => typeof each === 'string') || read.length === 0) {
        throw new Error(`Bicep's answer for ${file} isn't a list of files`);
      }
      found.set(file, read);
      if (found.size === paramsFiles.length) end();
    };

    const read = (chunk: Buffer): void => {
      buffered = Buffer.concat([buffered, chunk]);
      for (;;) {
        const headerEnd = buffered.indexOf(HEADER_END);
        if (headerEnd < 0) {
          if (buffered.length > MOST_HEADER_BYTES) throw new Error("a message from Bicep didn't end its header");
          return;
        }
        const length = contentLength(buffered.subarray(0, headerEnd).toString('utf8'));
        const start = headerEnd + HEADER_END.length;
        if (buffered.length < start + length) return;
        let message: unknown;
        try {
          message = JSON.parse(buffered.subarray(start, start + length).toString('utf8'));
        } catch (error) {
          throw new Error("a message from Bicep wasn't JSON", { cause: error });
        }
        buffered = buffered.subarray(start + length);
        answered(record(message));
      }
    };

    // Anything read once it has ended changes nothing: an ending is final.
    server.stdout.on('data', (chunk: Buffer) => {
      try {
        read(chunk);
      } catch (error) {
        end(error instanceof Error ? error : new Error(String(error)));
      }
    });
    server.stderr.on('data', (chunk: Buffer) => {
      stderr = `${stderr}${chunk.toString('utf8')}`.slice(-MOST_STDERR);
    });
    /** An error for a stop, with what Bicep said of it. */
    const stopped = (why: string): Error => {
      const said = stderr.trim();
      return new Error(`${why}${said === '' ? '' : `: ${said}`}`);
    };
    server.on('error', (error) => {
      end(stopped(`Bicep couldn't be run (${error.message})`));
    });
    server.on('close', (code, signal) => {
      end(stopped(`Bicep stopped before answering (${code === null ? String(signal) : `status ${String(code)}`})`));
    });
    // A server that has gone refuses what is written (EPIPE); ended by us, it is refused nothing.
    server.stdin.on('error', (error) => {
      end(stopped(`Bicep took no questions (${error.message})`));
    });
    server.stdin.write(paramsFiles.map((file, at) => framed(at + 1, file)).join(''));
  });
}
