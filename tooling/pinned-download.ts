// What the pinned tools share (gitleaks for the hooks, Bicep for deploy/azure,
// cosign for a deploy's image check): where they are installed, how a file is
// hashed, and a download that is refused, and never installed, unless it
// matches its pinned SHA-256. The pins reviewed in the repository are what we
// trust: gitleaks and Bicep publish no signatures, and cosign's own would need
// cosign to check.
import { createHash } from 'node:crypto';
import { chmodSync, closeSync, createWriteStream, mkdirSync, openSync, readSync, renameSync, rmSync } from 'node:fs';
import path from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

/** Where the pinned tools live once installed (git-ignored). */
export const TOOLS_DIR = fileURLToPath(new URL('../.tools/', import.meta.url));

/** A release file pinned by its SHA-256. */
export interface PinnedBinary {
  readonly file: string;
  readonly sha256: string;
}

/** The pinned file for this machine from a tool's table, or an error naming what is missing. */
export function pinnedFor<T>(table: Readonly<Record<string, T>>, platform: string, arch: string, label: string): T {
  const pinned = table[`${platform}-${arch}`];
  if (pinned === undefined) throw new Error(`No ${label} is pinned for ${platform}-${arch}.`);
  return pinned;
}

export const sha256Of = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

/**
 * A file's SHA-256, read through one open handle in 1 MB pieces, so a 120 MB
 * binary is never held in memory whole. Undefined if the file doesn't exist.
 */
export function sha256OfFile(file: string): string | undefined {
  let handle: number;
  try {
    handle = openSync(file, 'r');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  try {
    const hash = createHash('sha256');
    const chunk = new Uint8Array(1024 * 1024);
    for (let read = readSync(handle, chunk); read > 0; read = readSync(handle, chunk)) {
      hash.update(chunk.subarray(0, read));
    }
    return hash.digest('hex');
  } finally {
    closeSync(handle);
  }
}

export type Fetch = (
  url: string,
  init?: { readonly signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

/** Long enough for a 120 MB release file on a slow line; a download that stalls fails instead of hanging. */
const DOWNLOAD_TIMEOUT_MS = 300_000;

/** A fetch whose body is read as it arrives, for a file too large to hold whole. */
export type StreamingFetch = (
  url: string,
  init?: { readonly signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; body: ReadableStream<Uint8Array> | null }>;

/** Long enough for a 200 MB release file (cosign's for Windows) on a slow line. */
const LARGE_DOWNLOAD_TIMEOUT_MS = 900_000;

/** Tries in all, and the first pause before another: GitHub's release downloads fail now and then (S35, S59, S70). */
const ATTEMPTS = 3;
const RETRY_AFTER_MS = 2000;

/** A pause before trying again; tests pass one that doesn't wait. */
export type Wait = (ms: number) => Promise<unknown>;

/**
 * The answer to a request, asked again on a server error (5xx) or a dropped
 * connection, up to ATTEMPTS in all. A deadline passed or an abort is never asked again,
 * and any other answer, a 404 among them, is the request's own.
 */
async function fetchRetrying<R extends { readonly status: number }>(
  fetchOnce: () => Promise<R>,
  wait: Wait,
): Promise<R> {
  for (let attempt = 1; ; attempt += 1) {
    const last = attempt === ATTEMPTS;
    try {
      const response = await fetchOnce();
      if (response.status < 500 || last) return response;
    } catch (error) {
      const timedOut = error instanceof DOMException && (error.name === 'TimeoutError' || error.name === 'AbortError');
      if (timedOut || last) throw error;
    }
    await wait(RETRY_AFTER_MS * attempt);
  }
}

/**
 * Downloads a pinned file straight to `target`, hashing it as it arrives, so a
 * 200 MB release file is never held in memory (this machine is short of it).
 * It is written beside the target and renamed into place only once it matches
 * its pin, runnable; a mismatch, a failed request or a stall leaves nothing.
 */
export async function downloadPinnedTo(
  url: string,
  file: string,
  sha256: string,
  target: string,
  fetchFile: StreamingFetch = fetch,
  wait: Wait = delay,
): Promise<void> {
  const response = await fetchRetrying(
    () => fetchFile(url, { signal: AbortSignal.timeout(LARGE_DOWNLOAD_TIMEOUT_MS) }),
    wait,
  );
  if (!response.ok || response.body === null) {
    throw new Error(`Downloading ${file} failed: HTTP ${String(response.status)}.`);
  }
  mkdirSync(path.dirname(target), { recursive: true });
  const partial = `${target}.partial`;
  const hash = createHash('sha256');
  try {
    await pipeline(
      Readable.fromWeb(response.body),
      new Transform({
        transform(chunk: Buffer, _encoding, done) {
          hash.update(chunk);
          done(null, chunk);
        },
      }),
      createWriteStream(partial),
    );
    const actual = hash.digest('hex');
    if (actual !== sha256) {
      throw new Error(`${file} does not match its pinned SHA-256 (got ${actual}); nothing was installed.`);
    }
    chmodSync(partial, 0o755);
    renameSync(partial, target);
  } finally {
    rmSync(partial, { force: true });
  }
}

/** The file's bytes, once they match their pin; an error naming the file otherwise. */
export async function downloadPinned(
  url: string,
  file: string,
  sha256: string,
  fetchFile: Fetch = fetch,
  wait: Wait = delay,
): Promise<Uint8Array> {
  const response = await fetchRetrying(
    () => fetchFile(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) }),
    wait,
  );
  if (!response.ok) throw new Error(`Downloading ${file} failed: HTTP ${String(response.status)}.`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const actual = sha256Of(bytes);
  if (actual !== sha256) {
    throw new Error(`${file} does not match its pinned SHA-256 (got ${actual}); nothing was installed.`);
  }
  return bytes;
}
