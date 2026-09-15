// What the pinned tools share (gitleaks for the hooks, Bicep for deploy/azure):
// where they are installed, how a file is hashed, and a download that is
// refused, and never written anywhere, unless it matches its pinned SHA-256.
// Neither release publishes signatures, so the pins reviewed in the repository
// are what we trust.
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

/** Where the pinned tools live once installed (git-ignored). */
export const TOOLS_DIR = fileURLToPath(new URL('../.tools/', import.meta.url));

export const sha256Of = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

export type Fetch = (
  url: string,
  init?: { readonly signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

/** Long enough for a 120 MB release file on a slow line; a download that stalls fails instead of hanging. */
const DOWNLOAD_TIMEOUT_MS = 300_000;

/** The file's bytes, once they match their pin; an error naming the file otherwise. */
export async function downloadPinned(
  url: string,
  file: string,
  sha256: string,
  fetchFile: Fetch = fetch,
): Promise<Uint8Array> {
  const response = await fetchFile(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`Downloading ${file} failed: HTTP ${String(response.status)}.`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const actual = sha256Of(bytes);
  if (actual !== sha256) {
    throw new Error(`${file} does not match its pinned SHA-256 (got ${actual}); nothing was installed.`);
  }
  return bytes;
}
