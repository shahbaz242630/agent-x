// Fetching an MCP client's metadata document (6E3c, decision 2; CIMD;
// SEC-OAUTH-09): a client whose ID is an https address the allowlist trusts
// (AGENTX_OAUTH_CLIENT_METADATA_ORIGINS: an origin, a path prefix or one
// document's exact address, AG6) publishes there what it is. The
// fetch is a public GET carrying no customer data (ADR-013): no cookie, no
// token, nothing of the person or organisation.
//
// Every guard against the fetch being turned on us (SSRF):
// - An address the allowlist doesn't trust is never fetched, nor one that is
//   not https, nor one the client-ID rules refuse (a `..`, a user, a
//   fragment, an address not as the URL parser prints it, a %-encoded `.`,
//   `/` or `\`).
// - The outbound fetch's own rules (outbound-fetch.ts): only origins on the
//   outbound allowlist (each of ours must be, or the app refuses to start),
//   redirects never followed, TLS checks on.
// - 3 seconds for the whole of it, headers and body; at most 16 KB, counted as
//   it streams in, whatever the length the server claims; application/json
//   alone; a 200 alone.
// The document is then checked (client-metadata-document.ts) before anything
// of it is kept. Private addresses are not checked here: only the allowlist's
// fixed public hosts are ever named.
import { isTrustedMetadataClientId } from '@agentx/core/modules/oauth';
import { type OutboundFetch, OutboundRefused } from '@agentx/platform/outbound';

/** The whole fetch's time, headers and body (6E3 plan §6). */
const FETCH_MS = 3000;

/** The most bytes of a document (6E3 plan §6): far beyond any client's few addresses and its name. */
export const MOST_DOCUMENT_BYTES = 16_384;

/** Why a document wasn't taken, for the log: never the document itself. */
type MetadataRefusal =
  'not_listed' | 'refused' | 'status' | 'content_type' | 'too_large' | 'timeout' | 'unreadable' | 'not_json';

export type MetadataFetched =
  | { readonly outcome: 'fetched'; readonly document: unknown }
  | { readonly outcome: 'refused'; readonly reason: MetadataRefusal };

export interface ClientMetadataFetch {
  /** Whether this client ID is an address whose document may be fetched: https, a client ID's shape, listed. */
  listed(clientId: string): boolean;
  fetch(clientId: string): Promise<MetadataFetched>;
}

const refused = (reason: MetadataRefusal): MetadataFetched => ({ outcome: 'refused', reason });

/** Whether the response says it is JSON: `application/json`, with or without parameters. */
const isJson = (type: string | null): boolean => type?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';

/** The body read as it streams, up to `most` bytes; undefined past them, the rest never read. */
async function bodyUpTo(response: Response, most: number): Promise<Buffer | undefined> {
  if (response.body === null) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  let length = 0;
  // Leaving the loop early cancels the stream: the rest is never read.
  for await (const chunk of response.body) {
    const bytes = Buffer.from(chunk as Uint8Array);
    length += bytes.byteLength;
    if (length > most) return undefined;
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

export function createClientMetadataFetch({
  fetch,
  trusted,
  timeoutMs = FETCH_MS,
}: {
  readonly fetch: OutboundFetch;
  /** The allowlist, exactly as the setting holds it: origins, path prefixes and documents' exact addresses (AG6). */
  readonly trusted: readonly string[];
  /** Tests alone shorten it. */
  readonly timeoutMs?: number;
}): ClientMetadataFetch {
  const listed = (clientId: string): boolean => isTrustedMetadataClientId(clientId, trusted);

  /** The document's text, or why not; the time limit already running. */
  const read = async (clientId: string, signal: AbortSignal): Promise<MetadataFetched> => {
    const response = await fetch(clientId, {
      method: 'GET',
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal,
    });
    if (response.status !== 200) {
      await response.body?.cancel();
      return refused('status');
    }
    if (!isJson(response.headers.get('content-type'))) {
      await response.body?.cancel();
      return refused('content_type');
    }
    const body = await bodyUpTo(response, MOST_DOCUMENT_BYTES);
    if (body === undefined) return refused('too_large');
    try {
      return { outcome: 'fetched', document: JSON.parse(body.toString('utf8')) };
    } catch {
      return refused('not_json');
    }
  };

  return {
    listed,
    async fetch(clientId) {
      if (!listed(clientId)) return refused('not_listed');
      const controller = new AbortController();
      const timer = setTimeout(() => {
        controller.abort();
      }, timeoutMs);
      try {
        return await read(clientId, controller.signal);
      } catch (error) {
        if (error instanceof OutboundRefused) return refused('refused');
        return refused(controller.signal.aborted ? 'timeout' : 'unreadable');
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
