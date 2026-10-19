// What every store on Azure's blob service shares (Phase 3 E10c-3, L5c): the
// service is reached over its REST interface through the outbound allowlist
// (no cloud SDK, ADR-010), as the workload's own managed identity. Shared
// keys are off on the accounts, so a token is the only way in.
//
// - The token: asked of the identity endpoint Azure serves inside the
//   container, with the header Azure gives the process, for the storage
//   resource and the workload's identity (its client ID). Neither the header
//   nor the token is ever logged, nor kept past the call it is asked for.
// - A failure names the call and its status, and Azure's error code where it
//   gives one (a constant), never a URL past its origin, a header or a body.
import type { OutboundFetch } from '../outbound/index.ts';

/** The resource a token for Azure's blob service is asked for. */
const STORAGE_RESOURCE = 'https://storage.azure.com/';

/** The identity endpoint's API version in Container Apps (Microsoft). */
const IDENTITY_API_VERSION = '2019-08-01';

/** The blob service's API version every call names. */
export const BLOB_API_VERSION = '2024-11-04';

/** A container on the blob service, and how the workload asks for its token there. */
export interface AzureBlobSettings {
  readonly url: string;
  readonly clientId: string;
  readonly identityEndpoint: string;
  /** Never logged. */
  readonly identityHeader: string;
}

/** A call to the identity endpoint or the blob service that didn't do what was asked: its status and Azure's code. */
export class BlobStoreFailed extends Error {
  constructor(store: string, what: string) {
    super(`The ${store} failed: ${what}`);
    this.name = 'BlobStoreFailed';
  }
}

/** Azure's error code from an answer's header, if it is a plain constant. */
export const blobErrorCode = (response: Response): string => {
  const code = response.headers.get('x-ms-error-code') ?? '';
  return /^[A-Za-z]{1,64}$/.test(code) ? code : 'no code';
};

/** The token's value in the identity endpoint's answer, or undefined for an answer that has none. */
const tokenIn = (body: unknown): string | undefined =>
  typeof body === 'object' && body !== null && 'access_token' in body && typeof body.access_token === 'string'
    ? body.access_token
    : undefined;

/** The origins a store calls, for its outbound allowlist: the identity endpoint's and the container's. */
export const azureBlobOrigins = ({ url, identityEndpoint }: AzureBlobSettings): readonly string[] => [
  new URL(identityEndpoint).origin,
  new URL(url).origin,
];

/** A token for the blob service, as the workload's managed identity; a failure is the `store`'s. */
export async function blobServiceToken(
  { clientId, identityEndpoint, identityHeader }: AzureBlobSettings,
  fetch: OutboundFetch,
  { store, timeoutMs }: { readonly store: string; readonly timeoutMs: number },
): Promise<string> {
  const asked = new URL(identityEndpoint);
  asked.searchParams.set('api-version', IDENTITY_API_VERSION);
  asked.searchParams.set('resource', STORAGE_RESOURCE);
  asked.searchParams.set('client_id', clientId);
  const response = await fetch(asked, {
    headers: { 'x-identity-header': identityHeader },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new BlobStoreFailed(store, `the identity endpoint answered ${String(response.status)}`);
  }
  // An answer that isn't JSON is one without a token: the parser's error would quote it.
  const found = tokenIn(await response.json().catch(() => undefined));
  if (found === undefined) throw new BlobStoreFailed(store, "the identity endpoint's answer holds no token");
  return found;
}
