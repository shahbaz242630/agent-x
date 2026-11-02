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

/** A name the stores take: path segments of letters, digits, dots, dashes and underscores, never `..`. */
const NAME = /^(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._-]{1,100}(?:\/[A-Za-z0-9._-]{1,100}){0,4}$/;

export const isBlobName = (name: string): boolean => NAME.test(name);

export function checkedBlobName(name: string): string {
  if (!isBlobName(name)) throw new RangeError('A stored file is named by plain path segments');
  return name;
}

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

/**
 * Azure's own answers to a write refused because the blob is there already:
 * 403 UnauthorizedBlobOverwrite, as staging answered a second write of one
 * export (S125: the writer role holds `blobs/add/action` alone, which may
 * add a blob but never write over one); 409
 * BlobAlreadyExists, as it answers `If-None-Match: *` for an identity that
 * may write; 412 ConditionNotMet, as its page on conditions describes it.
 * Only these codes: any other 403 is a refusal of the identity, a failure.
 */
const ALREADY_THERE: ReadonlySet<string> = new Set([
  '403 UnauthorizedBlobOverwrite',
  '409 BlobAlreadyExists',
  '412 ConditionNotMet',
]);

/** Whether an answer to a write says the blob is there already. */
export const blobAlreadyThere = (response: Response): boolean =>
  ALREADY_THERE.has(`${String(response.status)} ${blobErrorCode(response)}`);

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

/** How long a token is used before another is asked: Azure's last hours, so a long job asks a handful of times. */
const TOKEN_KEPT_MS = 10 * 60_000;

/** A call to a container: `path` follows its URL, the token and the service's own headers are added. */
export type BlobServiceCall = (
  path: string,
  request: { readonly method: string; readonly headers: Record<string, string>; readonly body?: Buffer | string },
) => Promise<Response>;

/** Calls to one store's container, a token asked once and kept for a few minutes. */
export function blobServiceCaller({
  settings,
  fetch,
  store,
  timeoutMs,
  now = () => Date.now(),
}: {
  readonly settings: AzureBlobSettings;
  readonly fetch: OutboundFetch;
  readonly store: string;
  readonly timeoutMs: number;
  /** The clock a kept token is timed by. */
  readonly now?: () => number;
}): BlobServiceCall {
  let kept: { readonly value: string; readonly until: number } | undefined;

  const bearer = async (): Promise<string> => {
    if (kept !== undefined && now() < kept.until) return kept.value;
    const value = await blobServiceToken(settings, fetch, { store, timeoutMs });
    kept = { value, until: now() + TOKEN_KEPT_MS };
    return value;
  };

  return async (path, { method, headers, body }) =>
    fetch(`${settings.url}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${await bearer()}`,
        'x-ms-version': BLOB_API_VERSION,
        'x-ms-date': new Date(now()).toUTCString(),
        ...headers,
      },
      ...(body === undefined ? {} : { body }),
      signal: AbortSignal.timeout(timeoutMs),
    });
}
