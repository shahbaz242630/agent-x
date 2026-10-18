// The write-once container in the UAE an audit export for a case goes to
// (Phase 3 E10c-3; ADR-005 §6, ADR-002): Azure's blob service, written over
// its REST interface through the outbound allowlist (no cloud SDK, ADR-010),
// as the operator job's own managed identity. Shared keys are off on the
// account, so a token is the only way in.
//
// - The token: asked of the identity endpoint Azure serves inside the
//   container, with the header Azure gives the process, for the storage
//   resource and the job's identity (its client ID). Neither the header nor
//   the token is ever logged, nor kept past the write.
// - The write: one Put Blob, whole, never over a blob there already
//   (`If-None-Match: *`; Azure answers 409 BlobAlreadyExists), the service
//   checking the bytes it took against their MD5, their SHA-256 kept beside
//   them as metadata. The account's immutability keeps it from being
//   changed or deleted after.
// - A failure names the call and its status, and Azure's error code where it
//   gives one (a constant), never a URL past its origin, a header or a body.
import { createHash } from 'node:crypto';

import type { OutboundFetch } from '@agentx/platform/outbound';

import type { EvidenceStore } from './evidence-store.ts';

/** The resource a token for Azure's blob service is asked for. */
const STORAGE_RESOURCE = 'https://storage.azure.com/';

/** The identity endpoint's API version in Container Apps (Microsoft). */
const IDENTITY_API_VERSION = '2019-08-01';

/** The blob service's API version every write names. */
const BLOB_API_VERSION = '2024-11-04';

/** How long one call may take: a file of 10,000 events is about 20 MB. */
const CALL_TIMEOUT_MS = 120_000;

/** Azure's own code for a write refused because the blob is there already. */
const ALREADY_THERE = 'BlobAlreadyExists';

export interface AzureBlobSettings {
  readonly url: string;
  readonly clientId: string;
  readonly identityEndpoint: string;
  /** Never logged. */
  readonly identityHeader: string;
}

/** A call to the identity endpoint or the blob service that didn't do what was asked: its status and Azure's code. */
class EvidenceStoreFailed extends Error {
  constructor(what: string) {
    super(`The evidence store failed: ${what}`);
    this.name = 'EvidenceStoreFailed';
  }
}

/** Azure's error code from an answer's header, if it is a plain constant. */
const errorCodeOf = (response: Response): string => {
  const code = response.headers.get('x-ms-error-code') ?? '';
  return /^[A-Za-z]{1,64}$/.test(code) ? code : 'no code';
};

/** The token's value in the identity endpoint's answer, or undefined for an answer that has none. */
const tokenIn = (body: unknown): string | undefined =>
  typeof body === 'object' && body !== null && 'access_token' in body && typeof body.access_token === 'string'
    ? body.access_token
    : undefined;

/** The origins the store calls, for its outbound allowlist: the identity endpoint's and the container's. */
export const azureBlobOrigins = ({ url, identityEndpoint }: AzureBlobSettings): readonly string[] => [
  new URL(identityEndpoint).origin,
  new URL(url).origin,
];

export function azureBlobStore({
  settings,
  fetch,
}: {
  readonly settings: AzureBlobSettings;
  readonly fetch: OutboundFetch;
}): EvidenceStore {
  const { url, clientId, identityEndpoint, identityHeader } = settings;

  /** A token for the blob service, as the job's managed identity. */
  const token = async (): Promise<string> => {
    const asked = new URL(identityEndpoint);
    asked.searchParams.set('api-version', IDENTITY_API_VERSION);
    asked.searchParams.set('resource', STORAGE_RESOURCE);
    asked.searchParams.set('client_id', clientId);
    const response = await fetch(asked, {
      headers: { 'x-identity-header': identityHeader },
      signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new EvidenceStoreFailed(`the identity endpoint answered ${String(response.status)}`);
    }
    const found = tokenIn(await response.json());
    if (found === undefined) throw new EvidenceStoreFailed("the identity endpoint's answer holds no token");
    return found;
  };

  return {
    async put(name, content) {
      const bearer = await token();
      const response = await fetch(`${url}/${name}`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${bearer}`,
          'x-ms-version': BLOB_API_VERSION,
          'x-ms-blob-type': 'BlockBlob',
          'if-none-match': '*',
          'content-type': 'application/x-ndjson',
          'content-md5': createHash('md5').update(content).digest('base64'),
          'x-ms-meta-sha256': createHash('sha256').update(content).digest('hex'),
        },
        body: content,
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
      });
      // Nothing of the answer is read but its status and code.
      await response.body?.cancel();
      if (response.status === 201) return 'written';
      const code = errorCodeOf(response);
      if (response.status === 409 && code === ALREADY_THERE) return 'there_already';
      throw new EvidenceStoreFailed(`the blob service answered ${String(response.status)} (${code})`);
    },
  };
}
