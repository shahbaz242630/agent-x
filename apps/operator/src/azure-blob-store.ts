// The write-once container in the UAE an audit export for a case goes to
// (Phase 3 E10c-3; ADR-005 §6, ADR-002): Azure's blob service, written over
// its REST interface through the outbound allowlist (no cloud SDK, ADR-010),
// as the operator job's own managed identity. Shared keys are off on the
// account, so a token is the only way in.
//
// - The token: the job's identity's, asked as every store on the blob
//   service asks it (@agentx/platform/storage), never logged or kept.
// - The write: one Put Blob, whole, never over a blob there already
//   (`If-None-Match: *`; Azure answers 403 UnauthorizedBlobOverwrite, as the
//   writer role may add a blob but never write over one), the service
//   checking the bytes it took against their MD5, their SHA-256 kept beside
//   them as metadata. The account's immutability keeps it from being
//   changed or deleted after.
// - A failure names the call and its status, and Azure's error code where it
//   gives one (a constant), never a URL past its origin, a header or a body.
import { createHash } from 'node:crypto';

import type { OutboundFetch } from '@agentx/platform/outbound';
import {
  blobAlreadyThere,
  BLOB_API_VERSION,
  blobErrorCode,
  blobServiceToken,
  BlobStoreFailed,
  type AzureBlobSettings,
} from '@agentx/platform/storage';

import type { EvidenceStore } from './evidence-store.ts';

/** What a failure names: this store. */
const STORE = 'evidence store';

/** How long one call may take: a file of 10,000 events is about 20 MB. */
const CALL_TIMEOUT_MS = 120_000;

export function azureBlobStore({
  settings,
  fetch,
}: {
  readonly settings: AzureBlobSettings;
  readonly fetch: OutboundFetch;
}): EvidenceStore {
  return {
    async put(name, content) {
      const bearer = await blobServiceToken(settings, fetch, { store: STORE, timeoutMs: CALL_TIMEOUT_MS });
      const response = await fetch(`${settings.url}/${name}`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${bearer}`,
          'x-ms-version': BLOB_API_VERSION,
          'x-ms-date': new Date().toUTCString(),
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
      if (blobAlreadyThere(response)) return 'there_already';
      throw new BlobStoreFailed(
        STORE,
        `the blob service answered ${String(response.status)} (${blobErrorCode(response)})`,
      );
    },
  };
}
