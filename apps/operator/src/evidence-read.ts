// A file the operator's jobs wrote to the evidence store, read back by its
// first line (its summary): a repair reads its plan's (restore-job.ts), and a
// rebase after a repair reads that repair's outcome (AT13f, main.ts). Read
// through the store's own reader, as written; never trusted past what the
// caller checks of it.
//
// The record isn't signed: trust in it rests on `audit-exports` being add-only
// (write-once, nothing overwrites or deletes), writable only by our operator's
// and chain repair's identities (modules/evidence.bicep, policy.ts), and on the
// operator running the command that reads it.
import type { OperatorConfig } from '@agentx/platform/config';
import { createOutboundFetch } from '@agentx/platform/outbound';
import { azureBlobOrigins, azureWriteOnceStore, BlobStoreFailed, folderWriteOnceStore } from '@agentx/platform/storage';

/**
 * Whether the store said the file isn't there: Azure's 404, or the folder's
 * own refusal (development and test). BlobStoreFailed carries its answer in
 * these fixed words alone (packages/platform/src/storage/write-once.ts).
 */
const missingFile = (error: unknown): boolean =>
  error instanceof BlobStoreFailed &&
  (error.message.includes('the blob service answered 404 ') || error.message.endsWith('no file of that name'));

/** Whether the store refused this identity the read: Azure's 403, a role not given (or foundation not run yet). */
const readRefused = (error: unknown): boolean =>
  error instanceof BlobStoreFailed && error.message.includes('the blob service answered 403 ');

/** A summary read, or why there is none: no such file, no read role, or no store named. */
export type EvidenceSummary = Readonly<Record<string, unknown>> | 'missing' | 'denied' | 'unset';

/**
 * The file's first line as an object: `missing` where there is no such file or its first line isn't JSON, `denied`
 * where the store refused this identity the read, `unset` where no evidence store is named. Anything else that stops
 * the read (the network, a timeout) is thrown.
 */
export async function evidenceSummary(
  { evidence: { container, directory } }: OperatorConfig,
  name: string,
): Promise<EvidenceSummary> {
  let reader;
  if (container !== null) {
    reader = azureWriteOnceStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  } else if (directory === null) {
    return 'unset';
  } else {
    reader = folderWriteOnceStore(directory);
  }
  return summaryIn(reader, name);
}

/** The file's first line read through `reader`, as evidenceSummary says it. */
export async function summaryIn(
  reader: { get(name: string): Promise<Buffer> },
  name: string,
): Promise<Exclude<EvidenceSummary, 'unset'>> {
  try {
    const text = (await reader.get(name)).toString('utf8');
    const end = text.indexOf('\n');
    const parsed: unknown = JSON.parse(end < 0 ? text : text.slice(0, end));
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch (error) {
    if (readRefused(error)) return 'denied';
    if (!(missingFile(error) || error instanceof SyntaxError)) throw error;
    return 'missing';
  }
}

/** What a refused read tells the operator, in plain words: whose role to check, and that foundation must have run. */
export const READ_DENIED_PROBLEM =
  "this job's identity can't read the evidence store's records: check its read role on audit-exports and that foundation has run";
