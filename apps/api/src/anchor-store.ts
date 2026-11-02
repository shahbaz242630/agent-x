// Where the chains' anchors are kept, as the config sets it up (PL-58): a
// write-once container on Azure as the API's own managed identity, or the local
// folder in development and test. With neither set, memory alone, as job-list.ts
// has it, and a restart forgets them.
import { type AnchorLog, createAnchorLog } from '@agentx/platform/audit-chain';
import type { Config } from '@agentx/platform/config';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { createOutboundFetch } from '@agentx/platform/outbound';
import { azureBlobOrigins, azureWriteOnceStore, folderWriteOnceStore } from '@agentx/platform/storage';

export function anchorLogOf(
  { anchorStore: { directory, container }, audit: { anchorEpoch: epoch } }: Config,
  services: {
    readonly keys: KeyProvider;
    readonly logger: Logger;
    readonly now: () => Date;
    readonly unwritableAfterMs: number;
  },
): AnchorLog | undefined {
  if (container !== null) {
    const fetch = createOutboundFetch(azureBlobOrigins(container));
    return createAnchorLog({ ...services, epoch, store: azureWriteOnceStore({ settings: container, fetch }) });
  }
  return directory === null
    ? undefined
    : createAnchorLog({ ...services, epoch, store: folderWriteOnceStore(directory) });
}
