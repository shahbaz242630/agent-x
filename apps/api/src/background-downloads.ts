// The activity log's background downloads, as the config sets them up (Phase
// 3 L5c): the store, a container in the UAE written and read as the API's own
// managed identity, or the local folder in development and test; then the
// routes' use cases (asking, reading, downloading) and the builder's job. With neither set, both
// are off: the routes answer NOT_FOUND and no builder runs.
import type { Config } from '@agentx/platform/config';
import { createOutboundFetch } from '@agentx/platform/outbound';
import { azureBlobOrigins, azureBlockStore, type BlockStore, folderBlockStore } from '@agentx/platform/storage';

import { type ActivityExportBuilder, createActivityExportBuilder } from './activity-export-builder.ts';
import { type BackgroundExports, createBackgroundExports } from './activity-background-exports.ts';
import { createDownloadFiles, type DownloadFiles } from './activity-download-files.ts';

/** The store the config names, or undefined for none. */
export function downloadStoreOf({ activityDownloads: { directory, container } }: Config): BlockStore | undefined {
  if (container !== null) {
    return azureBlockStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  }
  return directory === null ? undefined : folderBlockStore(directory);
}

type ExportsServices = Parameters<typeof createBackgroundExports>[0];
type BuilderServices = Omit<Parameters<typeof createActivityExportBuilder>[0], 'store'>;

/** The routes' use cases and the builder, with the store; all undefined without one. */
export function backgroundDownloadsFrom(
  store: BlockStore | undefined,
  services: ExportsServices & BuilderServices,
): {
  readonly exports: BackgroundExports | undefined;
  readonly files: DownloadFiles | undefined;
  readonly builder: ActivityExportBuilder | undefined;
} {
  if (store === undefined) return { exports: undefined, files: undefined, builder: undefined };
  return {
    exports: createBackgroundExports(services),
    files: createDownloadFiles({ ...services, store }),
    builder: createActivityExportBuilder({ ...services, store }),
  };
}
