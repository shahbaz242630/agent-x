// Where the witness log keeps the chains' heads (TR-1, audit-chain/witness-log.ts): a write-once container in the UAE as
// the process's own managed identity, and the leader's snapshots in a container of their own (only the jobs copy may
// add there); or local folders in development and test, as the anchors' store. Read by the API (every role) and the
// operator's command (the heads alone: it only adds its own). Production refuses to start without them: a copy that
// writes chains without witnessing them leaves every other copy blind to its stops.
import {
  type BlobContainer,
  blobContainerOf,
  blobContainerProblems,
  type BlobContainerSettings,
} from './blob-container.ts';
import type { Env, Environment } from './common.ts';
import { type Checked, setting } from './settings.ts';

/** The heads' settings. */
const WITNESS_HEADS: BlobContainerSettings = {
  directory: 'AGENTX_AUDIT_WITNESS_DIR',
  url: 'AGENTX_AUDIT_WITNESS_URL',
  clientId: 'AGENTX_AUDIT_WITNESS_CLIENT_ID',
  deployedDoes: "keeps the chains' witnessed heads in their write-once container",
  holder: 'the app',
};

/** The snapshots' settings: the same identity as the heads'. */
const WITNESS_SNAPSHOTS: BlobContainerSettings = {
  directory: 'AGENTX_AUDIT_WITNESS_SNAPSHOTS_DIR',
  url: 'AGENTX_AUDIT_WITNESS_SNAPSHOTS_URL',
  clientId: 'AGENTX_AUDIT_WITNESS_CLIENT_ID',
  deployedDoes: "keeps the witness log's snapshots in their write-once container",
  holder: 'the app',
};

/** A store as set: a folder, development and test alone, or a container; null for each not set. */
export interface StorePlace {
  readonly directory: string | null;
  readonly container: BlobContainer | null;
}

/** Where the witness log is kept: the heads, and the snapshots apart. */
export interface WitnessStoreConfig {
  readonly heads: StorePlace;
  readonly snapshots: StorePlace;
}

/** The witness log's settings, each checked on its own. */
export function witnessSettings(env: Env) {
  return {
    witnessDirectory: setting(env, 'AGENTX_AUDIT_WITNESS_DIR'),
    witnessContainer: setting(env, 'AGENTX_AUDIT_WITNESS_URL'),
    witnessClientId: setting(env, 'AGENTX_AUDIT_WITNESS_CLIENT_ID'),
    witnessSnapshotsDirectory: setting(env, 'AGENTX_AUDIT_WITNESS_SNAPSHOTS_DIR'),
    witnessSnapshotsContainer: setting(env, 'AGENTX_AUDIT_WITNESS_SNAPSHOTS_URL'),
  };
}

type WitnessChecks = ReturnType<typeof witnessSettings>;

/** Whether a store is named at all, or its setting is wrong (already its own problem). */
const named = (directory: Checked<string | undefined>, container: Checked<string | undefined>): boolean =>
  !directory.ok || !container.ok || directory.value !== undefined || container.value !== undefined;

/**
 * The witness log's rules where its settings are valid: each store as blobContainerProblems says, and in production,
 * where `required` (the API's: every copy writes chains), both stores named. The operator's command checks its own at
 * the commands that write a chain.
 */
export function witnessProblems(
  env: Env,
  environment: Environment,
  checks: WitnessChecks,
  { required }: { readonly required: boolean },
): string[] {
  const { witnessDirectory, witnessContainer, witnessClientId, witnessSnapshotsDirectory, witnessSnapshotsContainer } =
    checks;
  const production = required && environment === 'production';
  return [
    ...(production && !named(witnessDirectory, witnessContainer)
      ? [`${WITNESS_HEADS.url}: is required in production; without it no other copy sees this one's chain heads`]
      : []),
    ...(production && !named(witnessSnapshotsDirectory, witnessSnapshotsContainer)
      ? [`${WITNESS_SNAPSHOTS.url}: is required in production; without it a start reads a day of heads files`]
      : []),
    ...(witnessDirectory.ok && witnessContainer.ok && witnessClientId.ok
      ? blobContainerProblems(env, environment, WITNESS_HEADS, {
          directory: witnessDirectory.value,
          container: witnessContainer.value,
          clientId: witnessClientId.value,
        })
      : []),
    ...(witnessSnapshotsDirectory.ok && witnessSnapshotsContainer.ok && witnessClientId.ok
      ? blobContainerProblems(env, environment, WITNESS_SNAPSHOTS, {
          directory: witnessSnapshotsDirectory.value,
          container: witnessSnapshotsContainer.value,
          // Shared with the heads: asked of the snapshots only where their container is named.
          clientId: witnessSnapshotsContainer.value === undefined ? undefined : witnessClientId.value,
        })
      : []),
  ];
}

/** The witness log's stores, once every setting is valid. */
export function witnessStoreOf(
  env: Env,
  checks: { readonly [Name in keyof WitnessChecks]: { readonly value: string | undefined } },
): WitnessStoreConfig {
  const clientId = checks.witnessClientId.value;
  return Object.freeze({
    heads: Object.freeze({
      directory: checks.witnessDirectory.value ?? null,
      container: blobContainerOf(env, checks.witnessContainer.value, clientId),
    }),
    snapshots: Object.freeze({
      directory: checks.witnessSnapshotsDirectory.value ?? null,
      container: blobContainerOf(env, checks.witnessSnapshotsContainer.value, clientId),
    }),
  });
}
