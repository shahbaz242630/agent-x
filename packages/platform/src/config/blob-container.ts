// A container on Azure's blob service a process writes to as its own managed
// identity, or the local folder standing in for it in development and test:
// the operator's write-once container for an audit export (E10c-3), the API's
// container for the activity log's background downloads (L5c). Each is set by
// three settings of its own (the folder; the container's URL and the
// identity's client ID), checked alike.
import { type Env, type Environment, LOCAL_ONLY } from './common.ts';
import type { SettingName } from './settings.ts';

/**
 * Where Azure tells a container's process how to get its managed identity's
 * token (Container Apps sets both wherever an identity is given): an
 * endpoint inside the container, and a secret its requests must carry.
 */
const IDENTITY_ENDPOINT = 'IDENTITY_ENDPOINT';
const IDENTITY_HEADER = 'IDENTITY_HEADER';

/** The hosts Azure's blob service answers on; a test server stands in for it in development and test. */
const BLOB_HOST = /^[a-z0-9]{3,24}\.blob\.core\.windows\.net$/;

/** A container, once its settings are checked, and how the process asks for its token there. */
export interface BlobContainer {
  readonly url: string;
  readonly clientId: string;
  readonly identityEndpoint: string;
  /** Never logged. */
  readonly identityHeader: string;
}

/** The three settings a store is set by, and what a refused folder says the deployed store is for. */
export interface BlobContainerSettings {
  readonly directory: SettingName;
  readonly url: SettingName;
  readonly clientId: SettingName;
  /** What a deployed environment does instead of writing to the folder (`writes an audit export to …`). */
  readonly deployedDoes: string;
  /** What runs with the identity, as a missing identity setting names it (`the job`, `the app`). */
  readonly holder: string;
}

/** The settings' values, each undefined where not set. */
export interface BlobContainerValues {
  readonly directory: string | undefined;
  readonly container: string | undefined;
  readonly clientId: string | undefined;
}

/**
 * The identity endpoint, if set: plain http only to this container itself
 * (where Azure serves it), https anywhere; nothing else is a place a token
 * may be asked of.
 */
function identityEndpointProblem(endpoint: string): string | undefined {
  const url = URL.canParse(endpoint) ? new URL(endpoint) : undefined;
  const loopback = url?.hostname === 'localhost' || url?.hostname === '127.0.0.1';
  return url !== undefined && (url.protocol === 'https:' || (url.protocol === 'http:' && loopback))
    ? undefined
    : `${IDENTITY_ENDPOINT}: must be the managed identity's endpoint Azure sets: http only to localhost or 127.0.0.1`;
}

/**
 * The store's problems: the folder in development and test alone, the folder
 * or the container but never both, the container with its client ID, on
 * Azure's blob service where deployed, and Azure's identity settings with it.
 */
export function blobContainerProblems(
  env: Env,
  environment: Environment,
  names: BlobContainerSettings,
  { directory, container, clientId }: BlobContainerValues,
): string[] {
  const local = LOCAL_ONLY.includes(environment);
  const endpoint = env[IDENTITY_ENDPOINT];
  const problems = [
    ...(directory !== undefined && !local
      ? [`${names.directory}: is allowed only in ${LOCAL_ONLY.join(' and ')}; ${environment} ${names.deployedDoes}`]
      : []),
    ...(directory !== undefined && container !== undefined
      ? [`${names.directory} and ${names.url}: set one, the folder or the container`]
      : []),
    ...((container === undefined) !== (clientId === undefined)
      ? [`${names.url} and ${names.clientId}: set both, or neither`]
      : []),
  ];
  if (container === undefined) return problems;
  const required = `is required with the container (Azure sets it where ${names.holder} has a managed identity)`;
  return [
    ...problems,
    ...(local || BLOB_HOST.test(new URL(container).hostname)
      ? []
      : [`${names.url}: ${environment} writes to Azure's blob service, <account>.blob.core.windows.net`]),
    ...(endpoint === undefined
      ? [`${IDENTITY_ENDPOINT}: ${required}`]
      : [identityEndpointProblem(endpoint)].filter((problem) => problem !== undefined)),
    ...(env[IDENTITY_HEADER] === undefined || env[IDENTITY_HEADER] === '' ? [`${IDENTITY_HEADER}: ${required}`] : []),
  ];
}

/** The container, once its settings are checked: null where none is set. */
export function blobContainerOf(env: Env, url: string | undefined, clientId: string | undefined): BlobContainer | null {
  if (url === undefined || clientId === undefined) return null;
  return Object.freeze({
    url,
    clientId,
    identityEndpoint: String(env[IDENTITY_ENDPOINT]),
    identityHeader: String(env[IDENTITY_HEADER]),
  });
}
