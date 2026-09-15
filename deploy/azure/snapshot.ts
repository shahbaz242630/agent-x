// Runs the pinned Bicep compiler over deploy/azure, with no Azure account and
// no network: `bicep lint` for the linter rules in bicepconfig.json, `bicep
// build` for what only the compiled template shows, and `bicep snapshot` for
// the resources a deployment would create, with every value it can work out
// resolved (policy.ts checks those). The files are copied to a temporary folder
// first, because a snapshot is written beside its parameters file and the
// repository must stay as it is.
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { installedBicep } from '../../tooling/bicep/bicep.ts';

/** One resource as the snapshot predicts it. Values Azure only knows at deploy time stay as ARM expressions. */
export interface PredictedResource {
  readonly id: string;
  readonly type: string;
  readonly name: string;
  readonly apiVersion: string;
  readonly location?: string;
  readonly kind?: string;
  readonly tags?: Readonly<Record<string, string>>;
  /** A condition Bicep can't settle offline, such as one on a secure parameter: the resource is deployed only if it holds. */
  readonly condition?: string;
  readonly properties?: unknown;
}

export interface Snapshot {
  readonly predictedResources: readonly PredictedResource[];
  /** What Bicep couldn't work out; a snapshot with any is partial (policy rule `snapshot-complete`). */
  readonly diagnostics?: readonly unknown[];
}

const AZURE_DIR = fileURLToPath(new URL('./', import.meta.url));

/** Every environment's parameters files in deploy/azure: each is linted, snapshotted and checked. */
export const paramsFiles = (dir = AZURE_DIR): string[] =>
  readdirSync(dir)
    .filter((file) => file.endsWith('.bicepparam'))
    .sort();

/**
 * The environments with a foundation: `<environment>.bicepparam` deploys
 * main.bicep, and each `<environment>.<part>.bicepparam` a part of it.
 */
export const environments = (dir = AZURE_DIR): string[] =>
  paramsFiles(dir).flatMap((file) => /^([a-z]+)\.bicepparam$/.exec(file)?.slice(1) ?? []);

/** The Bicep file a parameters file deploys, from its `using` line. */
export function templateOf(paramsText: string): string {
  const using = /^using\s+'([^']+)'\s*$/m.exec(paramsText)?.[1];
  if (using === undefined) throw new Error('a parameters file must name its Bicep file on a `using` line');
  return using;
}

/** Stand-ins for the subscription and tenant a real deployment runs in. */
const SUBSCRIPTION = '00000000-0000-0000-0000-000000000001';
const TENANT = '00000000-0000-0000-0000-000000000002';

/** A stand-in for one secret, made afresh on every run, so no value that looks like one is ever written down. */
const standIn = (bytes: number): string => randomBytes(bytes).toString('hex');

/**
 * Values the parameters files read from the deploying shell: a reserved
 * example domain for the alert address, and a fresh stand-in for every secret.
 * Zitadel's master key is exactly 32 characters, as secrets.bicep requires.
 */
function standInEnvironment(): Record<string, string> {
  return {
    AGENTX_AZURE_ALERT_EMAIL: 'alerts@example.invalid',
    AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD: standIn(24),
    AGENTX_AZURE_DB_OWNER_PASSWORD: standIn(24),
    AGENTX_AZURE_DB_APP_PASSWORD: standIn(24),
    AGENTX_AZURE_DB_BACKUP_PASSWORD: standIn(24),
    AGENTX_AZURE_DB_ZITADEL_PASSWORD: standIn(24),
    AGENTX_AZURE_ZITADEL_MASTERKEY: standIn(16),
    AGENTX_AZURE_ZITADEL_ADMIN_PASSWORD: standIn(24),
    AGENTX_AZURE_LOGIN_CLIENT_PRIVATE_KEY: standIn(24),
    AGENTX_AZURE_LOGIN_CLIENT_PUBLIC_KEY: standIn(24),
  };
}

export interface BicepRun {
  readonly status: number | null;
  /** What it printed, both streams together, for messages and the lint checks. */
  readonly output: string;
  /** Standard output alone, for a command whose output is data (`build --stdout`). */
  readonly stdout: string;
}

function runBicep(args: readonly string[], cwd: string, env: Record<string, string> = {}): BicepRun {
  const run = spawnSync(installedBicep(), args, {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    windowsHide: true,
  });
  if (run.error !== undefined) throw run.error;
  return { status: run.status, output: `${run.stdout}${run.stderr}`.trim(), stdout: run.stdout };
}

/** A throwaway copy of a deploy/azure folder, removed after `use` returns. */
export function inCopy<T>(use: (dir: string) => T, source = AZURE_DIR): T {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentx-azure-'));
  try {
    cpSync(source, dir, {
      recursive: true,
      filter: (file) => !/\.(?:ts|json)$/.test(file) || path.basename(file) === 'bicepconfig.json',
    });
    return use(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** `bicep lint` on one file of a folder, with the folder's bicepconfig.json. */
export const lint = (dir: string, file: string): BicepRun => runBicep(['lint', file], dir, standInEnvironment());

/** A Bicep file of a folder, compiled to its ARM template. */
export function build(dir: string, file: string): unknown {
  const run = runBicep(['build', file, '--stdout'], dir);
  if (run.status !== 0) throw new Error(`bicep build ${file} failed:\n${run.output}`);
  return JSON.parse(run.stdout) as unknown;
}

/** The names of a compiled template's secure parameters. */
export function secureParameters(template: unknown): string[] {
  const parameters = (template as { parameters?: Record<string, { type?: string }> }).parameters ?? {};
  return Object.entries(parameters)
    .filter(([, parameter]) => /^secure/i.test(parameter.type ?? ''))
    .map(([name]) => name);
}

/**
 * Values a deploying shell sets over the stand-ins, such as a rotation run's
 * empty ones. Environment variables only: this is how a parameters file reads them.
 */
type ShellValues = Readonly<Record<string, string>>;

/**
 * What a deployment of the parameters file would create, resolved as far as
 * Bicep can without Azure: at subscription scope, or into `resourceGroup` for
 * a part of an environment's foundation.
 */
function snapshot(dir: string, paramsFile: string, resourceGroup: string | undefined, values: ShellValues): Snapshot {
  const run = runBicep(
    [
      'snapshot',
      paramsFile,
      '--mode',
      'overwrite',
      '--subscription-id',
      SUBSCRIPTION,
      '--tenant-id',
      TENANT,
      '--location',
      'uaenorth',
      ...(resourceGroup === undefined ? [] : ['--resource-group', resourceGroup]),
    ],
    dir,
    { ...standInEnvironment(), ...values },
  );
  if (run.status !== 0) throw new Error(`bicep snapshot ${paramsFile} failed:\n${run.output}`);
  const written = path.join(dir, paramsFile.replace(/\.bicepparam$/, '.snapshot.json'));
  return JSON.parse(readFileSync(written, 'utf8')) as Snapshot;
}

export interface EnvironmentSnapshot {
  /** main.bicep's deployment alone. */
  readonly foundation: Snapshot;
  /** Each part's deployment alone, by its parameters file. */
  readonly parts: ReadonlyMap<string, Snapshot>;
  /** Everything together, as the policy checks it, so a part can only point at what the foundation creates. */
  readonly together: Snapshot;
}

/**
 * Everything an environment's deployments would create: the foundation at
 * subscription scope, then each part into the resource group the foundation
 * creates, the order they are deployed in (G3). `values` are set over the
 * stand-ins, as a deploying shell would.
 */
export function environmentSnapshot(dir: string, environment: string, values: ShellValues = {}): EnvironmentSnapshot {
  const foundation = snapshot(dir, `${environment}.bicepparam`, undefined, values);
  const groups = foundation.predictedResources.filter(
    (resource) => resource.type === 'Microsoft.Resources/resourceGroups',
  );
  const group = groups[0];
  if (group === undefined || groups.length > 1) {
    throw new Error(`${environment}.bicepparam must create one resource group; it creates ${String(groups.length)}`);
  }
  const parts = new Map(
    paramsFiles(dir)
      .filter((file) => file.startsWith(`${environment}.`) && file !== `${environment}.bicepparam`)
      .map((file) => [file, snapshot(dir, file, group.name, values)] as const),
  );
  const all = [foundation, ...parts.values()];
  return {
    foundation,
    parts,
    together: {
      predictedResources: all.flatMap((part) => part.predictedResources),
      diagnostics: all.flatMap((part) => part.diagnostics ?? []),
    },
  };
}
