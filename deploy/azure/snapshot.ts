// Runs the pinned Bicep compiler over deploy/azure, with no Azure account and
// no network: `bicep lint` for the linter rules in bicepconfig.json, and
// `bicep snapshot` for the resources a deployment would create, with every
// value it can work out resolved (policy.ts checks those). The files are copied
// to a temporary folder first, because a snapshot is written beside its
// parameters file and the repository must stay as it is.
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
  readonly properties?: unknown;
}

export interface Snapshot {
  readonly predictedResources: readonly PredictedResource[];
  /** What Bicep couldn't work out; a snapshot with any is partial (policy rule `snapshot-complete`). */
  readonly diagnostics?: readonly unknown[];
}

const AZURE_DIR = fileURLToPath(new URL('./', import.meta.url));

/** Every environment's parameters file in deploy/azure: each is linted, snapshotted and checked. */
export const paramsFiles = (dir = AZURE_DIR): string[] =>
  readdirSync(dir)
    .filter((file) => file.endsWith('.bicepparam'))
    .sort();

/** Stand-ins for the subscription and tenant a real deployment runs in. */
const SUBSCRIPTION = '00000000-0000-0000-0000-000000000001';
const TENANT = '00000000-0000-0000-0000-000000000002';

/**
 * Values the parameters files read from the deploying shell. The alert address
 * is a reserved example domain; the password is made afresh on every run, so no
 * value that looks like a secret is ever written down.
 */
function standInEnvironment(): Record<string, string> {
  return {
    AGENTX_AZURE_ALERT_EMAIL: 'alerts@example.invalid',
    AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD: randomBytes(24).toString('base64url'),
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

/** The names of main.bicep's secure parameters, read from the compiled template. */
export function secureParameters(dir: string): string[] {
  const run = runBicep(['build', 'main.bicep', '--stdout'], dir);
  if (run.status !== 0) throw new Error(`bicep build main.bicep failed:\n${run.output}`);
  const parameters = (JSON.parse(run.stdout) as { parameters?: Record<string, { type?: string }> }).parameters ?? {};
  return Object.entries(parameters)
    .filter(([, parameter]) => /^secure/i.test(parameter.type ?? ''))
    .map(([name]) => name);
}

/** What a deployment of the parameters file would create, resolved as far as Bicep can without Azure. */
export function snapshot(dir: string, paramsFile: string): Snapshot {
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
    ],
    dir,
    standInEnvironment(),
  );
  if (run.status !== 0) throw new Error(`bicep snapshot ${paramsFile} failed:\n${run.output}`);
  const written = path.join(dir, paramsFile.replace(/\.bicepparam$/, '.snapshot.json'));
  return JSON.parse(readFileSync(written, 'utf8')) as Snapshot;
}
