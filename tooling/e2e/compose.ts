// The end-to-end suite's handle on the compose stack (deploy/compose): where
// it is reached, how to run `docker compose` against it, and how to read what
// only the stack holds (Zitadel's automation token, the generated logins).
// Docker is always run with an argument list and no shell.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { firstFileIn } from './tar.ts';

const COMPOSE_FILE = fileURLToPath(new URL('../../deploy/compose/compose.yaml', import.meta.url));
const ENV_FILE = fileURLToPath(new URL('../../deploy/compose/.env', import.meta.url));

/** The stack's gitignored secrets folder (deploy/compose/prepare.ts). */
export const SECRETS_DIR = fileURLToPath(new URL('../../deploy/compose/secrets', import.meta.url));

/** The edge's published ports (compose.yaml): the API, and the login service. */
export const API_ORIGIN = 'http://localhost:8080';
export const LOGIN_ORIGIN = 'http://localhost:8081';

export interface Run {
  readonly stdout: string;
  /** stdout as it came, for a command that writes bytes (a tar stream). */
  readonly bytes: Buffer;
  readonly stderr: string;
  readonly code: number | null;
}

/**
 * Runs the Docker CLI. Rejects only if it can't be started or runs too long.
 * `env` adds variables to the CLI's own environment, for a value that must
 * not be on its command line (`exec -e NAME` passes it on from there).
 */
function docker(args: readonly string[], timeoutMs = 120_000, env: Record<string, string> = {}): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    });
    const stdout: Buffer[] = [];
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`docker ${args.slice(0, 2).join(' ')} took longer than ${String(timeoutMs)} ms`));
    }, timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(new Error('The end-to-end suite needs Docker and the compose stack up.', { cause: error }));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const bytes = Buffer.concat(stdout);
      resolve({ stdout: bytes.toString('utf8'), bytes, stderr, code });
    });
  });
}

/** `docker compose` against the stack's file. */
const compose = (args: readonly string[], timeoutMs?: number, env?: Record<string, string>): Promise<Run> =>
  docker(['compose', '-f', COMPOSE_FILE, ...args], timeoutMs, env);

/** Runs a compose command, or throws with Docker's own message. */
async function composeRun(args: readonly string[], timeoutMs?: number): Promise<Run> {
  const run = await compose(args, timeoutMs);
  if (run.code !== 0) {
    throw new Error(`docker compose ${args[0] ?? ''} failed (exit ${String(run.code)}): ${run.stderr.trim()}`);
  }
  return run;
}

/** Runs a compose command and returns its output, or throws with Docker's own message. */
const composeOk = async (args: readonly string[], timeoutMs?: number): Promise<string> =>
  (await composeRun(args, timeoutMs)).stdout;

/**
 * Zitadel's automation token, which its first start wrote inside the stack
 * (compose.yaml). `cp … -` streams it out of the container as a tar archive
 * on stdout, so it is read in memory and never touches the host's disk.
 */
export async function readAutomationToken(): Promise<string> {
  const { bytes } = await composeRun(['cp', 'zitadel:/pat-automation/automation.pat', '-']);
  const token = firstFileIn(bytes).toString('utf8').trim();
  if (token === '') throw new Error("Zitadel's automation token is empty");
  return token;
}

/** One service's log, as the container wrote it. */
export const serviceLogs = (service: string): Promise<string> =>
  composeOk(['logs', '--no-color', '--no-log-prefix', service]);

/** Runs a command inside a running service, with `env`'s variables passed on by name alone. */
export const execIn = (service: string, command: readonly string[], env: Record<string, string> = {}): Promise<Run> =>
  compose(['exec', '-T', ...Object.keys(env).flatMap((name) => ['-e', name]), service, ...command], undefined, env);

/**
 * Starts these services again, alone (`--no-deps`), and waits until they are
 * up; `recreate` makes new containers even if compose sees no change, as it
 * doesn't for a changed file they mount.
 */
export async function restart(services: readonly string[], recreate: boolean): Promise<void> {
  await composeRun(
    ['up', '--detach', '--no-deps', '--wait', ...(recreate ? ['--force-recreate'] : []), ...services],
    300_000,
  );
}

/** The state compose reports for one service, from `ps --format json`. */
export async function serviceState(service: string): Promise<{ State: string; ExitCode: number }> {
  const output = await composeOk(['ps', '--all', '--format', 'json', service]);
  const line = output.split('\n').find((candidate) => candidate.startsWith('{'));
  if (line === undefined) throw new Error(`compose knows no service called ${service}`);
  return JSON.parse(line) as { State: string; ExitCode: number };
}

/** The .env file's lines, as name and value. */
const envEntries = (): [string, string][] =>
  readFileSync(ENV_FILE, 'utf8')
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map((line) => [line.slice(0, line.indexOf('=')).trim(), line.slice(line.indexOf('=') + 1).trim()]);

/** The logins prepare generated, so a test can check none of them reaches a log. Never printed. */
export const localLogins = (): string[] => envEntries().map(([, value]) => value);

/** One login prepare generated, by its name. Never printed. */
export function localLogin(name: string): string {
  const found = envEntries().find(([entry]) => entry === name);
  if (found === undefined) throw new Error(`deploy/compose/.env has no ${name}`);
  return found[1];
}
