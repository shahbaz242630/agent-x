// The end-to-end suite's handle on the compose stack (deploy/compose): where
// it is reached, how to run `docker compose` against it, and how to read what
// only the stack holds (Zitadel's automation token, the generated logins).
// Docker is always run with an argument list and no shell.
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const COMPOSE_FILE = fileURLToPath(new URL('../../deploy/compose/compose.yaml', import.meta.url));
const ENV_FILE = fileURLToPath(new URL('../../deploy/compose/.env', import.meta.url));

/** The edge's published ports (compose.yaml): the API, and the login service. */
export const API_ORIGIN = 'http://localhost:8080';
export const LOGIN_ORIGIN = 'http://localhost:8081';

export interface Run {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | null;
}

/** Runs the Docker CLI. Rejects only if it can't be started or runs too long. */
function docker(args: readonly string[], timeoutMs = 120_000): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`docker ${args.slice(0, 2).join(' ')} took longer than ${String(timeoutMs)} ms`));
    }, timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(new Error('The end-to-end suite needs Docker and the compose stack up.', { cause: error }));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
  });
}

/** `docker compose` against the stack's file. */
const compose = (args: readonly string[], timeoutMs?: number): Promise<Run> =>
  docker(['compose', '-f', COMPOSE_FILE, ...args], timeoutMs);

/** Runs a compose command and returns its output, or throws with Docker's own message. */
async function composeOk(args: readonly string[], timeoutMs?: number): Promise<string> {
  const run = await compose(args, timeoutMs);
  if (run.code !== 0) {
    throw new Error(`docker compose ${args[0] ?? ''} failed (exit ${String(run.code)}): ${run.stderr.trim()}`);
  }
  return run.stdout;
}

/**
 * Zitadel's automation token, which its first start wrote inside the stack
 * (compose.yaml). Copied out of the container into a private temporary file,
 * read, and removed: it never lands in the repository folder.
 */
export async function readAutomationToken(): Promise<string> {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentx-e2e-'));
  try {
    const file = path.join(dir, 'automation.pat');
    await composeOk(['cp', 'zitadel:/pat-automation/automation.pat', file]);
    return readFileSync(file, 'utf8').trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** One service's log, as the container wrote it. */
export const serviceLogs = (service: string): Promise<string> =>
  composeOk(['logs', '--no-color', '--no-log-prefix', service]);

/** Runs a command inside a running service. */
export const execIn = (service: string, command: readonly string[]): Promise<Run> =>
  compose(['exec', '-T', service, ...command]);

/** The state compose reports for one service, from `ps --format json`. */
export async function serviceState(service: string): Promise<{ State: string; ExitCode: number }> {
  const output = await composeOk(['ps', '--all', '--format', 'json', service]);
  const line = output.split('\n').find((candidate) => candidate.startsWith('{'));
  if (line === undefined) throw new Error(`compose knows no service called ${service}`);
  return JSON.parse(line) as { State: string; ExitCode: number };
}

/** The logins prepare generated, so a test can check none of them reaches a log. Never printed. */
export function localLogins(): string[] {
  return readFileSync(ENV_FILE, 'utf8')
    .split('\n')
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map((line) => line.slice(line.indexOf('=') + 1).trim());
}
