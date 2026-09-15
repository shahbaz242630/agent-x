// Throwaway Postgres servers for the database tests, run with the Docker CLI
// (ADR-001: no Testcontainers library). Each server is a container from a
// digest-pinned image, reachable only on a random port of 127.0.0.1, and
// removed when the test run ends. A run that is killed can't remove its own
// container, so each one carries an expiry label and the next run removes any
// that have expired. Docker is always run with an argument list and no shell.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

const LABEL = 'agentx-test-db';
const EXPIRES_LABEL = 'agentx-test-db.expires';
const LIFETIME_MS = 2 * 60 * 60 * 1000;

interface DockerResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | null;
}

/** Runs the Docker CLI with `input` on stdin. Rejects only if it can't be started or runs too long. */
function docker(args: readonly string[], input = '', timeoutMs = 120_000): Promise<DockerResult> {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`docker ${args[0] ?? ''} took longer than ${String(timeoutMs)} ms`));
    }, timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(
        new Error('The database tests need Docker. Start Docker Desktop, then run the tests again.', { cause: error }),
      );
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
    child.stdin.end(input);
  });
}

/** Runs the Docker CLI and returns its output, or throws with Docker's own error message. */
async function dockerOk(args: readonly string[], input = '', timeoutMs = 120_000): Promise<string> {
  const result = await docker(args, input, timeoutMs);
  if (result.code !== 0) {
    throw new Error(`docker ${args[0] ?? ''} failed (exit ${String(result.code)}): ${result.stderr.trim()}`);
  }
  return result.stdout;
}

/** The host port Docker published for 127.0.0.1, from `docker port` output such as `127.0.0.1:55001`. */
export function parsePublishedPort(output: string): number {
  const match = /^127\.0\.0\.1:(\d{1,5})$/m.exec(output.trim());
  const port = Number(match?.[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`Docker published no port on 127.0.0.1: ${JSON.stringify(output)}`);
  }
  return port;
}

/** The IDs, from `docker ps` lines of `<id> <expiry in ms>`, whose expiry has passed or can't be read. */
export function expiredContainerIds(output: string, now: number): string[] {
  return output
    .split('\n')
    .map((line) => line.trim().split(/\s+/))
    .flatMap(([id, expires]) => {
      if (id === undefined || id === '') return [];
      const at = Number(expires);
      return Number.isFinite(at) && at > now ? [] : [id];
    });
}

/** Removes test containers left behind by earlier runs that were killed. */
export async function removeExpiredContainers(now: number): Promise<void> {
  const listing = await dockerOk([
    'ps',
    '--all',
    '--filter',
    `label=${LABEL}`,
    '--format',
    `{{.ID}} {{.Label "${EXPIRES_LABEL}"}}`,
  ]);
  const expired = expiredContainerIds(listing, now);
  if (expired.length > 0) await dockerOk(['rm', '--force', ...expired]);
}

export interface PostgresContainer {
  readonly id: string;
  readonly port: number;
  stop(): Promise<void>;
}

/**
 * Starts Postgres with the superuser's password set, and waits until it takes
 * connections on TCP. The first run pulls the image, which can take minutes.
 * The settings that make a server crash-safe are off: nothing here outlives the run.
 */
export async function startPostgres(image: string, superuserLogin: string, now: number): Promise<PostgresContainer> {
  const id = (
    await dockerOk(
      [
        'run',
        '--detach',
        '--rm',
        '--label',
        LABEL,
        '--label',
        `${EXPIRES_LABEL}=${String(now + LIFETIME_MS)}`,
        '--env',
        `POSTGRES_PASSWORD=${superuserLogin}`,
        '--publish',
        '127.0.0.1::5432',
        image,
        '-c',
        'fsync=off',
        '-c',
        'synchronous_commit=off',
        '-c',
        'full_page_writes=off',
      ],
      '',
      600_000,
    )
  ).trim();
  const stop = async (): Promise<void> => {
    await dockerOk(['rm', '--force', id]);
  };

  try {
    // The image's first start runs a temporary server on a local socket only,
    // then restarts; a TCP check passes only once the real server is up.
    for (let attempt = 0; ; attempt += 1) {
      const ready = await docker(['exec', id, 'pg_isready', '--host', '127.0.0.1', '--port', '5432', '--quiet']);
      if (ready.code === 0) break;
      if (attempt >= 240) throw new Error('Postgres did not start within 60 seconds');
      await sleep(250);
    }
    const port = parsePublishedPort(await dockerOk(['port', id, '5432/tcp']));
    return { id, port, stop };
  } catch (error) {
    await stop();
    throw error;
  }
}

/** What a container has written so far: Postgres logs to stderr, so both streams, in the order Docker kept. */
export async function containerLogs(id: string): Promise<string> {
  const result = await docker(['logs', id]);
  if (result.code !== 0) throw new Error(`docker logs failed (exit ${String(result.code)}): ${result.stderr.trim()}`);
  return `${result.stdout}${result.stderr}`;
}

/**
 * Runs a SQL script with psql inside the container, as the superuser, like an
 * admin running db/bootstrap. `variables` fill `:'name'` and `:"name"` in the
 * script, quoted by psql. Returns psql's output.
 */
export async function psql(
  id: string,
  script: string,
  variables: Readonly<Record<string, string>> = {},
): Promise<string> {
  const settings = Object.entries(variables).flatMap(([name, value]) => ['--set', `${name}=${value}`]);
  return dockerOk(
    [
      'exec',
      '--interactive',
      id,
      'psql',
      '--username',
      'postgres',
      '--dbname',
      'postgres',
      '--no-psqlrc',
      '--quiet',
      '--tuples-only',
      '--no-align',
      '--set',
      'ON_ERROR_STOP=1',
      ...settings,
      '--file',
      '-',
    ],
    script,
  );
}
