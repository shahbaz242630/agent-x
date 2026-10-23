/**
 * The load test of the money paths (Phase 4 D2, PL-38): `corepack pnpm load`,
 * with Docker running and the dev stack (`agentx`) down. In order:
 * 1. a clean `agentx-load` stack, the database and the API alone (compose.load.yaml)
 * 2. the seed: organisations, agents with mandates and keys (seed.load.test.ts)
 * 3. phase 1 of k6 (money-paths.k6.js)
 * 4. the API restarted, so its holdings check runs over phase 1's requests
 * 5. phase 2 of k6, with the spike
 * 6. the database checked (verify.load.test.ts) and the API's log read (logs.ts)
 * 7. the report, numbers only, into tooling/load/reports; the stack removed.
 * It fails if any check does. `--keep` leaves the stack up to look at;
 * `--cpus 2` gives the API two CPUs instead of staging's half.
 * Docker and Vitest run with argument lists and no shell.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, statfsSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ENV_FILE, prepare } from '../../deploy/compose/prepare.ts';
import { logFailures, summariseLogs } from './logs.ts';
import {
  API_CPUS_VARIABLE,
  LEAST_API_CPUS,
  LOAD_PROJECT,
  MOST_API_CPUS,
  optionsOf,
  OUT_DIR,
  POLICY_P95_MS,
  REPORTS_DIR,
} from './plan.ts';
import { type PhaseResult, phaseFailures, renderReport } from './report.ts';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const COMPOSE = [
  'compose',
  '-p',
  LOAD_PROJECT,
  '-f',
  path.join(ROOT, 'deploy/compose/compose.yaml'),
  '-f',
  path.join(ROOT, 'tooling/load/compose.load.yaml'),
];
const VITEST = path.join(ROOT, 'node_modules/vitest/vitest.mjs');

/** Docker's disk image grows with the stack: a run starts only with this much free (S93). */
const LEAST_FREE_BYTES = 20 * 1024 ** 3;

class LoadRefused extends Error {}

function run(command: string, args: readonly string[], options: { env?: NodeJS.ProcessEnv; shown?: boolean } = {}) {
  const done = spawnSync(command, args, {
    cwd: ROOT,
    env: { ...process.env, ...options.env },
    stdio: options.shown === false ? 'pipe' : 'inherit',
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 512 * 1024 ** 2,
  });
  if (done.error !== undefined) throw done.error;
  return { code: done.status, stdout: done.stdout };
}

function must(what: string, command: string, args: readonly string[], env: NodeJS.ProcessEnv = {}): void {
  console.log(`\n== ${what}`);
  if (run(command, args, { env }).code !== 0) throw new LoadRefused(`${what} failed: its output is above.`);
}

/** One login prepare wrote to deploy/compose/.env, by name. Never printed. */
function localLogin(name: string): string {
  const line = readFileSync(ENV_FILE, 'utf8')
    .split(/\r?\n/)
    .find((entry) => entry.startsWith(`${name}=`));
  if (line === undefined) throw new LoadRefused(`deploy/compose/.env has no ${name}.`);
  return line.slice(name.length + 1).trim();
}

function preflight(): void {
  if (run('docker', ['info', '--format', '{{.ServerVersion}}'], { shown: false }).code !== 0) {
    throw new LoadRefused('Docker is not running: start Docker Desktop, then run this again.');
  }
  // The dev stack's internal network has the same fixed addresses: never stopped from here, it may be someone's.
  const devStack = run('docker', ['ps', '-q', '--filter', 'label=com.docker.compose.project=agentx'], { shown: false });
  if (devStack.stdout.trim() !== '') {
    throw new LoadRefused('The dev stack (compose project agentx) is up, on the same addresses: stop it first.');
  }
  const { bavail, bsize } = statfsSync(ROOT);
  if (bavail * bsize < LEAST_FREE_BYTES) {
    throw new LoadRefused('Less than 20 GB is free on this disk: Docker could fill it. Free some first.');
  }
}

function phase(n: 1 | 2): PhaseResult {
  console.log(`\n== Phase ${String(n)} (k6, about two minutes)`);
  const args = [...COMPOSE, '--profile', 'load', 'run', '--rm', '--no-deps', '-e', `PHASE=${String(n)}`, 'k6'];
  // k6 answers 99 when a threshold failed: the report says which, so the run goes on.
  const { code } = run('docker', [...args, 'run', '--quiet', '/load/money-paths.k6.js']);
  if (code !== 0 && code !== 99) throw new LoadRefused(`k6 stopped in phase ${String(n)} (exit ${String(code)}).`);
  return JSON.parse(readFileSync(path.join(OUT_DIR, `k6-phase-${String(n)}.json`), 'utf8')) as PhaseResult;
}

/** The report's file for today and the API's size: a second run the same day gets its own. */
function reportFile(at: string, apiCpus: number): string {
  mkdirSync(REPORTS_DIR, { recursive: true });
  const name = `${at.slice(0, 10)}-local-${String(apiCpus)}cpu`;
  for (let n = 1; ; n += 1) {
    const file = path.join(REPORTS_DIR, n === 1 ? `${name}.md` : `${name}-${String(n)}.md`);
    if (!existsSync(file)) return file;
  }
}

function main(keep: boolean, apiCpus: number): number {
  preflight();
  // Read by compose.load.yaml: each docker call below inherits it.
  process.env[API_CPUS_VARIABLE] = String(apiCpus);
  prepare();
  const login = { AGENTX_LOAD_DB_PASSWORD: localLogin('AGENTX_LOCAL_DB_APP_PASSWORD') };
  const at = new Date().toISOString();
  const commit = run('git', ['rev-parse', '--short', 'HEAD'], { shown: false }).stdout.trim();
  must('A clean stack', 'docker', [...COMPOSE, 'down', '-v', '--remove-orphans']);
  rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(OUT_DIR, { recursive: true });
  try {
    // Built once: the set-up jobs and the API share the image, and building it for each at once races.
    must('The app image', 'docker', [...COMPOSE, 'build', 'api']);
    must('The database and the API', 'docker', [...COMPOSE, 'up', '--no-build', '--wait', 'api']);
    must('The seed', process.execPath, [VITEST, 'run', '--config', 'vitest.load.config.ts', 'seed'], login);
    const first = phase(1);
    must('The API restarted', 'docker', [...COMPOSE, 'restart', 'api']);
    must('The API back', 'docker', [...COMPOSE, 'up', '--wait', '--no-deps', 'api']);
    const second = phase(2);
    const created = first.created + second.created;
    console.log('\n== The database after the run');
    const verified = run(process.execPath, [VITEST, 'run', '--config', 'vitest.load.config.ts', 'verify'], {
      env: { ...login, AGENTX_LOAD_CREATED: String(created) },
    });
    const log = run('docker', [...COMPOSE, 'logs', '--no-log-prefix', '--no-color', 'api'], { shown: false });
    writeFileSync(path.join(OUT_DIR, 'api.log'), log.stdout);
    const logs = summariseLogs(log.stdout);
    const failures = [
      ...phaseFailures(first),
      ...phaseFailures(second),
      ...(verified.code === 0 ? [] : ['The database checks failed: their output is above.']),
      ...logFailures(logs, created, POLICY_P95_MS),
    ];
    const file = reportFile(at, apiCpus);
    const report = renderReport({
      at,
      commit,
      apiCpus,
      phases: [first, second],
      logs,
      databaseChecksPassed: verified.code === 0,
      failures,
    });
    writeFileSync(file, report);
    console.log(`\n${report}\nThe report: ${file}\nThe API's log: ${path.join(OUT_DIR, 'api.log')}`);
    return failures.length === 0 ? 0 : 1;
  } finally {
    if (keep) console.log(`\nThe stack is left up (--keep): docker ${COMPOSE.join(' ')} down -v`);
    else run('docker', [...COMPOSE, 'down', '-v', '--remove-orphans']);
  }
}

if (import.meta.main) {
  try {
    const options = optionsOf(process.argv.slice(2));
    if (options === undefined) {
      throw new LoadRefused(
        `Run it as \`corepack pnpm load [--keep] [--cpus <n>]\`, n from ${String(LEAST_API_CPUS)} to ${String(MOST_API_CPUS)}.`,
      );
    }
    process.exitCode = main(options.keep, options.apiCpus);
  } catch (error) {
    if (!(error instanceof LoadRefused)) throw error;
    console.error(`\n${error.message}`);
    process.exitCode = 1;
  }
}
