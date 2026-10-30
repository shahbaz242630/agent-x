/**
 * The load test of the money paths (Phase 4 D2, PL-38): `corepack pnpm load`,
 * with Docker running and the dev stack (`agentx`) down. In order:
 * 1. a clean `agentx-load` stack, the database and the API alone (compose.load.yaml)
 * 2. the seed: organisations, agents with mandates and keys (seed.load.test.ts)
 * 3. phase 1 of k6 (money-paths.k6.js)
 * 4. the API restarted, so its holdings check runs over phase 1's requests,
 *    and a new key for each agent (keys.load.test.ts), as Azure's second job makes its own
 * 5. phase 2 of k6, with the spike
 * 6. the database checked (verify.load.test.ts), the run's organisations
 *    made inert (cleanup.load.test.ts), as Azure's run leaves them on
 *    staging, and the API's log read (logs.ts)
 * 7. the report, numbers only, into tooling/load/reports; the stack removed.
 * It fails if any check does. `--keep` leaves the stack up to look at;
 * `--cpus 2` gives the API two CPUs instead of staging's half; `--delay-ms 2`
 * adds 2 ms to every packet the database sends, as Azure's network does
 * (4D2d P0). The report counts the database trips each request cost.
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
  DELAY_VARIABLE,
  LEAST_API_CPUS,
  type LoadOptions,
  LOAD_PROJECT,
  MOST_API_CPUS,
  MOST_DELAY_MS,
  optionsOf,
  OUT_DIR,
  POLICY_P95_MS,
  readSeeded,
  REPORTS_DIR,
} from './plan.ts';
import { type PhaseResult, type PhaseStatements, phaseFailures, renderReport } from './report.ts';

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

/**
 * One SQL statement run in the database's container as its admin, in the
 * server's `postgres` database, its rows as psql prints them unaligned. The
 * statement counter lives there, never in `agentx`: the API's schema check
 * refuses any object it doesn't know in its own database (S156, at the
 * restart). The password stays in the container's own environment: it is
 * never on this machine's command line.
 */
function asAdmin(statement: string): string {
  const psql = 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -U postgres -d postgres -At -v ON_ERROR_STOP=1 -c "$1"';
  const done = run('docker', [...COMPOSE, 'exec', '-T', 'db', 'sh', '-c', psql, 'sh', statement], { shown: false });
  if (done.code !== 0) throw new LoadRefused(`The database's statement counter answered ${String(done.code)}.`);
  return done.stdout.trim();
}

/** The app's statements (agentx_app, the API's role), one round trip each: its timers' as well as its requests'. */
const APP_STATEMENTS =
  "from pg_stat_statements s join pg_roles r on r.oid = s.userid join pg_database d on d.oid = s.dbid where r.rolname = 'agentx_app' and d.datname = 'agentx'";

/**
 * The statements sent in another's round trip (4D2d P11): with each start,
 * the connection's check and the transaction's settings; with a commit, its
 * read-back. Counted out, so the report's number stays round trips.
 */
const RIDERS =
  "coalesce(pg_catalog.sum(s.calls) filter (where s.query ~ '^(start transaction|begin)' or s.query like '% as unchanged' or s.query ~ '^select pg_catalog[.]set_config[(].*[)] as (org_id|statement_timeout)'), 0)";

/**
 * A phase with the statement counter reset before it and read after it: how
 * many statements the app ran, and its 80 most frequent kept in the run's
 * folder to see where they went: calls, the server's total and mean time in
 * ms, then the statement, so a trip's cost can be set against its work (P10).
 */
function measured(n: 1 | 2): { result: PhaseResult; statements: PhaseStatements } {
  asAdmin('select pg_stat_statements_reset()');
  const result = phase(n);
  // A counter that ran out of room dropped entries and their counts: never a number short without saying so.
  if (asAdmin('select dealloc from pg_stat_statements_info') !== '0') {
    throw new LoadRefused(`The statement counter ran out of room in phase ${String(n)}: raise pg_stat_statements.max.`);
  }
  const statements = Number(asAdmin(`select coalesce(pg_catalog.sum(s.calls), 0) - ${RIDERS} ${APP_STATEMENTS}`));
  const top = asAdmin(
    `select s.calls, pg_catalog.round(s.total_exec_time::numeric, 1), pg_catalog.round(s.mean_exec_time::numeric, 3), pg_catalog.left(pg_catalog.regexp_replace(s.query, '\\s+', ' ', 'g'), 300) ${APP_STATEMENTS} order by s.calls desc limit 80`,
  );
  writeFileSync(path.join(OUT_DIR, `statements-phase-${String(n)}.txt`), `${top}\n`);
  return { result, statements: { phase: n, statements } };
}

function phase(n: 1 | 2): PhaseResult {
  console.log(`\n== Phase ${String(n)} (k6, about two minutes)`);
  const args = [...COMPOSE, '--profile', 'load', 'run', '--rm', '--no-deps', '-e', `PHASE=${String(n)}`, 'k6'];
  // k6 answers 99 when a threshold failed: the report says which, so the run goes on.
  const { code } = run('docker', [...args, 'run', '--quiet', '/load/money-paths.k6.js']);
  if (code !== 0 && code !== 99) throw new LoadRefused(`k6 stopped in phase ${String(n)} (exit ${String(code)}).`);
  return JSON.parse(readFileSync(path.join(OUT_DIR, `k6-phase-${String(n)}.json`), 'utf8')) as PhaseResult;
}

/** The report's file for today, the API's size and any delay: a second run the same day gets its own. */
function reportFile(at: string, apiCpus: number, delayMs: number): string {
  mkdirSync(REPORTS_DIR, { recursive: true });
  const delayed = delayMs === 0 ? '' : `-${String(delayMs)}ms`;
  const name = `${at.slice(0, 10)}-local-${String(apiCpus)}cpu${delayed}`;
  for (let n = 1; ; n += 1) {
    const file = path.join(REPORTS_DIR, n === 1 ? `${name}.md` : `${name}-${String(n)}.md`);
    if (!existsSync(file)) return file;
  }
}

function main({ keep, apiCpus, delayMs }: LoadOptions): number {
  preflight();
  // Read by compose.load.yaml: each docker call below inherits them.
  process.env[API_CPUS_VARIABLE] = String(apiCpus);
  process.env[DELAY_VARIABLE] = String(delayMs);
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
    asAdmin('create extension if not exists pg_stat_statements');
    if (delayMs > 0) {
      must(`${String(delayMs)} ms added to the database's packets`, 'docker', [
        ...COMPOSE,
        '--profile',
        'delay',
        'run',
        '--rm',
        'delay',
      ]);
    }
    must('The seed', process.execPath, [VITEST, 'run', '--config', 'vitest.load.config.ts', 'seed'], {
      ...login,
      AGENTX_LOAD_RUN_ID: `local ${at}`,
    });
    const first = measured(1);
    must('The API restarted', 'docker', [...COMPOSE, 'restart', 'api']);
    must('The API back', 'docker', [...COMPOSE, 'up', '--wait', '--no-deps', 'api']);
    must('New keys', process.execPath, [VITEST, 'run', '--config', 'vitest.load.config.ts', 'keys'], login);
    const second = measured(2);
    const created = first.result.created + second.result.created;
    console.log('\n== The database after the run');
    const verified = run(process.execPath, [VITEST, 'run', '--config', 'vitest.load.config.ts', 'verify'], {
      env: { ...login, AGENTX_LOAD_CREATED: String(created) },
    });
    console.log('\n== The clean-up');
    const cleaned = run(process.execPath, [VITEST, 'run', '--config', 'vitest.load.config.ts', 'cleanup'], {
      env: login,
    });
    const log = run('docker', [...COMPOSE, 'logs', '--no-log-prefix', '--no-color', 'api'], { shown: false });
    writeFileSync(path.join(OUT_DIR, 'api.log'), log.stdout);
    const spikeOrgs = new Set(readSeeded().agents.flatMap(({ kind, orgId }) => (kind === 'capped' ? [orgId] : [])));
    const logs = summariseLogs(log.stdout, spikeOrgs);
    const failures = [
      ...phaseFailures(first.result),
      ...phaseFailures(second.result),
      ...(verified.code === 0 ? [] : ['The database checks failed: their output is above.']),
      ...(cleaned.code === 0 ? [] : ["The clean-up didn't leave every organisation inert: its output is above."]),
      ...logFailures(logs, created, POLICY_P95_MS),
    ];
    const file = reportFile(at, apiCpus, delayMs);
    const report = renderReport({
      at,
      commit,
      site: 'local',
      apiCpus,
      phases: [first.result, second.result],
      delayMs,
      statements: [first.statements, second.statements],
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
        `Run it as \`corepack pnpm load [--keep] [--cpus <n>] [--delay-ms <ms>]\`, n from ${String(LEAST_API_CPUS)} to ${String(MOST_API_CPUS)}, ms a whole number from 0 to ${String(MOST_DELAY_MS)}.`,
      );
    }
    process.exitCode = main(options);
  } catch (error) {
    if (!(error instanceof LoadRefused)) throw error;
    console.error(`\n${error.message}`);
    process.exitCode = 1;
  }
}
