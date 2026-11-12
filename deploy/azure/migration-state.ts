// What staging's database holds of an image's migrations, read without reaching
// the database (AZ6). deploy.ts holds no database credentials, and the server is
// on a private network, so the answer comes from what Azure already records: the
// migration job's runs. A run of the migration job ends Succeeded only once the
// database holds every migration its image carries (apps/migrate: it applies each
// one not yet applied, and refuses a ledger that isn't its own build's), and each
// run's record keeps the image's build (AGENTX_RELEASE) and the server it reached
// (AGENTX_DB_HOST). So the newest successful run on the server names a commit whose
// migrations the database holds; the image's own are its commit's db/migrations.
// What the image brings beyond those, the database lacks.
//
// Anything that can't be read (no such run Azure still lists, a run that names no
// build, a commit this clone lacks) is "can't be told", never "holds": deploy.ts
// then asks for the migration to run first, which applies only what is missing.
import { MIGRATION_NAME, MIGRATIONS_FOLDER } from '../../tooling/migration-order.ts';
import type { Az } from './deploy.ts';
import type { History } from './git.ts';
import { isRunOf } from './jobs.ts';
import { azureRefusal, get, record, workloadUrl } from './release.ts';

/** What the database on a server holds of an image's migrations, as migrate's runs show it. */
export type MigrationState =
  /** No migration job yet: a first deploy, whose jobs run after it. */
  | { readonly kind: 'no-job' }
  /** Every migration the image brings: `run`, migrate's newest successful run there, ran the build `ran`. */
  | { readonly kind: 'holds'; readonly run: string; readonly ran: string }
  /** The image brings `missing`, which `ran` (the build `run` ran) doesn't have. */
  | { readonly kind: 'behind'; readonly run: string; readonly ran: string; readonly missing: readonly string[] }
  /** It can't be told, for the reason given. */
  | { readonly kind: 'unknown'; readonly why: string };

/** How many of migrate's successful runs are read, newest first, for one on the server: a restore may leave older ones. */
const READS = 20;

/** A commit, as git writes it in full. */
const COMMIT = /^[0-9a-f]{40}$/;

/** One of migrate's runs as Azure lists it: its name, how it ended, and when it started. */
interface Listed {
  readonly name: string;
  readonly status: string;
  readonly started: string;
}

/** migrate's runs as Azure lists them, or what not reading them means. */
type Listing = { readonly kind: 'listed'; readonly runs: readonly Listed[] } | MigrationState;

/** migrate's runs, as Azure lists them, or why they can't be. */
function listedRuns(az: Az, subscription: string): Listing {
  const url = workloadUrl(subscription, 'migrate').replace('?api-version=', '/executions?api-version=');
  const done = az.run(['rest', '--method', 'get', '--url', url, '--output', 'json']);
  if (done.status !== 0) {
    if (done.stderr.includes('ResourceNotFound')) return { kind: 'no-job' };
    return { kind: 'unknown', why: `Azure didn't answer the read of migrate's runs (${azureRefusal(done.stderr)})` };
  }
  let value: unknown;
  try {
    value = record(JSON.parse(done.stdout)).value;
  } catch {
    value = undefined;
  }
  if (!Array.isArray(value)) return { kind: 'unknown', why: "Azure's list of migrate's runs wasn't a list" };
  const runs = value.map((entry) => {
    const found = record(entry);
    const properties = record(found.properties);
    const started = properties.startTime;
    return {
      name: String(found.name),
      status: String(properties.status),
      started: typeof started === 'string' ? started : '',
    };
  });
  return { kind: 'listed', runs };
}

/** A setting's value in the open in a run's one migrate container, or nothing. */
function settingIn(env: readonly unknown[], name: string): string {
  const found = env.map(record).find((setting) => setting.name === name);
  return typeof found?.value === 'string' ? found.value : '';
}

/** The server a run reached and the build it ran, from Azure's record of the run. */
function ranOn(az: Az, subscription: string, name: string): { readonly host: string; readonly ran: string } {
  const url = workloadUrl(subscription, 'migrate').replace('?api-version=', `/executions/${name}?api-version=`);
  const containers = record(record(get(az, url, name).properties).template).containers;
  const container = (Array.isArray(containers) ? containers : []).map(record).find((each) => each.name === 'migrate');
  const env = Array.isArray(container?.env) ? container.env : [];
  return { host: settingIn(env, 'AGENTX_DB_HOST'), ran: settingIn(env, 'AGENTX_RELEASE') };
}

/** The migration files at a commit, by name. */
const migrationsAt = (history: History, commit: string): readonly string[] =>
  history.filesIn(commit, MIGRATIONS_FOLDER).filter((name) => MIGRATION_NAME.test(name));

/**
 * What the database on `host` holds of the migrations `release` brings: from migrate's newest successful run on that
 * host (of the newest READS successful runs), and the two commits' db/migrations.
 */
export function migrationState(
  az: Az,
  history: History,
  subscription: string,
  host: string,
  release: string,
): MigrationState {
  const listing = listedRuns(az, subscription);
  if (listing.kind !== 'listed') return listing;
  const succeeded = listing.runs
    .filter((run) => run.status === 'Succeeded' && isRunOf('migrate', run.name))
    .sort((one, other) => other.started.localeCompare(one.started))
    .slice(0, READS);
  let found: { readonly run: string; readonly ran: string } | undefined;
  try {
    for (const { name } of succeeded) {
      const read = ranOn(az, subscription, name);
      if (read.host === host) {
        found = { run: name, ran: read.ran };
        break;
      }
    }
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    return { kind: 'unknown', why: error.message.replace(/\.$/, '') };
  }
  if (found === undefined) {
    return { kind: 'unknown', why: `Azure lists no successful run of migrate on ${host}` };
  }
  const { run, ran } = found;
  if (!COMMIT.test(ran)) return { kind: 'unknown', why: `migrate's run ${run} names no build it ran` };
  let held: ReadonlySet<string>;
  let brought: readonly string[];
  try {
    held = new Set(migrationsAt(history, ran));
    brought = migrationsAt(history, release);
  } catch {
    return {
      kind: 'unknown',
      why: `this folder's git can't list the migrations of ${ran}, which migrate's run ${run} ran (git fetch origin, then run apps again)`,
    };
  }
  const missing = brought.filter((name) => !held.has(name));
  return missing.length === 0 ? { kind: 'holds', run, ran } : { kind: 'behind', run, ran, missing };
}
