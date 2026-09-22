// A3e-1b: the API checks the database's security-relevant catalogue against
// what the migrations built, at start and on every anchor-check run; the
// operator's command (B1c) checks it at its start, before it writes anything.
//
// **At start it refuses to start.** A database whose walls have been rewritten
// must not be served from, the same way A2b-2 refuses to start on a broken
// platform chain. Nothing is lost by refusing: the in-memory anchor store is
// empty at start anyway.
//
// **During a run it raises the alarm and keeps going.** Stopping a running API
// would empty that anchor store, which is exactly what someone tampering would
// want — and a restart loop would keep it empty. The alarm is the point, not
// the shutdown.
//
// Either way the line is `audit.integrity_failed` with `check: 'schema'`, which
// the SEV-1 alert rule A2c-2 installed already matches, so this needs no new
// alert. The problems name rules and objects, never a value read from the
// database, so the alarm can't carry tampered text into the log.
import { type Database, liveSchemaProblems, type SchemaProblem } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { AUTHORITY_TABLES } from './authority-tables.ts';

/**
 * The role that owns the database and everything the migrations make, fixed by
 * `db/bootstrap/roles.sql` rather than configurable. Proven against that file
 * in tooling/checks/database-roles.test.ts, so renaming the role there without
 * changing it here fails the build.
 */
export const OWNER_ROLE = 'agentx_owner';

export interface SchemaCheckOptions<Schema = unknown> {
  readonly database: Database<Schema>;
  /** The role the app connects as, from its own settings, so its real rights are the ones checked. */
  readonly appRole: string;
  readonly logger: Logger;
  /**
   * How long the whole read may take. Postgres's own limits can be got round by
   * someone who owns the database, and a connection can accept a query and
   * never answer, so the app keeps its own — as the anchor check does.
   */
  readonly deadlineMs?: number | undefined;
  /** Ends the check at once when the API is stopping. */
  readonly signal?: AbortSignal | undefined;
}

/**
 * The default deadline. These are a dozen reads of system catalogues; a server
 * that cannot answer them in this long is not one we can vouch for.
 */
const SCHEMA_CHECK_DEADLINE_MS = 10_000;

/** The check ended because the API is stopping: the API's own doing, never the database's. */
class Stopped extends Error {
  constructor() {
    super('the schema check was stopped');
    this.name = 'Stopped';
  }
}

/**
 * The work, or a rejection once the deadline passes or the run is stopped
 * (Stopped), whichever comes first.
 *
 * A signal that has **already** aborted is checked before anything is waited
 * on: `addEventListener('abort', …)` never fires on one that aborted earlier,
 * so a stop that arrived first would otherwise be missed and the check would
 * sit out its whole deadline while the API was trying to shut down.
 */
async function withinDeadline<T>(work: Promise<T>, deadlineMs: number, signal: AbortSignal | undefined): Promise<T> {
  if (signal?.aborted === true) throw new Stopped();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stop: (() => void) | undefined;
  const cut = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`the schema check did not finish within ${String(deadlineMs)} ms`));
    }, deadlineMs);
    stop = () => {
      reject(new Stopped());
    };
    signal?.addEventListener('abort', stop, { once: true });
  });
  try {
    return await Promise.race([work, cut]);
  } finally {
    clearTimeout(timer);
    if (stop !== undefined) signal?.removeEventListener('abort', stop);
  }
}

/**
 * What the check found: the problems, the reason it couldn't run, or that the
 * API stopped it. A stop is ours, never the database's doing, so it is no sign
 * of anything: raising the integrity alarm for it would page someone on a
 * routine shutdown (found by A3f-2's tests; the anchor check already tells the
 * two apart).
 */
type SchemaCheckOutcome =
  | { readonly kind: 'clean' }
  | { readonly kind: 'drift'; readonly problems: readonly SchemaProblem[] }
  | { readonly kind: 'unreadable'; readonly error: unknown }
  | { readonly kind: 'stopped' };

/**
 * Reads the live catalogue once, within its deadline. It never throws: a
 * database that refuses the read, or will not answer it, is an outcome of its
 * own — losing the right to read the catalogue, or the ability to, is itself a
 * change worth knowing about.
 *
 * **The deadline is the point, not a nicety.** Without it, a database that
 * accepts a connection and never answers would leave the scheduled run pending
 * for ever: the schedule would never re-arm, the chain checks after it would
 * never run, and no alarm would ever be raised — the very way of stopping the
 * check that anchor-check.ts's own deadline exists to defeat. Found by the
 * A3e-1b review.
 */
async function checkSchema<Schema>({
  database,
  appRole,
  deadlineMs = SCHEMA_CHECK_DEADLINE_MS,
  signal,
}: SchemaCheckOptions<Schema>): Promise<SchemaCheckOutcome> {
  try {
    // The authority tables are the product's own list, the one CI checks the migrations against (A3f-2).
    const reading = Promise.resolve().then(() =>
      liveSchemaProblems(database, { appRole, ownerRole: OWNER_ROLE, authorityTables: AUTHORITY_TABLES }),
    );
    // Handled here too, so a read that finishes after its deadline never goes unhandled.
    void reading.catch(() => undefined);
    const problems = await withinDeadline(reading, deadlineMs, signal);
    return problems.length === 0 ? { kind: 'clean' } : { kind: 'drift', problems };
  } catch (error) {
    // Only the stop itself: a read that failed on its own is the alarm, even
    // if the API began stopping just after (anchor-check.ts draws the same line).
    if (error instanceof Stopped) return { kind: 'stopped' };
    return { kind: 'unreadable', error };
  }
}

/**
 * The check at start-up. Returns whether the API may go on; a refusal for
 * drift or an unreadable catalogue has already been logged, and one because
 * the API was stopped needs no line.
 */
export async function schemaSoundAtStart<Schema>(options: SchemaCheckOptions<Schema>): Promise<boolean> {
  const outcome = await checkSchema(options);
  if (outcome.kind === 'clean') {
    options.logger.info('db.schema_checked', { problems: 0 });
    return true;
  }
  // Stopped while starting: the API isn't going on either way, and a stop is no alarm.
  if (outcome.kind === 'stopped') return false;
  if (outcome.kind === 'drift') {
    options.logger.error('audit.integrity_failed', { check: 'schema', when: 'start', problems: outcome.problems });
  } else {
    // A database that won't answer is not a database we can vouch for.
    options.logger.error('audit.integrity_failed', { check: 'schema', when: 'start', reason: 'unreadable' });
    options.logger.error('db.schema_unreadable', { err: outcome.error });
  }
  return false;
}

/**
 * The check on a scheduled run. It raises the alarm and returns; the API keeps
 * serving, for the reason in this file's header.
 */
export async function checkSchemaOnSchedule<Schema>(options: SchemaCheckOptions<Schema>): Promise<void> {
  const outcome = await checkSchema(options);
  if (outcome.kind === 'clean' || outcome.kind === 'stopped') return;
  if (outcome.kind === 'drift') {
    options.logger.error('audit.integrity_failed', { check: 'schema', when: 'running', problems: outcome.problems });
    return;
  }
  options.logger.error('audit.integrity_failed', { check: 'schema', when: 'running', reason: 'unreadable' });
  options.logger.error('db.schema_unreadable', { err: outcome.error });
}
