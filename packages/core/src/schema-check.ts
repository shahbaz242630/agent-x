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
//
// **A server with every connection in use is a warning first (partner decision
// 3, S168).** Two copies of the API overlapping in a restart fill it, and that
// raised a false tamper alarm on run day 5. Only Postgres's own "too many
// connections" counts: anything else that stops the read is still the alarm at
// once. It becomes the alarm too if it lasts: at start past FULL_SERVER_START_MS,
// and on the schedule past the watch's limit, so filling the server can delay
// the alarm and never silence it.
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
  /** Ends the check at once when the process is stopping. */
  readonly signal?: AbortSignal | undefined;
}

/** Postgres's answer when every connection is in use (`too_many_connections`). */
const TOO_MANY_CONNECTIONS = '53300';

/** How long a start keeps asking a full server before that is the alarm: longer than two copies overlap in a restart. */
const FULL_SERVER_START_MS = 60_000;

/** How long a start waits between asks. */
const FULL_SERVER_RETRY_MS = 5_000;

/**
 * The default deadline. These are a dozen reads of system catalogues; a server
 * that cannot answer them in this long is not one we can vouch for.
 */
const SCHEMA_CHECK_DEADLINE_MS = 10_000;

/** The check ended because the process is stopping: its own doing, never the database's. */
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
 * sit out its whole deadline while the process was trying to shut down.
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
 * process stopped it. A stop is ours, never the database's doing, so it is no
 * sign of anything: raising the integrity alarm for it would page someone on
 * a routine shutdown (found by A3f-2's tests; the anchor check already tells
 * the two apart).
 */
type SchemaCheckOutcome =
  | { readonly kind: 'clean' }
  | { readonly kind: 'drift'; readonly problems: readonly SchemaProblem[] }
  | { readonly kind: 'unreadable'; readonly error: unknown }
  | { readonly kind: 'full'; readonly error: unknown }
  | { readonly kind: 'stopped' };

const fullServer = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && error.code === TOO_MANY_CONNECTIONS;

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
      liveSchemaProblems(database, {
        appRole,
        ownerRole: OWNER_ROLE,
        authorityTables: AUTHORITY_TABLES,
        statusGuardedTables: AUTHORITY_TABLES.filter((table) => table.rules !== undefined).map(({ table }) => table),
        madeOnceTables: AUTHORITY_TABLES.filter((table) => table.madeOnce === true).map(({ table }) => table),
        fixedAtCreation: Object.fromEntries(
          AUTHORITY_TABLES.flatMap(({ table, fixedAtCreation }) =>
            fixedAtCreation === undefined ? [] : [[table, fixedAtCreation]],
          ),
        ),
      }),
    );
    // Handled here too, so a read that finishes after its deadline never goes unhandled.
    void reading.catch(() => undefined);
    const problems = await withinDeadline(reading, deadlineMs, signal);
    return problems.length === 0 ? { kind: 'clean' } : { kind: 'drift', problems };
  } catch (error) {
    // Only the stop itself: a read that failed on its own is the alarm, even if
    // the process began stopping just after (the API's anchor-check.ts draws
    // the same line).
    if (error instanceof Stopped) return { kind: 'stopped' };
    return fullServer(error) ? { kind: 'full', error } : { kind: 'unreadable', error };
  }
}

/** How long a start keeps asking a full server, and how often: the defaults but in tests. */
interface FullServerWait {
  readonly limitMs?: number;
  readonly retryMs?: number;
}

/** Resolves after `ms`, or at once when the process stops: the check after it then says so. */
function pause(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

/**
 * The check at start-up. Returns whether the process may go on (the API to
 * serve, the operator's command to write); a refusal for drift or an
 * unreadable catalogue has already been logged, and one because the process
 * was stopped needs no line.
 */
export async function schemaSoundAtStart<Schema>(
  options: SchemaCheckOptions<Schema>,
  { limitMs = FULL_SERVER_START_MS, retryMs = FULL_SERVER_RETRY_MS }: FullServerWait = {},
): Promise<boolean> {
  const started = performance.now();
  let outcome = await checkSchema(options);
  while (outcome.kind === 'full' && performance.now() - started < limitMs) {
    options.logger.warn('db.schema_check_full_server', { when: 'start', err: outcome.error });
    await pause(retryMs, options.signal);
    outcome = await checkSchema(options);
  }
  if (outcome.kind === 'clean') {
    options.logger.info('db.schema_checked', { problems: 0 });
    return true;
  }
  // Stopped while starting: the process isn't going on either way, and a stop is no alarm.
  if (outcome.kind === 'stopped') return false;
  raiseSchemaAlarm(options.logger, 'start', outcome);
  return false;
}

/**
 * The check on the API's scheduled run. It raises the alarm and returns; the
 * API keeps serving, for the reason in this file's header.
 */
export async function checkSchemaOnSchedule<Schema>(
  options: SchemaCheckOptions<Schema>,
  watch: FullServerWatch,
): Promise<void> {
  const outcome = await checkSchema(options);
  if (outcome.kind === 'stopped') return;
  if (outcome.kind === 'full' && watch.withinLimit()) {
    options.logger.warn('db.schema_check_full_server', { when: 'running', err: outcome.error });
    return;
  }
  // A check that reached the catalogue, or failed for anything else, ends the full server's stretch.
  if (outcome.kind !== 'full') watch.ended();
  if (outcome.kind !== 'clean') raiseSchemaAlarm(options.logger, 'running', outcome);
}

/** How long a running check has met a full server in a row. */
export interface FullServerWatch {
  /** One more check met it: whether its stretch is still within the limit. */
  withinLimit(): boolean;
  ended(): void;
}

/** A watch whose limit counts from the first check to meet a full server. */
export function createFullServerWatch(limitMs: number, now: () => number): FullServerWatch {
  let since: number | undefined;
  return {
    withinLimit() {
      since ??= now();
      return now() - since < limitMs;
    },
    ended() {
      since = undefined;
    },
  };
}

/** The alarm for drift or an unreadable catalogue, at start-up or on the scheduled run. */
function raiseSchemaAlarm(
  logger: Logger,
  when: 'start' | 'running',
  outcome: Extract<SchemaCheckOutcome, { kind: 'drift' | 'unreadable' | 'full' }>,
): void {
  if (outcome.kind === 'drift') {
    logger.error('audit.integrity_failed', { check: 'schema', when, problems: outcome.problems });
    return;
  }
  // A database that won't answer is not a database we can vouch for.
  logger.error('audit.integrity_failed', { check: 'schema', when, reason: 'unreadable' });
  logger.error('db.schema_unreadable', { err: outcome.error });
}
