// A3e-1b: the API checks the database's security-relevant catalogue against
// what the migrations built, at start and on every anchor-check run.
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
}

/** What the check found: the problems, or the reason it couldn't run. */
type SchemaCheckOutcome =
  | { readonly kind: 'clean' }
  | { readonly kind: 'drift'; readonly problems: readonly SchemaProblem[] }
  | { readonly kind: 'unreadable'; readonly error: unknown };

/**
 * Reads the live catalogue once. It never throws: a database that refuses the
 * read is an outcome of its own, because losing the right to read the catalogue
 * is itself a change worth knowing about.
 */
async function checkSchema<Schema>({ database, appRole }: SchemaCheckOptions<Schema>): Promise<SchemaCheckOutcome> {
  try {
    const problems = await liveSchemaProblems(database, { appRole, ownerRole: OWNER_ROLE });
    return problems.length === 0 ? { kind: 'clean' } : { kind: 'drift', problems };
  } catch (error) {
    return { kind: 'unreadable', error };
  }
}

/**
 * The check at start-up. Returns whether the API may go on; a refusal has
 * already been logged.
 */
export async function schemaSoundAtStart<Schema>(options: SchemaCheckOptions<Schema>): Promise<boolean> {
  const outcome = await checkSchema(options);
  if (outcome.kind === 'clean') {
    options.logger.info('db.schema_checked', { problems: 0 });
    return true;
  }
  if (outcome.kind === 'drift') {
    options.logger.error('audit.integrity_failed', { check: 'schema', when: 'start', problems: outcome.problems });
  } else {
    // A database that won't answer is not a database we can vouch for.
    options.logger.error('audit.integrity_failed', { check: 'schema', when: 'start', reason: 'unreadable' });
    options.logger.error('api.schema_unreadable', { err: outcome.error });
  }
  return false;
}

/**
 * The check on a scheduled run. It raises the alarm and returns; the API keeps
 * serving, for the reason in this file's header.
 */
export async function checkSchemaOnSchedule<Schema>(options: SchemaCheckOptions<Schema>): Promise<void> {
  const outcome = await checkSchema(options);
  if (outcome.kind === 'clean') return;
  if (outcome.kind === 'drift') {
    options.logger.error('audit.integrity_failed', { check: 'schema', when: 'running', problems: outcome.problems });
    return;
  }
  options.logger.error('audit.integrity_failed', { check: 'schema', when: 'running', reason: 'unreadable' });
  options.logger.error('api.schema_unreadable', { err: outcome.error });
}
