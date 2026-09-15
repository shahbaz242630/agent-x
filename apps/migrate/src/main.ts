// The migration job: applies db/migrations as the migration role, then exits.
// Run it with `node apps/migrate/src/main.ts` at deploy time, before the API
// starts (ADR-001: migrations never run inside the app). It:
// 1. guards stdout and stderr, so anything written outside the logger is cleaned (ADR-013)
// 2. reads its settings, or refuses to run and says why (SEC-AV-03)
// 3. runs every migration not yet applied, each in its own transaction, and exits
//    0 when the database is current, 1 when it isn't
import { fileURLToPath } from 'node:url';

import { ConfigError, loadMigrationConfig, type MigrationConfig } from '@agentx/platform/config';
import { MigrationFailed, MigrationNotAtomic, MigrationRefused, runMigrations } from '@agentx/platform/db';
import {
  createLogger,
  createStartupLogger,
  guardOutputs,
  type Logger,
  type LoggerOptions,
  type Output,
} from '@agentx/platform/observability';

const SERVICE = 'migrate';

/** How the job's connection is named in Postgres's own views. */
const APPLICATION_NAME = 'agentx-migrate';

/** The migration files: next to the apps in the repository, and in the image. */
const MIGRATIONS = fileURLToPath(new URL('../../../db/migrations', import.meta.url));

/** The parts of `process` the job uses. Tests pass a stand-in. */
export interface MigrateProcess {
  readonly stdout: Output;
  readonly stderr: Output;
  exitCode?: number | string | null | undefined;
}

export interface MigrateOptions {
  /** The environment variables; `process.env` when not given. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  /** Where log lines go; stdout when not given. */
  readonly destination?: LoggerOptions['destination'];
  /** The folder of migration files; db/migrations when not given. */
  readonly directory?: string | undefined;
}

/** What went wrong, in the fields the operator needs: names, never file contents or values. */
function failure(error: unknown): Record<string, unknown> {
  if (error instanceof MigrationRefused) return { problems: error.problems };
  if (error instanceof MigrationFailed || error instanceof MigrationNotAtomic) {
    return { migration: error.migration, err: error };
  }
  return { err: error };
}

async function migrate(config: MigrationConfig, directory: string, logger: Logger): Promise<number> {
  logger.info('migrate.starting', { role: config.db.user });
  try {
    const applied = await runMigrations({
      connection: { ...config.db, applicationName: APPLICATION_NAME },
      directory,
      logger,
    });
    logger.info('migrate.done', { applied });
    return 0;
  } catch (error) {
    logger.error('migrate.failed', failure(error));
    return 1;
  }
}

/** Runs the job, sets the process's exit code and returns it: 0 when the database is current. */
export async function runMigrate(host: MigrateProcess, options: MigrateOptions): Promise<number> {
  guardOutputs(host);
  const { destination } = options;

  let config: MigrationConfig;
  try {
    config = loadMigrationConfig(options.env);
  } catch (error) {
    // A ConfigError's problems name each variable and rule, never a value.
    const startup = createStartupLogger({ service: SERVICE, destination });
    startup.error(
      'migrate.start_refused',
      error instanceof ConfigError ? { problems: error.problems } : { err: error },
    );
    startup.flush();
    host.exitCode = 1;
    return 1;
  }

  const logger = createLogger({ service: SERVICE, config, destination });
  const code = await migrate(config, options.directory ?? MIGRATIONS, logger);
  logger.flush();
  host.exitCode = code;
  return code;
}

// Only when Node runs this file itself: a real process, which in-process
// coverage can't see. The compose stack's end-to-end job runs it.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runMigrate(process, {});
