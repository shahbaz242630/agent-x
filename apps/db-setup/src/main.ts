// The database set-up job: the server's roles and databases from db/bootstrap,
// each role's login set, then the result checked (ADR-002; Database.md
// "Setting up a new server"). It runs as the server admin, before the
// migration job, whenever a server is new or a login is rotated: on the
// compose stack as its `db-setup` service, on Azure as a job started by hand
// (its admin login raises the privileged-login alert, which is expected and
// is the job's recorded reason). Run it with `node apps/db-setup/src/main.ts`.
// It:
// 1. guards stdout and stderr, so anything written outside the logger is cleaned (ADR-013)
// 2. reads its settings, or refuses to run and says why (SEC-AV-03)
// 3. sets up the server, and exits 0 when it matches db/bootstrap, 1 when it doesn't
import { fileURLToPath } from 'node:url';

import { ConfigError, loadSetupConfig, type SetupConfig } from '@agentx/platform/config';
import { ServerSetupRefused, setUpServer } from '@agentx/platform/db';
import {
  createLogger,
  createStartupLogger,
  guardOutputs,
  type Logger,
  type LoggerOptions,
  type Output,
} from '@agentx/platform/observability';

const SERVICE = 'db-setup';

/** The bootstrap files: next to the apps in the repository, and in the image. */
const BOOTSTRAP = fileURLToPath(new URL('../../../db/bootstrap', import.meta.url));

/** The parts of `process` the job uses. Tests pass a stand-in. */
export interface SetupProcess {
  readonly stdout: Output;
  readonly stderr: Output;
  exitCode?: number | string | null | undefined;
}

export interface SetupOptions {
  /** The environment variables; `process.env` when not given. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  /** Where log lines go; stdout when not given. */
  readonly destination?: LoggerOptions['destination'];
  /** The folder of bootstrap files; db/bootstrap when not given. */
  readonly directory?: string | undefined;
}

/** What went wrong, in the fields the operator needs: names, never logins. */
export function failure(error: unknown): Record<string, unknown> {
  return error instanceof ServerSetupRefused ? { problems: error.problems } : { err: error };
}

async function setUp(config: SetupConfig, directory: string, logger: Logger): Promise<number> {
  logger.info('db_setup.starting', { admin: config.admin.user, database: config.db.database });
  try {
    const outcome = await setUpServer({
      admin: {
        host: config.db.host,
        port: config.db.port,
        database: config.admin.database,
        user: config.admin.user,
        password: config.admin.password,
        tls: config.db.tls,
      },
      database: config.db.database,
      logins: config.logins,
      directory,
      logger,
    });
    logger.info('db_setup.done', { ...outcome });
    return 0;
  } catch (error) {
    logger.error('db_setup.failed', failure(error));
    return 1;
  }
}

/** Runs the job, sets the process's exit code and returns it: 0 when the server matches db/bootstrap. */
export async function runDbSetup(host: SetupProcess, options: SetupOptions): Promise<number> {
  guardOutputs(host);
  const { destination } = options;

  let config: SetupConfig;
  try {
    config = loadSetupConfig(options.env);
  } catch (error) {
    // A ConfigError's problems name each variable and rule, never a value.
    const startup = createStartupLogger({ service: SERVICE, destination });
    startup.error(
      'db_setup.start_refused',
      error instanceof ConfigError ? { problems: error.problems } : { err: error },
    );
    startup.flush();
    host.exitCode = 1;
    return 1;
  }

  const logger = createLogger({ service: SERVICE, config, destination });
  const code = await setUp(config, options.directory ?? BOOTSTRAP, logger);
  logger.flush();
  host.exitCode = code;
  return code;
}

// Only when Node runs this file itself: a real process, which in-process
// coverage can't see. The compose stack's end-to-end job runs it.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runDbSetup(process, {});
