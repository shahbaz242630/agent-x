// The operator's command (B1c; ADR-011 §3): operator actions, run as a job
// started by a person, as the app's own role, never the owner, so the same
// tenant walls hold it as hold the API. Its one command, for now:
//
//   node apps/operator/src/main.ts create-organization --name <name>
//
// It:
// 1. guards stdout and stderr, so anything written outside the logger is cleaned (ADR-013)
// 2. reads its settings and its one key (`audit-mac`), or refuses to run and says why (SEC-AV-03)
// 3. reads what it was asked and checks the name, before it connects: a
//    refusal names each rule broken, never the name, which is never logged
// 4. connects as the app's role, and refuses one that could get round the tenant walls (ADR-005 §3)
// 5. checks the live schema, and refuses to write through walls that have been rewritten (A3e-1b)
// 6. creates the organisation, on its own audit chain and the platform's,
//    and exits 0; 1 when anything is refused or fails, with nothing changed
import { OrganizationRefused, organizationName } from '@agentx/core/modules/organizations';
import { schemaSoundAtStart } from '@agentx/core/schema-check';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { ConfigError, loadOperatorConfig, type OperatorConfig } from '@agentx/platform/config';
import { assertRuntimeRole, createDatabase, type Database, UnsafeDatabaseRole } from '@agentx/platform/db';
import { type KeyProvider, loadKeys } from '@agentx/platform/keys';
import {
  createLogger,
  createStartupLogger,
  guardOutputs,
  type Logger,
  type LoggerOptions,
  type Output,
} from '@agentx/platform/observability';

import { createOrganizationAsOperator, type OperatorTables } from './create-organization.ts';

const SERVICE = 'operator';

/** How the command's connection is named in Postgres's own views. */
const APPLICATION_NAME = 'agentx-operator';

/** The one key the command holds: the audit chains' MAC. Any other mounted with it is refused. */
const HELD_KEYS = ['audit-mac'] as const;

/** What the operator types after the command's path, the name as one argument. */
export const USAGE = 'create-organization --name <name>';

/** The parts of `process` the command uses. Tests pass a stand-in. */
export interface OperatorProcess {
  readonly stdout: Output;
  readonly stderr: Output;
  exitCode?: number | string | null | undefined;
}

export interface OperatorOptions {
  /** What follows the command's path; `process.argv`'s when not given. */
  readonly argv?: readonly string[] | undefined;
  /** The environment variables; `process.env` when not given. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  /** Where log lines go; stdout when not given. */
  readonly destination?: LoggerOptions['destination'];
}

/** What the operator asked for, once read and checked. */
interface Request {
  readonly command: 'create-organization';
  /** As it will be kept (NFC). */
  readonly name: string;
}

/**
 * What the operator asked for, or the problems. Nothing typed is repeated in
 * a problem: the name could be anywhere among the arguments, and a name is
 * never logged.
 */
function readRequest(argv: readonly string[]): Request | { readonly problems: readonly string[] } {
  const [command, flag, name, ...rest] = argv;
  if (command !== 'create-organization' || flag !== '--name' || name === undefined || rest.length > 0) {
    return { problems: [`the command is ${USAGE}, with the name quoted as one argument, and nothing else`] };
  }
  try {
    return { command, name: organizationName(name) };
  } catch (error) {
    if (error instanceof OrganizationRefused) return { problems: error.problems };
    throw error;
  }
}

/**
 * Opens a pool of one connection (the command runs one step at a time) and
 * checks the role it logged in as, or closes it and returns nothing, having
 * said why.
 */
async function connect(config: OperatorConfig, logger: Logger): Promise<Database<OperatorTables> | undefined> {
  const database = createDatabase<OperatorTables>(
    { ...config.db, maxConnections: 1, applicationName: APPLICATION_NAME },
    logger,
  );
  try {
    await assertRuntimeRole(database);
  } catch (error) {
    if (error instanceof UnsafeDatabaseRole) {
      // The problems name the role's rights and other roles, never a value.
      logger.error('operator.start_refused', { problems: error.problems });
    } else {
      logger.error('operator.database_unavailable', { err: error });
    }
    await database.destroy();
    return undefined;
  }
  return database;
}

/** Does what was asked once the settings are read: the exit code. */
async function run(
  config: OperatorConfig,
  keys: KeyProvider,
  argv: readonly string[],
  logger: Logger,
): Promise<number> {
  const request = readRequest(argv);
  if ('problems' in request) {
    logger.error('operator.refused', { problems: request.problems });
    return 1;
  }
  logger.info('operator.starting', { command: request.command, role: config.db.user, keys: keys.describe() });

  const database = await connect(config, logger);
  if (database === undefined) return 1;
  try {
    // Before anything is written: the new organisation's rows would go through the same walls.
    if (!(await schemaSoundAtStart({ database, appRole: config.db.user, logger }))) return 1;
    const created = await createOrganizationAsOperator(
      database,
      { keys, ids: uuidV7Ids, logger },
      { name: request.name, release: config.release },
    );
    logger
      .child({ orgId: created.orgId })
      .info('operator.organization_created', { orgSeq: created.orgSeq, platformSeq: created.platformSeq });
    return 0;
  } catch (error) {
    // Nothing was changed: the creation is one transaction. A chain that
    // refused the event has raised the integrity alarm already (withSignedStates).
    logger.error('operator.failed', { command: request.command, err: error });
    return 1;
  } finally {
    await database.destroy();
  }
}

/** Runs the command, sets the process's exit code and returns it: 0 once it is done. */
export async function runOperator(host: OperatorProcess, options: OperatorOptions): Promise<number> {
  guardOutputs(host);
  const { destination } = options;

  let config: OperatorConfig;
  let keys: KeyProvider;
  try {
    config = loadOperatorConfig(options.env);
    keys = loadKeys(config.keys, HELD_KEYS);
  } catch (error) {
    // A ConfigError's problems name each variable, key file and rule, never a value.
    const startup = createStartupLogger({ service: SERVICE, destination });
    startup.error(
      'operator.start_refused',
      error instanceof ConfigError ? { problems: error.problems } : { err: error },
    );
    startup.flush();
    host.exitCode = 1;
    return 1;
  }

  const logger = createLogger({ service: SERVICE, config, destination });
  const code = await run(config, keys, options.argv ?? process.argv.slice(2), logger);
  logger.flush();
  host.exitCode = code;
  return code;
}

// Only when Node runs this file itself: a real process, which in-process
// coverage can't see.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runOperator(process, {});
