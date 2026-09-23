// The operator's command (B1c; ADR-011 §3): operator actions, run as a job
// started by a person, as the app's own role, never the owner, so the same
// tenant walls hold it as hold the API. Its one command, for now:
//
//   node apps/operator/src/main.ts create-organization --name <name>
//   node apps/operator/src/main.ts --request <file>
//
// The second is how its job on Azure runs it (apps.bicep): the file holds the
// same words and the new organisation's ID (`--id`) as a JSON list, written by
// the person starting the run (deploy/azure/operator.ts), since a run started
// with arguments of its own would lose its mounted files. With the ID named,
// the same request run twice makes one organisation: the second run is
// refused, changing nothing.
//
// It:
// 1. guards stdout and stderr, so anything written outside the logger is cleaned (ADR-013)
// 2. reads its settings (the name Azure gives its job's run among them, which
//    its platform event records: B1c-2b) and its one key (`audit-mac`), or
//    refuses to run and says why (SEC-AV-03)
// 3. reads what it was asked and checks the name, before it connects: a
//    refusal names each rule broken, never the name, which is never logged,
//    nor anything else a request file holds
// 4. connects as the app's role, and refuses one that could get round the tenant walls (ADR-005 §3)
// 5. checks the live schema, and refuses to write through walls that have been rewritten (A3e-1b)
// 6. creates the organisation, on its own audit chain and the platform's,
//    and exits 0; 1 when anything is refused or fails, with nothing changed,
//    unless the connection was lost as the creation committed (see run's
//    catch: the failure names the organisation's ID, to look for first)
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';

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
import { NO_REQUEST_PROBLEM, REQUEST_LIMIT_BYTES, REQUEST_USAGE, UUID_V7 } from './request.ts';

const SERVICE = 'operator';

/** How the command's connection is named in Postgres's own views. */
const APPLICATION_NAME = 'agentx-operator';

/** The one key the command holds: the audit chains' MAC. Any other mounted with it is refused. */
const HELD_KEYS = ['audit-mac'] as const;

/** What the operator types after the command's path, the name as one argument. */
export const USAGE = 'create-organization --name <name>';

/** How the job names the file its request is in. */
const REQUEST_FLAG = '--request';

/** The parts of `process` the command uses. Tests pass a stand-in. */
export interface OperatorProcess {
  readonly stdout: Output;
  readonly stderr: Output;
  exitCode?: number | string | null | undefined;
}

export interface OperatorOptions {
  /** What follows the command's path. */
  readonly argv: readonly string[];
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
  /** The new organisation's ID, which a request file names; typed, the command makes one. */
  readonly id: string | undefined;
}

/** Why a request can't be done, each rule broken. */
interface Problems {
  readonly problems: readonly string[];
}

/** One problem. */
const problem = (text: string): Problems => ({ problems: [text] });

/**
 * A request file's text: a plain file (never a pipe or a device, which could
 * hold a read open or never end), at most REQUEST_LIMIT_BYTES of UTF-8, a
 * byte-order mark allowed. Text that isn't UTF-8 is refused, not repaired: a
 * repaired name would be kept for good. What is checked is what was opened,
 * so nothing can be swapped in between; opened without waiting (O_NONBLOCK,
 * which Windows lacks and ignores here), so a pipe with no writer is refused
 * rather than waited on.
 */
function readRequestFile(file: string): { readonly text: string } | Problems {
  const descriptor = openSync(file, constants.O_RDONLY | constants.O_NONBLOCK);
  // One byte more than a request may hold, in one read: a plain file gives all it has up to that.
  const bytes = Buffer.alloc(REQUEST_LIMIT_BYTES + 1);
  let read: number;
  try {
    if (!fstatSync(descriptor).isFile()) return problem("the request file isn't a plain file");
    read = readSync(descriptor, bytes, 0, bytes.length, 0);
  } finally {
    closeSync(descriptor);
  }
  if (read > REQUEST_LIMIT_BYTES) {
    return problem(`the request file holds more than ${String(REQUEST_LIMIT_BYTES)} bytes`);
  }
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, read)) };
  } catch {
    return problem("the request file isn't UTF-8 text");
  }
}

/**
 * The words a request file holds, a JSON list of the command's arguments, or
 * the problems. A problem says what is wrong with the file, never what is in it.
 */
function requestWords(argv: readonly string[]): { readonly words: readonly string[] } | Problems {
  const [, file, ...rest] = argv;
  if (file === undefined || rest.length > 0) {
    return problem(`${REQUEST_FLAG} takes the one file that holds the request, and nothing else`);
  }
  let read: { readonly text: string } | Problems;
  try {
    read = readRequestFile(file);
  } catch (error) {
    // The system's reason alone (ENOENT, EACCES…); anything else is a bug.
    if (!(error instanceof Error && 'code' in error)) throw error;
    return problem(`the request file can't be read (${String(error.code)})`);
  }
  if ('problems' in read) return read;
  let words: unknown;
  try {
    words = JSON.parse(read.text);
  } catch {
    words = undefined;
  }
  if (!Array.isArray(words) || !words.every((word) => typeof word === 'string')) {
    return problem("the request file must hold a JSON list of the command's words");
  }
  if (words.length === 0) return problem(NO_REQUEST_PROBLEM);
  return { words };
}

/**
 * What the operator asked for, or the problems. Nothing typed is repeated in
 * a problem: the name could be anywhere among the arguments, and a name is
 * never logged. A request file also names the new organisation's ID, so a
 * request left on the job can never make a second one: run again, it meets
 * the directory's key and changes nothing.
 */
function readRequest(argv: readonly string[]): Request | Problems {
  const fromFile = argv[0] === REQUEST_FLAG;
  const asked = fromFile ? requestWords(argv) : { words: argv };
  if ('problems' in asked) return asked;
  const [command, flag, name, ...rest] = asked.words;
  const [idFlag, id, ...more] = rest;
  const shaped = command === 'create-organization' && flag === '--name' && name !== undefined;
  if (!fromFile && !(shaped && rest.length === 0)) {
    return problem(`the command is ${USAGE}, with the name quoted as one argument, and nothing else`);
  }
  if (fromFile && !(shaped && idFlag === '--id' && id !== undefined && more.length === 0)) {
    return problem(`the request file holds ${REQUEST_USAGE} as a JSON list, and nothing else`);
  }
  if (id !== undefined && !UUID_V7.test(id)) return problem("the organisation's ID must be a UUIDv7, in lower case");
  try {
    return { command: 'create-organization', name: organizationName(String(name)), id };
  } catch (error) {
    if (error instanceof OrganizationRefused) return { problems: error.problems };
    throw error;
  }
}

/**
 * Whether an error is the directory refusing an organisation it lists already:
 * its key, orgs_pkey, which Postgres names only when a row breaks it.
 */
const listedAlready = (error: unknown): boolean =>
  error instanceof Error && 'constraint' in error && error.constraint === 'orgs_pkey';

/**
 * Opens a pool of one connection, one job's share of the server's (the schema
 * check's reads queue on it; every other step runs one after another), and
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
  // The request file's, or made here, by the server: known before the work, so a failure can name it.
  const orgId = request.id ?? uuidV7Ids.next();
  const log = logger.child({ orgId });
  try {
    // Before anything is written: the new organisation's rows would go through the same walls.
    if (!(await schemaSoundAtStart({ database, appRole: config.db.user, logger }))) return 1;
    const created = await createOrganizationAsOperator(
      database,
      { keys, ids: uuidV7Ids, logger },
      { orgId, name: request.name, release: config.release, run: config.run },
    );
    log.info('operator.organization_created', { orgSeq: created.orgSeq, platformSeq: created.platformSeq });
    return 0;
  } catch (error) {
    // A request run again (one left on the job): its organisation exists, and
    // the directory's key refused the second, changing nothing.
    if (listedAlready(error)) {
      log.error('operator.done_before', { command: request.command });
      return 1;
    }
    // The creation is one transaction, so nothing was changed, unless the
    // connection was lost as it committed: then the organisation may exist.
    // The line names its ID. A request file can simply be run again; a typed
    // command makes a new ID, so look for this one on the platform chain first,
    // or the run makes a second organisation. A chain that refused the event
    // has raised the integrity alarm already (withSignedStates).
    log.error('operator.failed', { command: request.command, err: error });
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
  const code = await run(config, keys, options.argv, logger);
  logger.flush();
  host.exitCode = code;
  return code;
}

// Only when Node runs this file itself: a real process, which in-process
// coverage can't see.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runOperator(process, { argv: process.argv.slice(2) });
