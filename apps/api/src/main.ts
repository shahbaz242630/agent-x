// The API process: start-up, shutdown and crash handling around the server.
// Run it with `node apps/api/src/main.ts`. In order, it:
// 1. guards stdout and stderr, so anything written outside the logger is cleaned (ADR-013)
// 2. reads the config and the keys, or refuses to start and says why (SEC-AV-03)
// 3. logs the config fingerprint, the keys' versions and check values among it (SEC-OPS-05)
// 4. opens the database pool as the app's role and refuses to run as one that
//    could get round the tenant walls (ADR-005 §3, APP-02)
// 5. writes the fingerprint's hash to the platform audit chain, or refuses to
//    start (SEC-OPS-05)
// 6. listens, with the console's sign-in when the config names a login service
//    (B2-3a-2), and starts the audit chains' anchor check (ADR-012 §2): the
//    platform's, and each organisation's from the directory's list (B1d-2);
//    and, each on a timer of its own, the idempotency keys' retention sweep
//    (B1e-3), the sign-in flows' sweep (B2-3a-2), the ended sessions'
//    sweep (B2-4a) and the security events' retention sweep (B2-5a); and
//    the security events' recorder, writing its counts each minute (B2-5b)
// 7. stops cleanly on SIGTERM or SIGINT: HTTP first, so every
//    request in flight is answered, then the anchor check and the sweep, then
//    the recorder's last counts, then the pool
// A crash is logged before the process exits. Every exit writes the logger's
// held-back line counts first, so none are lost.
import { type AuditTables, createAuditTrail, holdOrganisation } from '@agentx/core/modules/audit';
import { type DirectoryTables, listedOrganizations } from '@agentx/core/modules/directory';
import {
  createLoginFlows,
  createOidcClient,
  createSessions,
  createSignIn,
  createStepUpChallenges,
  type IdentityTables,
  type LoginFlows,
  membersFor,
  membershipFor,
  type Sessions,
  type StepUpChallenges,
  type SignIn,
} from '@agentx/core/modules/identity';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import { createSecurityEvents, type SecurityEventsTables } from '@agentx/core/modules/security-events';
import { checkSchemaOnSchedule, schemaSoundAtStart } from '@agentx/core/schema-check';
import { systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import { ChainBroken } from '@agentx/platform/audit-chain';
import { type Config, ConfigError, configFingerprint, loadConfig } from '@agentx/platform/config';
import {
  assertRuntimeRole,
  createDatabase,
  type Database,
  sweepExpiredKeys,
  UnsafeDatabaseRole,
} from '@agentx/platform/db';
import { type KeyProvider, loadKeys } from '@agentx/platform/keys';
import { createOutboundFetch } from '@agentx/platform/outbound';
import {
  createLogger,
  createStartupLogger,
  guardOutputs,
  type Logger,
  type LoggerOptions,
  type Output,
} from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';

import { createAnchorCheck, scheduleAnchorCheck } from './anchor-check.ts';
import { scheduleRuns } from './background.ts';
import { createRowSweep, scheduleRowSweep } from './row-sweep.ts';
import { createRetentionSweep, scheduleRetentionSweep } from './retention-sweep.ts';
import { createSecurityRecorder, type SecurityRecorder } from './security-recorder.ts';
import { buildServer } from './server.ts';
import { recordStart } from './start-record.ts';

/** Every table the API reaches, module by module. */
type ApiTables = PlatformControlsTables & DirectoryTables & AuditTables & IdentityTables & SecurityEventsTables;

const SERVICE = 'api';

/** How the API's connections are named in Postgres's own views. */
const APPLICATION_NAME = 'agentx-api';

/**
 * How long a stop may take before the process gives up and exits, within the
 * container platform's usual 30-second grace period, so the counts are still
 * written. A request that never ends would otherwise hold the stop up until the
 * platform kills the process.
 */
const STOP_DEADLINE_MS = 25_000;

/**
 * When, after a stop begins, the security events' last write must have ended
 * (B2-5b): the minute's run may hold it up by one batch, 10 seconds at most,
 * and the last write begins no batch that could end later than this, which
 * leaves the pool time to close within the stop deadline.
 */
const RECORDER_DONE_BY_MS = 20_000;

/**
 * How long the anchor check of one chain may take before it counts as not
 * completed (anchor-check.ts). Each of its statements has 10 seconds at most
 * (verifyAlone); this bounds the whole check, whatever the database does.
 */
const ANCHOR_CHECK_DEADLINE_MS = 120_000;

/**
 * The idempotency keys' retention sweep (B1e-3): at each start, then an hour
 * after each sweep ends; a batch of 1,000 keys at a time, at most 100 batches
 * an organisation a run, each within the anchor check's deadline.
 */
const SWEEP = { batch: 1_000, mostBatches: 100 } as const;
const SWEEP_EVERY_MS = 3_600_000;

/**
 * The global tables' sweeps: the sign-in flows' (B2-3a-2), the ended
 * sessions' (B2-4a) and the security events' past their retention (B2-5a),
 * each a batch of 1,000 rows at a time, at most 100 batches a run.
 */
const ROW_SWEEP = { batch: 1_000, mostBatches: 100 } as const;

/** How often the recorder writes the security events' counts whose minute has ended (B2-5b). */
const RECORD_EVERY_MS = 60_000;

/**
 * The console's sign-in (ADR-003 §5), when the config names a login service;
 * off otherwise (B2-6 switches it on for staging).
 */
function signInFrom(
  config: Config,
  database: Database<ApiTables>,
  flows: LoginFlows,
  sessions: Sessions,
  challenges: StepUpChallenges,
): SignIn | undefined {
  if (config.signIn === undefined) return undefined;
  const { issuer, clientId, clientSecret, internalOrigin } = config.signIn;
  return createSignIn({
    db: database,
    oidc: createOidcClient({
      settings: {
        issuer,
        clientId,
        clientSecret,
        redirectUri: `${config.http.publicOrigin}/v1/auth/callback`,
        internalOrigin,
      },
      fetch: createOutboundFetch(config.outbound.allowedOrigins),
      clock: systemClock,
    }),
    flows,
    sessions,
    challenges,
    ids: uuidV7Ids,
    clock: systemClock,
  });
}

/** The parts of `process` the API uses. Tests pass a stand-in. */
export interface ApiProcess {
  readonly stdout: Output;
  readonly stderr: Output;
  on(event: 'SIGTERM' | 'SIGINT', listener: (signal: NodeJS.Signals) => void): unknown;
  on(event: 'uncaughtException', listener: (error: Error, origin: NodeJS.UncaughtExceptionOrigin) => void): unknown;
  exit(code: number): void;
  exitCode?: number | string | null | undefined;
}

export interface RunOptions {
  /** The environment variables; `process.env` when not given. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  /** Where log lines go; stdout when not given. */
  readonly destination?: LoggerOptions['destination'];
}

/**
 * Stops the server once, however many signals arrive, then exits. The listeners
 * stay on: without one, Node's default for a second SIGTERM would end the
 * process at once, before the counts are written.
 */
function onStopSignals(
  host: ApiProcess,
  server: FastifyInstance,
  background: { stop(): Promise<void> },
  recorder: SecurityRecorder,
  database: Database<ApiTables>,
  logger: Logger,
): void {
  let stopping = false;
  const stop = async (signal: NodeJS.Signals): Promise<void> => {
    if (stopping) return;
    stopping = true;
    const stoppingAt = systemClock.now().getTime();
    logger.info('api.stopping', { signal });
    // Cleared below however the stop ends, so it fires only if stopping hangs.
    const deadline = setTimeout(() => {
      logger.error('api.stop_timed_out', { deadlineMs: STOP_DEADLINE_MS });
      logger.flush();
      host.exit(1);
    }, STOP_DEADLINE_MS);
    try {
      // Requests are still answered while the server stops (return503OnClosing is
      // off), so the pool closes only once the last of them, and the anchor
      // check and the sweep, have finished with it.
      await Promise.all([server.close(), background.stop()]);
      // After the last request, so none of its events is left behind.
      await recorder.flush(stoppingAt + RECORDER_DONE_BY_MS);
      await database.destroy();
      logger.info('api.stopped');
      logger.flush();
      host.exit(0);
    } catch (error) {
      logger.error('api.stop_failed', { err: error });
      logger.flush();
      host.exit(1);
    } finally {
      clearTimeout(deadline);
    }
  };
  host.on('SIGTERM', (signal) => void stop(signal));
  host.on('SIGINT', (signal) => void stop(signal));
}

/**
 * Opens the pool and checks the role it logged in as. A role that could bypass
 * the tenant walls is a wrong setting, refused like any other; a database that
 * can't be reached is reported as unavailable. Either way the pool is closed
 * and nothing is returned.
 */
async function connectDatabase(config: Config, logger: Logger): Promise<Database<ApiTables> | undefined> {
  const database = createDatabase<ApiTables>(
    {
      host: config.db.host,
      port: config.db.port,
      database: config.db.database,
      user: config.db.user,
      password: config.db.password,
      tls: config.db.tls,
      maxConnections: config.db.poolMax,
      applicationName: APPLICATION_NAME,
    },
    logger,
  );
  try {
    await assertRuntimeRole(database);
  } catch (error) {
    if (error instanceof UnsafeDatabaseRole) {
      // The problems name the role's rights and other roles, never a value.
      logger.error('api.start_refused', { problems: error.problems });
    } else {
      logger.error('api.database_unavailable', { err: error });
    }
    await database.destroy();
    return undefined;
  }
  logger.info('api.database_connected', { role: config.db.user });
  return database;
}

/**
 * Starts the API and returns its server, or returns nothing, with a failed exit
 * code, when it can't start.
 */
export async function runApi(host: ApiProcess, options: RunOptions): Promise<FastifyInstance | undefined> {
  guardOutputs(host);
  const { destination } = options;

  let config: Config;
  let keys: KeyProvider;
  try {
    config = loadConfig(options.env);
    keys = loadKeys(config.keys);
  } catch (error) {
    // A ConfigError's problems name each variable, key file and rule, never a value.
    const startup = createStartupLogger({ service: SERVICE, destination });
    startup.error('api.start_refused', error instanceof ConfigError ? { problems: error.problems } : { err: error });
    startup.flush();
    host.exitCode = 1;
    return undefined;
  }

  const logger = createLogger({ service: SERVICE, config, destination });
  host.on('uncaughtException', (error, origin) => {
    logger.error('api.crashed', { err: error, origin });
    logger.flush();
    host.exit(1);
  });
  const fingerprint = configFingerprint(config, keys.describe(), options.env);
  logger.info('api.starting', { ...fingerprint });

  const database = await connectDatabase(config, logger);
  if (database === undefined) {
    logger.flush();
    host.exitCode = 1;
    return undefined;
  }

  // Before anything is written: a database whose walls have been rewritten
  // must not be served from, and the platform chain's own tables are among
  // what is checked (A3e-1b).
  if (!(await schemaSoundAtStart({ database, appRole: config.db.user, logger }))) {
    await database.destroy();
    logger.flush();
    host.exitCode = 1;
    return undefined;
  }

  let recorded: bigint;
  try {
    recorded = await recordStart(database, keys, uuidV7Ids, {
      configHash: fingerprint.configHash,
      release: config.release,
    });
  } catch (error) {
    // The platform chain refused the event or the database did: either way no
    // one could later account for this start. A broken chain is tampering, or a
    // key version this process doesn't hold, and raises the integrity alarm.
    if (error instanceof ChainBroken) logger.error('audit.integrity_failed', { chain: 'platform', check: 'start' });
    logger.error('api.start_not_recorded', { err: error });
    await database.destroy();
    logger.flush();
    host.exitCode = 1;
    return undefined;
  }
  logger.info('api.start_recorded', { seq: recorded });

  // A failure to build the server is a bug, so it goes to the crash handler above.
  const flows = createLoginFlows({ clock: systemClock });
  const sessions = createSessions({ ids: uuidV7Ids, clock: systemClock, timeouts: config.sessions });
  const challenges = createStepUpChallenges({ ids: uuidV7Ids, clock: systemClock });
  const signIn = signInFrom(config, database, flows, sessions, challenges);
  const securityEvents = createSecurityEvents({
    ids: uuidV7Ids,
    clock: systemClock,
    retentionDays: config.securityEvents.retentionDays,
  });
  const recorder = createSecurityRecorder({
    write: (events) => securityEvents.record(database, events),
    now: () => systemClock.now().getTime(),
    logger,
  });
  const server = await buildServer({
    config,
    logger,
    ids: uuidV7Ids,
    healthChecks: [],
    signIn: signIn === undefined ? undefined : { service: signIn, sessionSeconds: config.sessions.absoluteSeconds },
    securityEvents: recorder,
    findMembership: (orgId, userId, correlationId) =>
      membershipFor(database, { keys, ids: uuidV7Ids, logger: logger.child({ correlationId }) }, orgId, userId),
    listMembers: (orgId, correlationId) =>
      membersFor(database, { keys, ids: uuidV7Ids, logger: logger.child({ correlationId }) }, orgId),
  });
  try {
    await server.listen({ host: config.http.host, port: config.http.port });
  } catch (error) {
    logger.error('api.listen_failed', { err: error });
    // Closed, so nothing it opened keeps the process running.
    await server.close();
    await database.destroy();
    logger.flush();
    host.exitCode = 1;
    return undefined;
  }
  logger.info('api.listening', { ports: server.addresses().map((address) => address.port) });
  const platform = createPlatformChain({ keys, ids: uuidV7Ids });
  const trail = createAuditTrail({ keys, ids: uuidV7Ids });
  const anchors = createAnchorCheck({
    chains: [
      {
        chain: { kind: 'platform' },
        verify: (anchor) => platform.verifyAlone(database, anchor),
      },
    ],
    organizations: {
      list: () => listedOrganizations(database),
      recorded: () => platform.createdOrganizations(database),
      verify: (orgId, anchor) => trail.verifyAlone(database, orgId, anchor),
      // The run's own logger: the hold's lines name the organisation themselves.
      hold: (orgId, failure) => holdOrganisation(database, orgId, { keys, ids: uuidV7Ids, logger }, failure),
    },
    keys,
    clock: systemClock,
    logger,
    // Three missed checks in a row are the alarm, not just a warning.
    staleAfterMs: config.audit.anchorSeconds * 3 * 1000,
    deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
  });
  const retention = createRetentionSweep({
    list: () => listedOrganizations(database),
    sweep: (orgId, most) => sweepExpiredKeys(database, orgId, most),
    logger,
    deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
    ...SWEEP,
  });
  // The schema is checked on the same schedule as the chains, so the two share
  // one timer and one pace (the retention sweep has its own, below). It runs first: a chain read through rewritten walls is
  // worth less than knowing the walls were rewritten.
  const anchorCheck = scheduleAnchorCheck(
    {
      async run(signal?: AbortSignal): Promise<void> {
        // Within its own deadline and ending at once when the API stops, so a
        // database that accepts a read and never answers cannot hold the
        // schedule open and silence every later check.
        await checkSchemaOnSchedule({ database, appRole: config.db.user, logger, signal });
        if (signal?.aborted === true) return;
        await anchors.run(signal);
      },
    },
    config.audit.anchorSeconds * 1000,
  );
  // On a timer of its own (B1e-3): a long sweep must never hold up the anchor
  // check. The two share the pool, and both start at once: each statement is
  // bounded, and a pool at its limit queues rather than refuses. Nothing orders
  // the sweep after a schema check: 0009's `retention` policy is its wall.
  const sweeping = scheduleRetentionSweep(retention, SWEEP_EVERY_MS);
  // The sign-in flows' and the ended sessions' own sweeps, each on its own
  // timer too, whether or not sign-in is on: rows left from when it was on
  // still go (B2-3a-2, B2-4a).
  const flowSweeping = scheduleRowSweep(
    createRowSweep({
      rows: 'identity.flow',
      sweep: (most) => flows.sweep(database, most),
      logger,
      deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
      ...ROW_SWEEP,
    }),
    SWEEP_EVERY_MS,
  );
  const sessionSweeping = scheduleRowSweep(
    createRowSweep({
      rows: 'identity.session',
      sweep: (most) => sessions.sweep(database, most),
      logger,
      deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
      ...ROW_SWEEP,
    }),
    SWEEP_EVERY_MS,
  );
  // Step-up challenges past their five minutes (B3-1), on a timer of its own too.
  const challengeSweeping = scheduleRowSweep(
    createRowSweep({
      rows: 'identity.step_up_challenge',
      sweep: (most) => challenges.sweep(database, most),
      logger,
      deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
      ...ROW_SWEEP,
    }),
    SWEEP_EVERY_MS,
  );
  // The security events past the retention the config names (B2-5a), on a timer of its own too.
  const eventSweeping = scheduleRowSweep(
    createRowSweep({
      rows: 'security.event',
      sweep: (most) => securityEvents.sweep(database, most),
      logger,
      deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
      ...ROW_SWEEP,
    }),
    SWEEP_EVERY_MS,
  );
  // The minute's counts, on a timer of their own (B2-5b); the last are written as the API stops.
  const recording = scheduleRuns(recorder, RECORD_EVERY_MS);
  onStopSignals(
    host,
    server,
    {
      stop: async () => {
        await Promise.all([
          anchorCheck.stop(),
          sweeping.stop(),
          flowSweeping.stop(),
          sessionSweeping.stop(),
          challengeSweeping.stop(),
          eventSweeping.stop(),
          recording.stop(),
        ]);
      },
    },
    recorder,
    database,
    logger,
  );
  return server;
}

// Only when Node runs this file itself. That's a real process, which in-process
// coverage can't see: tooling/checks/api-process.db.test.ts runs it.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runApi(process, {});
