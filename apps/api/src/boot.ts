// What every role of the API does first (4D2e D). In order, it:
// 1. guards stdout and stderr, so anything written outside the logger is cleaned (ADR-013)
// 2. reads the config and the keys, or refuses to start and says why (SEC-AV-03)
// 3. logs the config fingerprint, the keys' versions and check values among it, and the role (SEC-OPS-05)
// 4. opens the database pool as the app's role and refuses to run as one that
//    could get round the tenant walls (ADR-005 §3, APP-02)
// 5. checks the live schema, and writes the fingerprint's hash to the platform
//    audit chain, or refuses to start (SEC-OPS-05)
// And it stops cleanly on SIGTERM or SIGINT: HTTP first where there is any, so
// every request in flight is answered, then the background work, then the
// recorder's last counts, then the pool. A crash is logged before the process
// exits. Every exit writes the logger's held-back line counts first, so none
// are lost.
import type { AgentsTables } from '@agentx/core/modules/agents';
import { type AuditTables, markHoldsWith } from '@agentx/core/modules/audit';
import { type DirectoryTables, markOrgWorkNow } from '@agentx/core/modules/directory';
import {
  createLoginFlows,
  createSessions,
  createStepUpChallenges,
  type IdentityTables,
} from '@agentx/core/modules/identity';
import type { LimitReservationsTables } from '@agentx/core/modules/limit-reservations';
import type { MandatesTables } from '@agentx/core/modules/mandates';
import type { OrganizationsTables } from '@agentx/core/modules/organizations';
import { type PlatformControlsTables, releaseJobLease, takeJobLease } from '@agentx/core/modules/platform-controls';
import type { InstructionsTables } from '@agentx/core/modules/instructions';
import type { TransactionsTables } from '@agentx/core/modules/transactions';
import type { FundingSourcesTables } from '@agentx/core/modules/funding-sources';
import { createOutbox, type NotificationsTables } from '@agentx/core/modules/notifications';
import type { FakePartnerTables } from '@agentx/core/modules/providers';
import { createProviderEvents, type ProviderEventsTables } from '@agentx/core/modules/provider-events';
import { createSecurityEvents, type SecurityEventsTables } from '@agentx/core/modules/security-events';
import type { ActivityExportTables, ActivityTables } from '@agentx/core/modules/activity';
import type { SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import type { SuppliersTables } from '@agentx/core/modules/suppliers';
import { schemaSoundAtStart, whileServerFull } from '@agentx/core/schema-check';
import { systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import { ChainBroken } from '@agentx/platform/audit-chain';
import {
  type Config,
  ConfigError,
  configFingerprint,
  gateRefOf,
  loadConfig,
  partnerName,
} from '@agentx/platform/config';
import {
  assertRuntimeRole,
  createDatabase,
  type Database,
  organisationShareOf,
  UnsafeDatabaseRole,
} from '@agentx/platform/db';
import { API_PURPOSES, type KeyProvider, loadKeys, OPERATOR_ONLY } from '@agentx/platform/keys';
import { createOutboundFetch } from '@agentx/platform/outbound';
import {
  asNoWork,
  createLogger,
  createStartupLogger,
  guardOutputs,
  type Logger,
  type LoggerOptions,
  type Output,
  workUnderWay,
} from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';

import { createLeadership, LEASE_TERM_MS, type Leadership } from './background.ts';
import { backgroundDownloadsFrom, downloadStoreOf } from './background-downloads.ts';
import { railFor } from './funding-source-links.ts';
import { directoryNamesFrom } from './kept-names.ts';
import { createJobWatch } from './job-watch.ts';
import { createSecurityRecorder, type SecurityRecorder } from './security-recorder.ts';
import { recordStart } from './start-record.ts';

/** Every table the API reaches, module by module. */
export type ApiTables = PlatformControlsTables &
  AgentsTables &
  FundingSourcesTables &
  MandatesTables &
  SpendRequestsTables &
  LimitReservationsTables &
  OrganizationsTables &
  SuppliersTables &
  FakePartnerTables &
  DirectoryTables &
  AuditTables &
  IdentityTables &
  NotificationsTables &
  SecurityEventsTables &
  ActivityTables &
  ActivityExportTables &
  InstructionsTables &
  TransactionsTables &
  ProviderEventsTables;

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

/** A process that has started: read its config, opened its pool and recorded its start. */
export interface Booted {
  readonly host: ApiProcess;
  readonly config: Config;
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly database: Database<ApiTables>;
}

/**
 * Stops the process once, however many signals arrive, then exits. The listeners
 * stay on: without one, Node's default for a second SIGTERM would end the
 * process at once, before the counts are written. `jobs` has no server, and a
 * process stopped while it starts has none yet.
 */
export function onStopSignals(
  { host, logger, database }: Booted,
  server: () => FastifyInstance | undefined,
  background: { stop(): Promise<void> },
  recorder: SecurityRecorder,
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
      await Promise.all([server()?.close(), background.stop()]);
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
      organisationShare: organisationShareOf(config.db.poolMax),
      applicationName: APPLICATION_NAME,
    },
    logger,
  );
  try {
    await whileServerFull(() => assertRuntimeRole(database), logger);
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
 * Everything every role does before its own work, or nothing, with a failed
 * exit code, when the process can't start.
 */
export async function boot(host: ApiProcess, options: RunOptions): Promise<Booted | undefined> {
  guardOutputs(host);
  const { destination } = options;

  let config: Config;
  let keys: KeyProvider;
  try {
    config = loadConfig(options.env);
    // Every key but the operator's own, which it checks the operator's events with the public half of (PL-57).
    keys = loadKeys(config.keys, API_PURPOSES, OPERATOR_ONLY);
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
    // Node runs this in the context of what threw. That is usually the culprit, but a throw from an old connection's
    // socket is in whoever opened it (logger.ts). So the line names the work, in a field of its own, and doesn't claim it.
    const workAtCrash = workUnderWay();
    asNoWork(() => {
      logger.error('api.crashed', { err: error, origin, ...(workAtCrash && { workAtCrash }) });
    });
    logger.flush();
    host.exit(1);
  });
  const fingerprint = configFingerprint(config, keys.describe(), options.env);
  logger.info('api.starting', { ...fingerprint, role: config.role });
  // ADR-014 §4: which payment partner this process talks to.
  logger.info('api.partner', { mode: partnerName(config.partner) });

  const database = await connectDatabase(config, logger);
  if (database === undefined) {
    logger.flush();
    host.exitCode = 1;
    return undefined;
  }
  // Every role sets holds: each set marks the hold history's work, in the hold's own transaction (4D2e D10).
  markHoldsWith((tx, orgId) => markOrgWorkNow(tx, orgId, 'hold_history'));

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
      gateRef: gateRefOf(config.partner),
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
  return { host, config, keys, logger, database };
}

/** The lease on the jobs, where this process has them: this process's own, by an ID of its own. */
export function leadershipOf({ config, logger, database }: Booted): Leadership | undefined {
  if (config.role === 'web') return undefined;
  const holder = uuidV7Ids.next();
  return createLeadership({
    store: {
      take: (beating) => takeJobLease(database, holder, beating, LEASE_TERM_MS / 1000),
      release: () => releaseJobLease(database, holder),
    },
    logger,
    // As the anchor check's own stale limit: what a chain may go unchecked before that is the alarm.
    notLeadingAfterMs: config.audit.anchorSeconds * 3 * 1000,
  });
}

/** What both sides of the API use: none opens a connection or starts a timer as it is made. */
export function sharedParts({ config, keys, logger, database }: Booted, leadership: Leadership | undefined) {
  const outbox = createOutbox({ ids: uuidV7Ids, clock: systemClock });
  const directory = directoryNamesFrom(config, createOutboundFetch(config.outbound.allowedOrigins));
  const securityEvents = createSecurityEvents({
    ids: uuidV7Ids,
    clock: systemClock,
    retentionDays: config.securityEvents.retentionDays,
  });
  return {
    flows: createLoginFlows({ clock: systemClock }),
    sessions: createSessions({ ids: uuidV7Ids, clock: systemClock, timeouts: config.sessions }),
    challenges: createStepUpChallenges({ ids: uuidV7Ids, clock: systemClock }),
    // Where role grants write their notices (B5-1b), and the notices' sweep reads.
    outbox,
    directory,
    securityEvents,
    // The activity log's background downloads (L5c): on where the config names a store for them.
    downloads: backgroundDownloadsFrom(downloadStoreOf(config), {
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      outbox,
      directory,
      logger,
    }),
    // Sees a job stopped from inside (PL-33 part, PL-34). The `jobs.pulse` line is the `jobs` side's to say.
    watch: createJobWatch({
      logger,
      now: () => systemClock.now().getTime(),
      pulsing: () => leadership?.leading() ?? false,
    }),
    recorder: createSecurityRecorder({
      write: (events) => securityEvents.record(database, events),
      now: () => systemClock.now().getTime(),
      logger,
    }),
    // ADR-014 §4: the fake, over its own records in this database, where the config says so; no other rail is built yet.
    rail: railFor(config.partner, { database, clock: systemClock, ids: uuidV7Ids }),
    // The partner's messages as kept (E1b): the inbox, and the refused ones as evidence, for the security events' retention.
    providerEvents: createProviderEvents({
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      retentionDays: config.securityEvents.retentionDays,
    }),
  };
}

export type SharedParts = ReturnType<typeof sharedParts>;
