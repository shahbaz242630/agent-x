// The API process: start-up, shutdown and crash handling around the server.
// Run it with `node apps/api/src/main.ts`. In order, it:
// 1. guards stdout and stderr, so anything written outside the logger is cleaned (ADR-013)
// 2. reads the config, or refuses to start and says why (SEC-AV-03)
// 3. logs the config fingerprint (SEC-OPS-05)
// 4. listens, and stops cleanly on SIGTERM or SIGINT
// A crash is logged before the process exits. Every exit writes the logger's
// held-back line counts first, so none are lost.
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { type Config, ConfigError, configFingerprint, loadConfig } from '@agentx/platform/config';
import {
  createLogger,
  createStartupLogger,
  guardOutputs,
  type Logger,
  type LoggerOptions,
  type Output,
} from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';

import { buildServer } from './server.ts';

const SERVICE = 'api';

/**
 * How long a stop may take before the process gives up and exits, within the
 * container platform's usual 30-second grace period, so the counts are still
 * written. A request that never ends would otherwise hold the stop up until the
 * platform kills the process.
 */
const STOP_DEADLINE_MS = 25_000;

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
function onStopSignals(host: ApiProcess, server: FastifyInstance, logger: Logger): void {
  let stopping = false;
  const stop = async (signal: NodeJS.Signals): Promise<void> => {
    if (stopping) return;
    stopping = true;
    logger.info('api.stopping', { signal });
    // Cleared below however the stop ends, so it fires only if stopping hangs.
    const deadline = setTimeout(() => {
      logger.error('api.stop_timed_out', { deadlineMs: STOP_DEADLINE_MS });
      logger.flush();
      host.exit(1);
    }, STOP_DEADLINE_MS);
    try {
      await server.close();
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
 * Starts the API and returns its server, or returns nothing, with a failed exit
 * code, when it can't start.
 */
export async function runApi(host: ApiProcess, options: RunOptions): Promise<FastifyInstance | undefined> {
  guardOutputs(host);
  const { destination } = options;

  let config: Config;
  try {
    config = loadConfig(options.env);
  } catch (error) {
    // A ConfigError's problems name each variable and rule, never a value.
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
  logger.info('api.starting', { ...configFingerprint(config, options.env) });

  // A failure to build the server is a bug, so it goes to the crash handler above.
  const server = await buildServer({ config, logger, ids: uuidV7Ids, healthChecks: [] });
  try {
    await server.listen({ host: config.http.host, port: config.http.port });
  } catch (error) {
    logger.error('api.listen_failed', { err: error });
    // Closed, so nothing it opened (a database pool, later) keeps the process running.
    await server.close();
    logger.flush();
    host.exitCode = 1;
    return undefined;
  }
  logger.info('api.listening', { ports: server.addresses().map((address) => address.port) });
  onStopSignals(host, server, logger);
  return server;
}

// Only when Node runs this file itself. That's a real process, which in-process
// coverage can't see: tooling/checks/api-process.test.ts runs it.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runApi(process, {});
