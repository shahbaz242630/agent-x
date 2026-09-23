// The operator's command's settings (apps/operator; ADR-011 §3: operator
// actions, recorded on the platform audit chain). It connects as the app's own
// role, never the owner, so it is held to the same tenant walls as the API,
// and it holds only the keys its commands use. The API's HTTP, pool and
// anchor settings are refused here by name: the command reads only what it
// needs, and a typo is still caught. It also reads the name Azure gives each
// run of its job, which its platform event records (B1c-2b).
import type { KeySettings } from '../keys/load.ts';
import { ConfigError, type Env, type Environment, LOCAL_ONLY, type LogLevel } from './common.ts';
import { checkLocation, pgVariableProblems, secretSetting, tlsModeProblems } from './database.ts';
import type { DatabaseTlsMode } from './primitives.ts';
import {
  allOk,
  type Checked,
  failures,
  logLevelProblems,
  nodeDebugProblems,
  releaseProblems,
  setting,
  unknownSettings,
} from './settings.ts';
import { tlsProblems } from './tls.ts';

/** The release name a local run uses when none is set. */
const LOCAL_RELEASE = 'local';

/**
 * Where Azure names the run of a job a process is part of: Container Apps
 * sets it in every run (its built-in environment variables), as the job's
 * name, a hyphen and the run's own letters and digits (`my-job-iwpi4il`).
 */
const RUN_VARIABLE = 'CONTAINER_APP_JOB_EXECUTION_NAME';

/**
 * A run's name: two or more lower-case words of letters and digits joined by
 * single hyphens, the first starting with a letter. Each word after the first
 * starts at its hyphen, so the pattern has only one way to match and takes
 * time in proportion to the name, whose length is checked before it.
 */
const RUN_NAME = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$/;
const RUN_NAME_LENGTH = 64;

/** The run's name, if Azure gave one, or a problem that says what it must be, never what it was. */
function runSetting(env: Env): Checked<string | undefined> {
  const run = env[RUN_VARIABLE];
  if (run === undefined) return { ok: true, value: undefined };
  return run.length <= RUN_NAME_LENGTH && RUN_NAME.test(run)
    ? { ok: true, value: run }
    : {
        ok: false,
        problem: `${RUN_VARIABLE}: must be a job run's name as Azure gives it, at most ${String(RUN_NAME_LENGTH)} characters: two or more lower-case words of letters and digits joined by single hyphens, the first starting with a letter`,
      };
}

/**
 * Where it is deployed, the command only ever runs as its job, so every event
 * it records can name the run: the way from the event to Azure's record of
 * the run, and of who started it (ADR-005 §6). A run by hand, which only
 * development and test allow, names none.
 */
function runProblems(environment: Environment, run: string | undefined): string[] {
  return run === undefined && !LOCAL_ONLY.includes(environment)
    ? [
        `${RUN_VARIABLE}: is required in ${environment}, so the platform's event names the run that did it (Azure sets it in every run of a job)`,
      ]
    : [];
}

export interface OperatorConfig {
  readonly environment: Environment;
  readonly release: string;
  /** The job's run this is, as Azure names it, recorded in the platform's event; null for a run by hand (development and test). */
  readonly run: string | null;
  readonly log: { readonly level: LogLevel; readonly eventCapPerMinute: number };
  /** The app's own role's connection (ADR-005 §3), as the API's. */
  readonly db: {
    readonly host: string;
    readonly port: number;
    readonly database: string;
    readonly user: string;
    /** Never logged. */
    readonly password: string;
    readonly tls: DatabaseTlsMode;
  };
  /** Where the platform mounts the command's keys, and each one's current version where it isn't 1. */
  readonly keys: KeySettings;
}

/** Reads and checks the operator's command's settings, or throws a ConfigError listing every problem. */
export function loadOperatorConfig(env: Env = process.env): OperatorConfig {
  const location = checkLocation(env);
  const checks = {
    environment: setting(env, 'AGENTX_ENV'),
    release: setting(env, 'AGENTX_RELEASE'),
    run: runSetting(env),
    logLevel: setting(env, 'AGENTX_LOG_LEVEL'),
    eventCap: setting(env, 'AGENTX_LOG_EVENT_CAP_PER_MINUTE'),
    keysDirectory: setting(env, 'AGENTX_KEYS_DIR'),
    keysCurrent: setting(env, 'AGENTX_KEYS_CURRENT'),
    dbHost: location.host,
    dbPort: location.port,
    dbName: location.database,
    dbTls: location.tls,
    user: setting(env, 'AGENTX_DB_USER'),
    password: secretSetting(env, 'AGENTX_DB_PASSWORD'),
  };
  const { environment, release, run, logLevel } = checks;

  const problems = [
    ...tlsProblems(env),
    ...pgVariableProblems(env),
    ...unknownSettings(env, 'operator'),
    ...failures(Object.values(checks)),
    ...(environment.ok && release.ok ? releaseProblems(environment.value, release.value) : []),
    ...(environment.ok && run.ok ? runProblems(environment.value, run.value) : []),
    ...(environment.ok && logLevel.ok ? logLevelProblems(environment.value, logLevel.value) : []),
    ...(environment.ok && location.tls.ok ? tlsModeProblems(environment.value, location.tls.value) : []),
    ...(environment.ok ? nodeDebugProblems(environment.value, env) : []),
  ];
  // Every failed setting is already among the problems; the type guard narrows the checks to their values.
  if (!allOk(checks) || problems.length > 0) throw new ConfigError(problems);

  return Object.freeze({
    environment: checks.environment.value,
    release: checks.release.value ?? LOCAL_RELEASE,
    run: checks.run.value ?? null,
    log: Object.freeze({ level: checks.logLevel.value, eventCapPerMinute: checks.eventCap.value }),
    db: Object.freeze({
      host: checks.dbHost.value,
      port: checks.dbPort.value,
      database: checks.dbName.value,
      user: checks.user.value,
      password: checks.password.value,
      tls: checks.dbTls.value,
    }),
    keys: Object.freeze({
      directory: checks.keysDirectory.value,
      current: Object.freeze(checks.keysCurrent.value ?? {}),
    }),
  });
}
