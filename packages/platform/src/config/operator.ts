// The operator's command's settings (apps/operator; ADR-011 §3: operator
// actions, recorded on the platform audit chain). It connects as the app's own
// role, never the owner, so it is held to the same tenant walls as the API,
// and it holds only the keys its commands use. The API's HTTP, pool and
// anchor settings are refused here by name: the command reads only what it
// needs, and a typo is still caught.
import type { KeySettings } from '../keys/load.ts';
import { ConfigError, type Env, type Environment, type LogLevel } from './common.ts';
import { checkLocation, pgVariableProblems, secretSetting, tlsModeProblems } from './database.ts';
import type { DatabaseTlsMode } from './primitives.ts';
import {
  allOk,
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

export interface OperatorConfig {
  readonly environment: Environment;
  readonly release: string;
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
  const { environment, release, logLevel } = checks;

  const problems = [
    ...tlsProblems(env),
    ...pgVariableProblems(env),
    ...unknownSettings(env, 'operator'),
    ...failures(Object.values(checks)),
    ...(environment.ok && release.ok ? releaseProblems(environment.value, release.value) : []),
    ...(environment.ok && logLevel.ok ? logLevelProblems(environment.value, logLevel.value) : []),
    ...(environment.ok && location.tls.ok ? tlsModeProblems(environment.value, location.tls.value) : []),
    ...(environment.ok ? nodeDebugProblems(environment.value, env) : []),
  ];
  // Every failed setting is already among the problems; the type guard narrows the checks to their values.
  if (!allOk(checks) || problems.length > 0) throw new ConfigError(problems);

  return Object.freeze({
    environment: checks.environment.value,
    release: checks.release.value ?? LOCAL_RELEASE,
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
