// The migration job's settings (ADR-001: migrations are applied by
// runMigrations as agentx_owner at deploy time, never by the running app).
// It shares the database's location with the app and has its own role and
// password. The app's settings are refused here by name: the job reads only
// what it needs, and a typo is still caught.
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

export interface MigrationConfig {
  readonly environment: Environment;
  readonly release: string;
  readonly log: { readonly level: LogLevel; readonly eventCapPerMinute: number };
  /** The migration role's connection (agentx_owner). */
  readonly db: {
    readonly host: string;
    readonly port: number;
    readonly database: string;
    readonly user: string;
    /** Never logged. */
    readonly password: string;
    readonly tls: DatabaseTlsMode;
  };
}

/** Reads and checks the migration job's settings, or throws a ConfigError listing every problem. */
export function loadMigrationConfig(env: Env = process.env): MigrationConfig {
  const location = checkLocation(env);
  const checks = {
    environment: setting(env, 'AGENTX_ENV'),
    release: setting(env, 'AGENTX_RELEASE'),
    logLevel: setting(env, 'AGENTX_LOG_LEVEL'),
    eventCap: setting(env, 'AGENTX_LOG_EVENT_CAP_PER_MINUTE'),
    dbHost: location.host,
    dbPort: location.port,
    dbName: location.database,
    dbTls: location.tls,
    user: setting(env, 'AGENTX_DB_MIGRATION_USER'),
    password: secretSetting(env, 'AGENTX_DB_MIGRATION_PASSWORD'),
  };
  const { environment, release, logLevel } = checks;

  const problems = [
    ...tlsProblems(env),
    ...pgVariableProblems(env),
    ...unknownSettings(env, 'migrate'),
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
  });
}
