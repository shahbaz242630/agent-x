// The database set-up job's settings (ADR-002: the server admin creates the
// roles and databases, and gives each role its login from the secret store).
// It connects as the admin, to the admin's own database first. Only this job
// holds the admin's login and every role's; the app and the migration job
// refuse these settings by name, and this job refuses theirs.
import { ConfigError, type Env, type Environment, type LogLevel } from './common.ts';
import { checkLocation, pgVariableProblems, type SecretName, secretSetting, tlsModeProblems } from './database.ts';
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

/** The roles whose logins the job sets: db/bootstrap's three, and the login service's. */
export type SetupRole = 'owner' | 'app' | 'backup' | 'zitadel';

const LOGIN_SETTINGS: Readonly<Record<SetupRole, SecretName>> = {
  owner: 'AGENTX_DB_OWNER_PASSWORD',
  app: 'AGENTX_DB_APP_PASSWORD',
  backup: 'AGENTX_DB_BACKUP_PASSWORD',
  zitadel: 'AGENTX_DB_ZITADEL_PASSWORD',
};

/**
 * A role's login is generated, never chosen by a person: long enough that it
 * can't be guessed, in the characters a SCRAM verifier takes as they are
 * (db/scram.ts). The admin's login is Azure's to judge, so it only has to be set.
 */
const MINIMUM_LOGIN_LENGTH = 24;
const PLAIN_LOGIN = /^[\x21-\x7e]+$/;

export interface SetupConfig {
  readonly environment: Environment;
  readonly release: string;
  readonly log: { readonly level: LogLevel; readonly eventCapPerMinute: number };
  /** Where the server is, and the app's database on it. */
  readonly db: {
    readonly host: string;
    readonly port: number;
    readonly tls: DatabaseTlsMode;
    /** The app's database the job creates (agentx). */
    readonly database: string;
  };
  /** The server admin: on Azure the break-glass login (ADR-002), locally the superuser. */
  readonly admin: {
    readonly user: string;
    /** Never logged. */
    readonly password: string;
    /** The database the admin connects to first, which exists on every server. */
    readonly database: string;
  };
  /** Each role's login. Never logged; sent to the server only as a SCRAM verifier. */
  readonly logins: Readonly<Record<SetupRole, string>>;
}

/** Worded without a colon after the name: the log scrubber redacts whatever follows `PASSWORD:`. */
function loginProblems(name: SecretName, login: Checked<string>): string[] {
  return login.ok && (login.value.length < MINIMUM_LOGIN_LENGTH || !PLAIN_LOGIN.test(login.value))
    ? [
        `${name} must be at least ${String(MINIMUM_LOGIN_LENGTH)} characters of printable ASCII with no spaces, ` +
          'so it is out of reach of guessing and can be stored as a SCRAM verifier',
      ]
    : [];
}

/** The roles the job creates, which can't be the admin that creates them. */
const SET_UP_ROLES: readonly string[] = ['agentx_owner', 'agentx_app', 'agentx_backup', 'zitadel'];

function adminProblems(admin: Checked<string>): string[] {
  return admin.ok && SET_UP_ROLES.includes(admin.value)
    ? ['AGENTX_DB_ADMIN_USER: must be the server admin, not one of the roles the set-up job creates']
    : [];
}

/** Databases the app's can never be: Postgres's own, and the login service's (server-setup.ts refuses them too). */
const RESERVED_DATABASES: readonly string[] = ['postgres', 'template0', 'template1', 'zitadel'];

function appDatabaseProblems(database: Checked<string>, adminDatabase: Checked<string>): string[] {
  const reserved = [...RESERVED_DATABASES, ...(adminDatabase.ok ? [adminDatabase.value] : [])];
  return database.ok && reserved.includes(database.value)
    ? [
        "AGENTX_DB_NAME: must be the app's own database, not Postgres's own (postgres, template0, template1), the login service's (zitadel) or the admin's (AGENTX_DB_ADMIN_DATABASE)",
      ]
    : [];
}

/** One login opening two roles would join what ADR-005 §3 keeps apart. */
function reusedLogins(logins: readonly (readonly [SecretName, Checked<string>])[]): string[] {
  const problems: string[] = [];
  logins.forEach(([name, login], index) => {
    for (const [otherName, other] of logins.slice(index + 1)) {
      if (login.ok && other.ok && login.value === other.value) {
        problems.push(`${name} and ${otherName} hold the same login; every role needs its own`);
      }
    }
  });
  return problems;
}

/** Reads and checks the set-up job's settings, or throws a ConfigError listing every problem. */
export function loadSetupConfig(env: Env = process.env): SetupConfig {
  const location = checkLocation(env);
  const logins = {
    owner: secretSetting(env, LOGIN_SETTINGS.owner),
    app: secretSetting(env, LOGIN_SETTINGS.app),
    backup: secretSetting(env, LOGIN_SETTINGS.backup),
    zitadel: secretSetting(env, LOGIN_SETTINGS.zitadel),
  };
  const checks = {
    environment: setting(env, 'AGENTX_ENV'),
    release: setting(env, 'AGENTX_RELEASE'),
    logLevel: setting(env, 'AGENTX_LOG_LEVEL'),
    eventCap: setting(env, 'AGENTX_LOG_EVENT_CAP_PER_MINUTE'),
    dbHost: location.host,
    dbPort: location.port,
    dbName: location.database,
    dbTls: location.tls,
    adminUser: setting(env, 'AGENTX_DB_ADMIN_USER'),
    adminDatabase: setting(env, 'AGENTX_DB_ADMIN_DATABASE'),
    adminPassword: secretSetting(env, 'AGENTX_DB_ADMIN_PASSWORD'),
    ...logins,
  };
  const { environment, release, logLevel } = checks;
  const named = (Object.keys(LOGIN_SETTINGS) as SetupRole[]).map(
    (role) => [LOGIN_SETTINGS[role], logins[role]] as const,
  );

  const problems = [
    ...tlsProblems(env),
    ...pgVariableProblems(env),
    ...unknownSettings(env, 'setup'),
    ...failures(Object.values(checks)),
    ...adminProblems(checks.adminUser),
    ...appDatabaseProblems(checks.dbName, checks.adminDatabase),
    ...named.flatMap(([name, login]) => loginProblems(name, login)),
    ...reusedLogins([['AGENTX_DB_ADMIN_PASSWORD', checks.adminPassword], ...named]),
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
      tls: checks.dbTls.value,
      database: checks.dbName.value,
    }),
    admin: Object.freeze({
      user: checks.adminUser.value,
      password: checks.adminPassword.value,
      database: checks.adminDatabase.value,
    }),
    logins: Object.freeze({
      owner: checks.owner.value,
      app: checks.app.value,
      backup: checks.backup.value,
      zitadel: checks.zitadel.value,
    }),
  });
}
