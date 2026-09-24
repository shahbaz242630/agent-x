// The AGENTX_ variable registry and the checks a value goes through. Four
// processes read settings, each through its own loader: the app (loadConfig,
// config.ts), the migration job (loadMigrationConfig, migration.ts), the
// database set-up job (loadSetupConfig, setup.ts) and the operator's command
// (loadOperatorConfig, operator.ts). Each knows every registered name, so a
// variable meant for another job is refused by name rather than mistaken for
// a typo.
import { isAbsolute } from 'node:path';

import { z } from 'zod';

import { isKeyPurpose, type KeyPurpose, PURPOSES } from '../keys/purposes.ts';
import {
  DEFAULT_LOG,
  type Env,
  type Environment,
  ENVIRONMENTS,
  LOCAL_ONLY,
  LOG_LEVELS,
  type LogLevel,
} from './common.ts';
import { databaseHost, identifier, text, tlsMode, wholeNumber } from './primitives.ts';
import { refusedProxyEntries } from './proxies.ts';

/**
 * True for an http(s) origin written exactly as the URL standard prints it.
 * The standard allows `*` in a host name, but it would only ever match a host
 * literally called that, so it's refused rather than mistaken for a wildcard.
 */
function isCanonicalOrigin(entry: string): boolean {
  if (!URL.canParse(entry)) return false;
  const url = new URL(entry);
  return (url.protocol === 'https:' || url.protocol === 'http:') && url.origin === entry && !url.host.includes('*');
}

const originList = text.transform((raw, ctx) => {
  const entries = raw.split(',');
  const bad = entries.flatMap((entry, index) => (isCanonicalOrigin(entry) ? [] : [index + 1]));
  if (bad.length > 0) {
    ctx.addIssue({
      code: 'custom',
      message:
        `entry ${bad.join(', ')} is not an origin. Write each as scheme://host[:port]: ` +
        'http or https, lowercase, no default port, no path, no user name, comma-separated with no spaces',
    });
    return z.NEVER;
  }
  return [...new Set(entries)].sort();
});

const publicOrigin = text.refine(isCanonicalOrigin, {
  error:
    'is not an origin. Write it as scheme://host[:port]: http or https, lowercase, no default port, no path, no user name',
});

/** A host name is refused: it could resolve to an address nobody meant. */
const listenAddress = text.pipe(
  z.union([z.ipv4(), z.ipv6()], { error: 'must be an IP address, such as 127.0.0.1 or 0.0.0.0, not a host name' }),
);

const proxyList = text.transform((raw, ctx) => {
  const entries = raw.split(',');
  const bad = refusedProxyEntries(entries);
  if (bad.length > 0) {
    ctx.addIssue({
      code: 'custom',
      message:
        `entry ${bad.join(', ')} is not a proxy address. Write each as an IP address or a CIDR range ` +
        'no wider than /16 (IPv4) or /48 (IPv6), with IPv4 ranges in IPv4 form, comma-separated with no spaces',
    });
    return z.NEVER;
  }
  return [...new Set(entries)].sort();
});

/** A folder the platform mounts: an absolute path, so it can't depend on where the process was started. */
const mountedFolder = text.refine(isAbsolute, { error: 'must be an absolute path, such as /mnt/secrets' });

/** One key's current version, as `<purpose>:<version>`. */
const KEY_VERSION = /^([a-z-]+):([1-9][0-9]{0,5})$/;

function parseKeyVersion(entry: string): readonly [KeyPurpose, number] | undefined {
  const [, purpose = '', version = ''] = KEY_VERSION.exec(entry) ?? [];
  return isKeyPurpose(purpose) ? [purpose, Number(version)] : undefined;
}

const keyVersionList = text.transform((raw, ctx): Partial<Record<KeyPurpose, number>> => {
  const entries = raw.split(',').map(parseKeyVersion);
  const bad = entries.flatMap((entry, index) => (entry === undefined ? [index + 1] : []));
  if (bad.length > 0) {
    ctx.addIssue({
      code: 'custom',
      message:
        `entry ${bad.join(', ')} is not a key's current version. Write each as <purpose>:<version>, ` +
        `the purpose one of ${PURPOSES.join(', ')} and the version a whole number from 1, comma-separated with no spaces`,
    });
    return z.NEVER;
  }
  const current = new Map(entries.filter((entry) => entry !== undefined));
  if (current.size < entries.length) {
    ctx.addIssue({ code: 'custom', message: 'names a key more than once: give each key one current version' });
    return z.NEVER;
  }
  // In PURPOSES' order, so the same versions always read, and fingerprint, the same.
  return Object.fromEntries(
    PURPOSES.flatMap((purpose) => {
      const version = current.get(purpose);
      return version === undefined ? [] : [[purpose, version] as const];
    }),
  );
});

/**
 * Each AGENTX_ variable a process reads. A default is written as the text an
 * operator would set, so it goes through the same checks as a set value. A
 * password is listed so its name is known, but read by secretSetting
 * (database.ts), which also takes the `_FILE` form.
 */
const SETTINGS = {
  AGENTX_ENV: { schema: text.pipe(z.enum(ENVIRONMENTS, { error: `must be one of: ${ENVIRONMENTS.join(', ')}` })) },
  AGENTX_RELEASE: {
    schema: text
      .regex(/^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/, {
        error: 'must be 1 to 64 letters, digits, dots, dashes or underscores, starting with a letter or digit',
      })
      .optional(),
  },
  AGENTX_LOG_LEVEL: {
    schema: text.pipe(z.enum(LOG_LEVELS, { error: `must be one of: ${LOG_LEVELS.join(', ')}` })),
    default: DEFAULT_LOG.level,
  },
  AGENTX_LOG_EVENT_CAP_PER_MINUTE: {
    schema: wholeNumber({
      min: 10,
      max: 1_000_000,
      unit: 'lines',
      minimumReason: 'fewer would hide ordinary activity',
    }),
    default: String(DEFAULT_LOG.eventCapPerMinute),
  },
  AGENTX_HTTP_HOST: { schema: listenAddress, default: '127.0.0.1' },
  AGENTX_HTTP_PORT: { schema: wholeNumber({ min: 0, max: 65_535 }), default: '8080' },
  AGENTX_PUBLIC_ORIGIN: { schema: publicOrigin.optional() },
  AGENTX_TRUSTED_PROXIES: { schema: proxyList.optional() },
  AGENTX_RATE_LIMIT_PER_MINUTE: {
    schema: wholeNumber({
      min: 10,
      max: 100_000,
      unit: 'requests',
      minimumReason: 'fewer would stop ordinary use of the console',
    }),
    // Half the default log cap, so one client's request lines can't fill it (see rateLimitProblems).
    default: '300',
  },
  AGENTX_OUTBOUND_ALLOWED_ORIGINS: { schema: originList.optional() },
  // ADR-003 §5: the login service the API is the OIDC client of, all three
  // or none (sign-in is off without them). The issuer is its origin exactly,
  // as its tokens name it; the secret is read by secretSetting (database.ts).
  AGENTX_OIDC_ISSUER: { schema: publicOrigin.optional() },
  AGENTX_OIDC_CLIENT_ID: {
    schema: text.regex(/^[!-~]{1,255}$/, { error: 'must be 1 to 255 visible ASCII characters' }).optional(),
  },
  AGENTX_OIDC_CLIENT_SECRET: { schema: text },
  AGENTX_OIDC_CLIENT_SECRET_FILE: { schema: text },
  // ADR-003 §7: a console session ends after this long unused, and this long
  // after it opened however much it is used.
  AGENTX_SESSION_IDLE_MINUTES: {
    schema: wholeNumber({
      min: 5,
      max: 480,
      unit: 'minutes',
      minimumReason: 'shorter would sign people out mid-task',
    }),
    default: '30',
  },
  AGENTX_SESSION_ABSOLUTE_HOURS: {
    schema: wholeNumber({ min: 1, max: 24, unit: 'hours', minimumReason: 'shorter would sign people out mid-task' }),
    default: '12',
  },
  // ADR-005 §6, ADR-011 §7: how long a security event (a failed sign-in, a
  // rate-limit hit, with its IP address) is kept before the sweep deletes it.
  AGENTX_SECURITY_EVENT_RETENTION_DAYS: {
    schema: wholeNumber({
      min: 30,
      max: 400,
      unit: 'days',
      minimumReason: 'shorter would lose the evidence before a slow attack is noticed',
    }),
    default: '90',
  },
  AGENTX_PAYEE_COOLING_OFF_HOURS: {
    schema: wholeNumber({
      min: 24,
      // Longer than a year is almost certainly a typo, and a huge value could overflow date arithmetic.
      max: 8760,
      unit: 'hours',
      minimumReason: 'the ADR-012 safety minimum for payee changes',
    }),
    default: '24',
  },
  // ADR-012 §2: how often the app checks each audit chain against its last
  // anchor and anchors it again. A rollback made between two checks isn't
  // seen, so the window is kept short.
  AGENTX_AUDIT_ANCHOR_SECONDS: {
    schema: wholeNumber({
      min: 60,
      max: 3600,
      unit: 'seconds',
      minimumReason: 'more often only repeats the whole check of every chain',
    }),
    default: '300',
  },
  // The app's keys (ADR-011 §2): one file per key version, mounted by the
  // platform, and each key's current version where it isn't 1.
  AGENTX_KEYS_DIR: { schema: mountedFolder },
  AGENTX_KEYS_CURRENT: { schema: keyVersionList.optional() },
  // The database (ADR-002: one per environment; ADR-005 §3: the app's own role).
  AGENTX_DB_HOST: { schema: databaseHost },
  AGENTX_DB_PORT: { schema: wholeNumber({ min: 1, max: 65_535 }), default: '5432' },
  AGENTX_DB_NAME: { schema: identifier, default: 'agentx' },
  AGENTX_DB_TLS: { schema: tlsMode, default: 'verify-full' },
  AGENTX_DB_USER: { schema: identifier, default: 'agentx_app' },
  AGENTX_DB_PASSWORD: { schema: text },
  AGENTX_DB_PASSWORD_FILE: { schema: text },
  AGENTX_DB_POOL_MAX: { schema: wholeNumber({ min: 1, max: 100, unit: 'connections' }), default: '10' },
  // The migration job's own role (agentx_owner). The running app never holds it.
  AGENTX_DB_MIGRATION_USER: { schema: identifier, default: 'agentx_owner' },
  AGENTX_DB_MIGRATION_PASSWORD: { schema: text },
  AGENTX_DB_MIGRATION_PASSWORD_FILE: { schema: text },
  // The set-up job's (ADR-002): the server admin, who creates the roles and
  // databases, and the login it gives each role. Neither the app nor the
  // migration job ever holds them.
  AGENTX_DB_ADMIN_USER: { schema: identifier },
  AGENTX_DB_ADMIN_DATABASE: { schema: identifier, default: 'postgres' },
  AGENTX_DB_ADMIN_PASSWORD: { schema: text },
  AGENTX_DB_ADMIN_PASSWORD_FILE: { schema: text },
  AGENTX_DB_OWNER_PASSWORD: { schema: text },
  AGENTX_DB_OWNER_PASSWORD_FILE: { schema: text },
  AGENTX_DB_APP_PASSWORD: { schema: text },
  AGENTX_DB_APP_PASSWORD_FILE: { schema: text },
  AGENTX_DB_BACKUP_PASSWORD: { schema: text },
  AGENTX_DB_BACKUP_PASSWORD_FILE: { schema: text },
  AGENTX_DB_ZITADEL_PASSWORD: { schema: text },
  AGENTX_DB_ZITADEL_PASSWORD_FILE: { schema: text },
} as const;

export type SettingName = keyof typeof SETTINGS;

/** What every process reads: which build and environment it is, and how it logs. */
const COMMON: readonly SettingName[] = [
  'AGENTX_ENV',
  'AGENTX_RELEASE',
  'AGENTX_LOG_LEVEL',
  'AGENTX_LOG_EVENT_CAP_PER_MINUTE',
];

/** Where the database is and how the connection is protected. */
const LOCATION: readonly SettingName[] = ['AGENTX_DB_HOST', 'AGENTX_DB_PORT', 'AGENTX_DB_NAME', 'AGENTX_DB_TLS'];

export type Process = 'app' | 'migrate' | 'setup' | 'operator';

/**
 * Each process's settings, and the reason it gives when it refuses one that
 * belongs to another. Anything else in AGENTX_ style is refused.
 */
export const READERS: Readonly<Record<Process, { job: string; reads: readonly SettingName[]; reason: string }>> = {
  app: {
    job: 'the app (apps/api)',
    reads: [
      ...COMMON,
      'AGENTX_HTTP_HOST',
      'AGENTX_HTTP_PORT',
      'AGENTX_PUBLIC_ORIGIN',
      'AGENTX_TRUSTED_PROXIES',
      'AGENTX_RATE_LIMIT_PER_MINUTE',
      'AGENTX_OUTBOUND_ALLOWED_ORIGINS',
      'AGENTX_OIDC_ISSUER',
      'AGENTX_OIDC_CLIENT_ID',
      'AGENTX_OIDC_CLIENT_SECRET',
      'AGENTX_OIDC_CLIENT_SECRET_FILE',
      'AGENTX_SESSION_IDLE_MINUTES',
      'AGENTX_SESSION_ABSOLUTE_HOURS',
      'AGENTX_SECURITY_EVENT_RETENTION_DAYS',
      'AGENTX_PAYEE_COOLING_OFF_HOURS',
      'AGENTX_AUDIT_ANCHOR_SECONDS',
      'AGENTX_KEYS_DIR',
      'AGENTX_KEYS_CURRENT',
      ...LOCATION,
      'AGENTX_DB_USER',
      'AGENTX_DB_PASSWORD',
      'AGENTX_DB_PASSWORD_FILE',
      'AGENTX_DB_POOL_MAX',
    ],
    reason: "the running app holds no login but its own role's (ADR-005 §3)",
  },
  migrate: {
    job: 'the migration job (apps/migrate)',
    reads: [
      ...COMMON,
      ...LOCATION,
      'AGENTX_DB_MIGRATION_USER',
      'AGENTX_DB_MIGRATION_PASSWORD',
      'AGENTX_DB_MIGRATION_PASSWORD_FILE',
    ],
    reason: 'the migration job reads only the database and log settings',
  },
  setup: {
    job: 'the database set-up job (apps/db-setup)',
    reads: [
      ...COMMON,
      ...LOCATION,
      'AGENTX_DB_ADMIN_USER',
      'AGENTX_DB_ADMIN_DATABASE',
      'AGENTX_DB_ADMIN_PASSWORD',
      'AGENTX_DB_ADMIN_PASSWORD_FILE',
      'AGENTX_DB_OWNER_PASSWORD',
      'AGENTX_DB_OWNER_PASSWORD_FILE',
      'AGENTX_DB_APP_PASSWORD',
      'AGENTX_DB_APP_PASSWORD_FILE',
      'AGENTX_DB_BACKUP_PASSWORD',
      'AGENTX_DB_BACKUP_PASSWORD_FILE',
      'AGENTX_DB_ZITADEL_PASSWORD',
      'AGENTX_DB_ZITADEL_PASSWORD_FILE',
    ],
    reason: 'the set-up job reads only the database, log and login settings it needs',
  },
  operator: {
    job: "the operator's command (apps/operator)",
    reads: [
      ...COMMON,
      'AGENTX_KEYS_DIR',
      'AGENTX_KEYS_CURRENT',
      ...LOCATION,
      'AGENTX_DB_USER',
      'AGENTX_DB_PASSWORD',
      'AGENTX_DB_PASSWORD_FILE',
    ],
    reason: "the operator's command reads only the database, log and key settings it needs, as the app's role",
  },
};

const PREFIX = 'AGENTX_';

export type Checked<T> = { ok: true; value: T } | { ok: false; problem: string };

function check<T>(env: Env, name: SettingName, schema: z.ZodType<T>, fallback?: string): Checked<T> {
  const result = schema.safeParse(env[name] ?? fallback);
  return result.success
    ? { ok: true, value: result.data }
    : { ok: false, problem: `${name}: ${result.error.issues.map((issue) => issue.message).join('; ')}` };
}

type Value<Name extends SettingName> = z.infer<(typeof SETTINGS)[Name]['schema']>;

/** Reads a registered setting, with its default when it has one. */
export function setting<Name extends SettingName>(env: Env, name: Name): Checked<Value<Name>> {
  const entry: { readonly schema: z.ZodType; readonly default?: string } = SETTINGS[name];
  // The registry is indexed by a type parameter, which the compiler can't follow into each entry's schema type.
  return check(env, name, entry.schema, entry.default) as Checked<Value<Name>>;
}

/**
 * Names in AGENTX_ style, in any case, that this process doesn't read: typos,
 * which would otherwise be ignored, and settings that belong to another
 * process, named as such so an operator sees which job they were meant for.
 * Worded without a colon after the name: the log scrubber redacts whatever
 * follows a name like `PASSWORD:`, which would hide the message.
 */
export function unknownSettings(env: Env, reader: Process): string[] {
  const mine: readonly string[] = READERS[reader].reads;
  return Object.keys(env)
    .filter((name) => name.toUpperCase().startsWith(PREFIX) && !mine.includes(name))
    .map((name) => {
      const owners = Object.values(READERS).filter((other) => (other.reads as readonly string[]).includes(name));
      return owners.length > 0
        ? `${name} belongs to ${owners.map((owner) => owner.job).join(' and ')}; ${READERS[reader].reason}`
        : `${name} is not a setting the app knows; check the spelling and the capitals`;
    });
}

/** The problems among checked settings, in their order. */
export function failures(settings: readonly Checked<unknown>[]): string[] {
  return settings.flatMap((entry) => (entry.ok ? [] : [entry.problem]));
}

/**
 * Narrows a group of checks to their values once every one passed. The
 * failures are listed by `failures`; this only tells the compiler.
 */
export function allOk<T extends Record<string, Checked<unknown>>>(
  checks: T,
): checks is T & { [K in keyof T]: T[K] & { ok: true } } {
  return Object.values(checks).every((entry) => entry.ok);
}

/** Every deployed build names its release, so each error can be traced to the code that ran. */
export function releaseProblems(environment: Environment, release: string | undefined): string[] {
  return release === undefined && !LOCAL_ONLY.includes(environment)
    ? [`AGENTX_RELEASE: is required in ${environment}, so every log line and error names the build that ran`]
    : [];
}

/** Logging standard §2: debug is off in production, where lines could carry more detail than needed. */
export function logLevelProblems(environment: Environment, level: LogLevel): string[] {
  return environment === 'production' && level === 'debug'
    ? ['AGENTX_LOG_LEVEL: debug is off in production; use info, warn or error']
    : [];
}

/**
 * Node's own debug switches make its core modules print request details
 * (fetch prints whole URLs, queries included) straight to stderr, outside the
 * redacting logger. They're for local debugging, never production.
 */
const NODE_DEBUG_SWITCHES = ['NODE_DEBUG', 'NODE_DEBUG_NATIVE'];

export function nodeDebugProblems(environment: Environment, env: Env): string[] {
  return environment === 'production'
    ? NODE_DEBUG_SWITCHES.filter((name) => env[name] !== undefined).map(
        (name) => `${name}: must be unset in production; Node would print its own debug output outside the logger`,
      )
    : [];
}
