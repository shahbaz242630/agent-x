// The AGENTX_ variable registry and the checks a value goes through. Two
// processes read settings, each through its own loader: the app (loadConfig,
// config.ts) and the migration job (loadMigrationConfig, migration.ts). Both
// know every registered name, so a variable meant for the other job is
// refused by name rather than mistaken for a typo.
import { z } from 'zod';

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
} as const;

export type SettingName = keyof typeof SETTINGS;

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
 * which would otherwise be ignored, and settings that belong to the other
 * process, named as such so an operator sees which job they were meant for.
 * Worded without a colon after the name: the log scrubber redacts whatever
 * follows a name like `PASSWORD:`, which would hide the message.
 */
export function unknownSettings(
  env: Env,
  mine: readonly SettingName[],
  other: { readonly job: string; readonly reason: string },
): string[] {
  return Object.keys(env)
    .filter((name) => name.toUpperCase().startsWith(PREFIX) && !(mine as readonly string[]).includes(name))
    .map((name) =>
      Object.hasOwn(SETTINGS, name)
        ? `${name} belongs to ${other.job}; ${other.reason}`
        : `${name} is not a setting the app knows; check the spelling and the capitals`,
    );
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
