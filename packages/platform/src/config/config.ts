// Deployment config (Rule Book §5, ADR-010 §5, ADR-011 §9, ADR-012 §6). Every
// setting comes from an AGENTX_ environment variable, set by reviewed
// infrastructure code, and is checked once at start-up. Anything wrong stops
// the start: a bad value, a broken rule between settings, a value below a
// safety minimum, a misspelt AGENTX_ variable, or TLS certificate checks
// turned off. Problems name the variable and the rule, never the value, so a
// secret pasted into the wrong variable can't leak through the error.
import { z } from 'zod';

import { tlsProblems } from './tls.ts';

const ENVIRONMENTS = ['development', 'test', 'staging', 'production'] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

/** Where nothing real is at stake, so a local stack may talk plain http and needs no release name. */
const LOCAL_ONLY: readonly Environment[] = ['development', 'test'];

/** The logging standard's levels, most to least severe. */
const LOG_LEVELS = ['error', 'warn', 'info', 'debug'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** The release name a local run uses when none is set. */
const LOCAL_RELEASE = 'local';

export interface Config {
  readonly environment: Environment;
  /** The deployed build (for example a commit hash), named on every log line and error. */
  readonly release: string;
  /** Logging standard §2 and SEC-AV-09. */
  readonly log: {
    readonly level: LogLevel;
    /** The most lines of one event written per minute; the rest are counted, not written. */
    readonly eventCapPerMinute: number;
  };
  /** SEC-WEB-05: the only origins the app may call, as `scheme://host[:port]`. */
  readonly outbound: { readonly allowedOrigins: readonly string[] };
  /** ADR-012 §1: how long a new or changed payee waits before it can be paid. */
  readonly payees: { readonly coolingOffHours: number };
}

export class ConfigError extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`Refusing to start: ${problems.length} config problem(s).\n- ${problems.join('\n- ')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

type Env = Readonly<Record<string, string | undefined>>;

const text = z
  .string({ error: 'is required' })
  .min(1, { error: 'is empty: give it a value, or remove it to use the default', abort: true });

function wholeNumber(limits: { min: number; max: number; unit: string; minimumReason: string }) {
  return text
    .regex(/^[0-9]+$/, { error: 'must be a whole number, written in digits only' })
    .transform(Number)
    .pipe(
      // A digits-only value that isn't a finite number overflowed, so it is too big.
      z
        .number({ error: `must be at most ${limits.max} ${limits.unit}` })
        .min(limits.min, { error: `must be at least ${limits.min} ${limits.unit} (${limits.minimumReason})` })
        .max(limits.max, { error: `must be at most ${limits.max} ${limits.unit}` }),
    );
}

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

/**
 * Each AGENTX_ variable the app reads. A default is written as the text an
 * operator would set, so it goes through the same checks as a set value.
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
    default: 'info',
  },
  AGENTX_LOG_EVENT_CAP_PER_MINUTE: {
    schema: wholeNumber({
      min: 10,
      max: 1_000_000,
      unit: 'lines',
      minimumReason: 'fewer would hide ordinary activity',
    }),
    default: '600',
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
} as const;

type SettingName = keyof typeof SETTINGS;

const PREFIX = 'AGENTX_';

type Checked<T> = { ok: true; value: T } | { ok: false; problem: string };

function check<T>(env: Env, name: SettingName, schema: z.ZodType<T>, fallback?: string): Checked<T> {
  const result = schema.safeParse(env[name] ?? fallback);
  return result.success
    ? { ok: true, value: result.data }
    : { ok: false, problem: `${name}: ${result.error.issues.map((issue) => issue.message).join('; ')}` };
}

/** Names in AGENTX_ style, in any case, that aren't exactly a setting: typos, which would otherwise be ignored. */
function unknownSettings(env: Env): string[] {
  return Object.keys(env)
    .filter((name) => name.toUpperCase().startsWith(PREFIX) && !Object.hasOwn(SETTINGS, name))
    .map((name) => `${name}: not a setting the app knows; check the spelling and the capitals`);
}

function plainHttpProblems(environment: Environment, allowedOrigins: readonly string[]): string[] {
  const plainHttp = allowedOrigins.some((origin) => origin.startsWith('http:'));
  return plainHttp && !LOCAL_ONLY.includes(environment)
    ? [
        `AGENTX_OUTBOUND_ALLOWED_ORIGINS: plain http is allowed only in ${LOCAL_ONLY.join(' and ')}; ` +
          `${environment} must use https`,
      ]
    : [];
}

/** Every deployed build names its release, so each error can be traced to the code that ran. */
function releaseProblems(environment: Environment, release: string | undefined): string[] {
  return release === undefined && !LOCAL_ONLY.includes(environment)
    ? [`AGENTX_RELEASE: is required in ${environment}, so every log line and error names the build that ran`]
    : [];
}

/** Logging standard §2: debug is off in production, where lines could carry more detail than needed. */
function logLevelProblems(environment: Environment, level: LogLevel): string[] {
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

function nodeDebugProblems(environment: Environment, env: Env): string[] {
  return environment === 'production'
    ? NODE_DEBUG_SWITCHES.filter((name) => env[name] !== undefined).map(
        (name) => `${name}: must be unset in production; Node would print its own debug output outside the logger`,
      )
    : [];
}

/**
 * Reads and checks the config, or throws a ConfigError listing every problem.
 * The app calls this once at start-up and exits if it throws.
 */
export function loadConfig(env: Env = process.env): Config {
  const environment = check(env, 'AGENTX_ENV', SETTINGS.AGENTX_ENV.schema);
  const release = check(env, 'AGENTX_RELEASE', SETTINGS.AGENTX_RELEASE.schema);
  const logLevel = check(env, 'AGENTX_LOG_LEVEL', SETTINGS.AGENTX_LOG_LEVEL.schema, SETTINGS.AGENTX_LOG_LEVEL.default);
  const eventCap = check(
    env,
    'AGENTX_LOG_EVENT_CAP_PER_MINUTE',
    SETTINGS.AGENTX_LOG_EVENT_CAP_PER_MINUTE.schema,
    SETTINGS.AGENTX_LOG_EVENT_CAP_PER_MINUTE.default,
  );
  const allowedOrigins = check(env, 'AGENTX_OUTBOUND_ALLOWED_ORIGINS', SETTINGS.AGENTX_OUTBOUND_ALLOWED_ORIGINS.schema);
  const coolingOffHours = check(
    env,
    'AGENTX_PAYEE_COOLING_OFF_HOURS',
    SETTINGS.AGENTX_PAYEE_COOLING_OFF_HOURS.schema,
    SETTINGS.AGENTX_PAYEE_COOLING_OFF_HOURS.default,
  );

  const settings = [environment, release, logLevel, eventCap, allowedOrigins, coolingOffHours];
  const problems = [
    ...tlsProblems(env),
    ...unknownSettings(env),
    ...settings.flatMap((setting) => (setting.ok ? [] : [setting.problem])),
    // A rule between settings runs whenever the settings it compares are valid,
    // so one start reports it alongside any other problem.
    ...(environment.ok && allowedOrigins.ok ? plainHttpProblems(environment.value, allowedOrigins.value ?? []) : []),
    ...(environment.ok && release.ok ? releaseProblems(environment.value, release.value) : []),
    ...(environment.ok && logLevel.ok ? logLevelProblems(environment.value, logLevel.value) : []),
    ...(environment.ok ? nodeDebugProblems(environment.value, env) : []),
  ];
  if (
    !environment.ok ||
    !release.ok ||
    !logLevel.ok ||
    !eventCap.ok ||
    !allowedOrigins.ok ||
    !coolingOffHours.ok ||
    problems.length > 0
  ) {
    throw new ConfigError(problems);
  }

  return Object.freeze({
    environment: environment.value,
    release: release.value ?? LOCAL_RELEASE,
    log: Object.freeze({ level: logLevel.value, eventCapPerMinute: eventCap.value }),
    outbound: Object.freeze({ allowedOrigins: Object.freeze(allowedOrigins.value ?? []) }),
    payees: Object.freeze({ coolingOffHours: coolingOffHours.value }),
  });
}
