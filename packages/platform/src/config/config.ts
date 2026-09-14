// Deployment config (Rule Book §5, ADR-010 §5, ADR-011 §9, ADR-012 §6). Every
// setting comes from an AGENTX_ environment variable, set by reviewed
// infrastructure code, and is checked once at start-up. Anything wrong stops
// the start: a bad value, a broken rule between settings, a value below a
// safety minimum, a misspelt AGENTX_ variable, or TLS certificate checks
// turned off. Problems name the variable and the rule, never the value, so a
// secret pasted into the wrong variable can't leak through the error.
import { z } from 'zod';

import { refusedProxyEntries } from './proxies.ts';
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

/**
 * The address a local run is reached at when none is set, on the default port.
 * A local run on another port, or reached as 127.0.0.1, sets its own.
 */
const LOCAL_PUBLIC_ORIGIN = 'http://localhost:8080';

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
  /** The API's HTTP server (ADR-011 §4, §6). */
  readonly http: {
    /** The address it listens on. */
    readonly host: string;
    /** The port it listens on; 0 (any free port) only in development and test. */
    readonly port: number;
    /** SEC-WEB-01: the one origin the console and API are served from. Browser writes must come from it. */
    readonly publicOrigin: string;
    /** SEC-AV-07: the proxies whose `X-Forwarded-For` is believed, as addresses or CIDR ranges. */
    readonly trustedProxies: readonly string[];
    /** ADR-011 §4: the most requests one client address may make per minute. */
    readonly rateLimitPerMinute: number;
  };
  /** SEC-WEB-05: the only origins the app may call, as `scheme://host[:port]`. */
  readonly outbound: { readonly allowedOrigins: readonly string[] };
  /** ADR-012 §1: how long a new or changed payee waits before it can be paid. */
  readonly payees: { readonly coolingOffHours: number };
}

/** The log settings when none are set; also what the start-up logger writes with before the config is read. */
export const DEFAULT_LOG: Config['log'] = Object.freeze({ level: 'info', eventCapPerMinute: 600 });

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

function wholeNumber(limits: { min: number; max: number; unit?: string; minimumReason?: string }) {
  const unit = limits.unit === undefined ? '' : ` ${limits.unit}`;
  const reason = limits.minimumReason === undefined ? '' : ` (${limits.minimumReason})`;
  return text
    .regex(/^[0-9]+$/, { error: 'must be a whole number, written in digits only' })
    .transform(Number)
    .pipe(
      // A digits-only value that isn't a finite number overflowed, so it is too big.
      z
        .number({ error: `must be at most ${limits.max}${unit}` })
        .min(limits.min, { error: `must be at least ${limits.min}${unit}${reason}` })
        .max(limits.max, { error: `must be at most ${limits.max}${unit}` }),
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

function plainHttpProblems(name: SettingName, environment: Environment, origins: readonly string[]): string[] {
  const plainHttp = origins.some((origin) => origin.startsWith('http:'));
  return plainHttp && !LOCAL_ONLY.includes(environment)
    ? [`${name}: plain http is allowed only in ${LOCAL_ONLY.join(' and ')}; ${environment} must use https`]
    : [];
}

/** Every deployed build names its release, so each error can be traced to the code that ran. */
function releaseProblems(environment: Environment, release: string | undefined): string[] {
  return release === undefined && !LOCAL_ONLY.includes(environment)
    ? [`AGENTX_RELEASE: is required in ${environment}, so every log line and error names the build that ran`]
    : [];
}

/** A deployed app must be told its own address: it's the only origin browser writes are accepted from. */
function publicOriginProblems(environment: Environment, origin: string | undefined): string[] {
  if (origin === undefined) {
    return LOCAL_ONLY.includes(environment)
      ? []
      : [`AGENTX_PUBLIC_ORIGIN: is required in ${environment}; browser writes are accepted only from it`];
  }
  return plainHttpProblems('AGENTX_PUBLIC_ORIGIN', environment, [origin]);
}

/**
 * The app speaks plain http, so outside a local run a TLS proxy is always in
 * front. Unless the API believes that proxy's `X-Forwarded-For`, every client
 * looks like the proxy, and the rate limit becomes one limit for everyone.
 */
function trustedProxiesProblems(environment: Environment, proxies: readonly string[] | undefined): string[] {
  return proxies === undefined && !LOCAL_ONLY.includes(environment)
    ? [
        `AGENTX_TRUSTED_PROXIES: is required in ${environment}; without the TLS proxy's address, ` +
          'every client would share one rate limit',
      ]
    : [];
}

/**
 * ADR-012 §9: a client is rate-limited before it can fill the log. Every request
 * line is one event, capped per clock minute. A client's rate-limit minute starts
 * with its first request, so it can straddle two clock minutes and fit up to
 * twice its limit in one: the limit must be at most half the cap.
 */
function rateLimitProblems(rateLimitPerMinute: number, eventCapPerMinute: number): string[] {
  return rateLimitPerMinute * 2 > eventCapPerMinute
    ? [
        `AGENTX_RATE_LIMIT_PER_MINUTE: must be at most half of AGENTX_LOG_EVENT_CAP_PER_MINUTE (${eventCapPerMinute}), ` +
          "so one client's requests can't fill the request log on their own",
      ]
    : [];
}

/** Port 0 takes any free port, which suits a test; a deployed app must be where its ingress sends traffic. */
function portProblems(environment: Environment, value: number): string[] {
  return value === 0 && !LOCAL_ONLY.includes(environment)
    ? [
        `AGENTX_HTTP_PORT: 0 (any free port) is allowed only in ${LOCAL_ONLY.join(' and ')}; ${environment} must name its port`,
      ]
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
  const host = check(env, 'AGENTX_HTTP_HOST', SETTINGS.AGENTX_HTTP_HOST.schema, SETTINGS.AGENTX_HTTP_HOST.default);
  const httpPort = check(env, 'AGENTX_HTTP_PORT', SETTINGS.AGENTX_HTTP_PORT.schema, SETTINGS.AGENTX_HTTP_PORT.default);
  const origin = check(env, 'AGENTX_PUBLIC_ORIGIN', SETTINGS.AGENTX_PUBLIC_ORIGIN.schema);
  const trustedProxies = check(env, 'AGENTX_TRUSTED_PROXIES', SETTINGS.AGENTX_TRUSTED_PROXIES.schema);
  const rateLimit = check(
    env,
    'AGENTX_RATE_LIMIT_PER_MINUTE',
    SETTINGS.AGENTX_RATE_LIMIT_PER_MINUTE.schema,
    SETTINGS.AGENTX_RATE_LIMIT_PER_MINUTE.default,
  );
  const allowedOrigins = check(env, 'AGENTX_OUTBOUND_ALLOWED_ORIGINS', SETTINGS.AGENTX_OUTBOUND_ALLOWED_ORIGINS.schema);
  const coolingOffHours = check(
    env,
    'AGENTX_PAYEE_COOLING_OFF_HOURS',
    SETTINGS.AGENTX_PAYEE_COOLING_OFF_HOURS.schema,
    SETTINGS.AGENTX_PAYEE_COOLING_OFF_HOURS.default,
  );

  const settings = [
    environment,
    release,
    logLevel,
    eventCap,
    host,
    httpPort,
    origin,
    trustedProxies,
    rateLimit,
    allowedOrigins,
    coolingOffHours,
  ];
  const problems = [
    ...tlsProblems(env),
    ...unknownSettings(env),
    ...settings.flatMap((setting) => (setting.ok ? [] : [setting.problem])),
    // A rule between settings runs whenever the settings it compares are valid,
    // so one start reports it alongside any other problem.
    ...(environment.ok && allowedOrigins.ok
      ? plainHttpProblems('AGENTX_OUTBOUND_ALLOWED_ORIGINS', environment.value, allowedOrigins.value ?? [])
      : []),
    ...(environment.ok && release.ok ? releaseProblems(environment.value, release.value) : []),
    ...(environment.ok && logLevel.ok ? logLevelProblems(environment.value, logLevel.value) : []),
    ...(environment.ok && origin.ok ? publicOriginProblems(environment.value, origin.value) : []),
    ...(environment.ok && httpPort.ok ? portProblems(environment.value, httpPort.value) : []),
    ...(environment.ok && trustedProxies.ok ? trustedProxiesProblems(environment.value, trustedProxies.value) : []),
    ...(rateLimit.ok && eventCap.ok ? rateLimitProblems(rateLimit.value, eventCap.value) : []),
    ...(environment.ok ? nodeDebugProblems(environment.value, env) : []),
  ];
  if (
    !environment.ok ||
    !release.ok ||
    !logLevel.ok ||
    !eventCap.ok ||
    !host.ok ||
    !httpPort.ok ||
    !origin.ok ||
    !trustedProxies.ok ||
    !rateLimit.ok ||
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
    http: Object.freeze({
      host: host.value,
      port: httpPort.value,
      // Only development and test get here without one (publicOriginProblems).
      publicOrigin: origin.value ?? LOCAL_PUBLIC_ORIGIN,
      trustedProxies: Object.freeze(trustedProxies.value ?? []),
      rateLimitPerMinute: rateLimit.value,
    }),
    outbound: Object.freeze({ allowedOrigins: Object.freeze(allowedOrigins.value ?? []) }),
    payees: Object.freeze({ coolingOffHours: coolingOffHours.value }),
  });
}
