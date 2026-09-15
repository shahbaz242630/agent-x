// The app's deployment config (Rule Book §5, ADR-010 §5, ADR-011 §9, ADR-012
// §6). Every setting comes from an AGENTX_ environment variable, set by
// reviewed infrastructure code, and is checked once at start-up. Anything
// wrong stops the start: a bad value, a broken rule between settings, a value
// below a safety minimum, a misspelt AGENTX_ variable, a setting that belongs
// to another job, a PG* variable, or TLS certificate checks turned off.
// Problems name the variable and the rule, never the value, so a secret pasted
// into the wrong variable can't leak through the error.
import { ConfigError, type Env, type Environment, LOCAL_ONLY, type LogLevel } from './common.ts';
import { checkLocation, pgVariableProblems, secretSetting, tlsModeProblems } from './database.ts';
import type { DatabaseTlsMode } from './primitives.ts';
import {
  allOk,
  failures,
  logLevelProblems,
  nodeDebugProblems,
  releaseProblems,
  setting,
  type SettingName,
  unknownSettings,
} from './settings.ts';
import { tlsProblems } from './tls.ts';

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
  /** The app's database connection (ADR-002), as the app's own role (ADR-005 §3). */
  readonly db: {
    readonly host: string;
    readonly port: number;
    readonly database: string;
    readonly user: string;
    /** Never logged, never in the fingerprint. */
    readonly password: string;
    readonly tls: DatabaseTlsMode;
    /** The most connections the pool keeps open. */
    readonly poolMax: number;
  };
  /** SEC-WEB-05: the only origins the app may call, as `scheme://host[:port]`. */
  readonly outbound: { readonly allowedOrigins: readonly string[] };
  /** ADR-012 §1: how long a new or changed payee waits before it can be paid. */
  readonly payees: { readonly coolingOffHours: number };
}

function plainHttpProblems(name: SettingName, environment: Environment, origins: readonly string[]): string[] {
  const plainHttp = origins.some((origin) => origin.startsWith('http:'));
  return plainHttp && !LOCAL_ONLY.includes(environment)
    ? [`${name}: plain http is allowed only in ${LOCAL_ONLY.join(' and ')}; ${environment} must use https`]
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

/**
 * Reads and checks the config, or throws a ConfigError listing every problem.
 * The app calls this once at start-up and exits if it throws.
 */
export function loadConfig(env: Env = process.env): Config {
  const location = checkLocation(env);
  const checks = {
    environment: setting(env, 'AGENTX_ENV'),
    release: setting(env, 'AGENTX_RELEASE'),
    logLevel: setting(env, 'AGENTX_LOG_LEVEL'),
    eventCap: setting(env, 'AGENTX_LOG_EVENT_CAP_PER_MINUTE'),
    host: setting(env, 'AGENTX_HTTP_HOST'),
    httpPort: setting(env, 'AGENTX_HTTP_PORT'),
    origin: setting(env, 'AGENTX_PUBLIC_ORIGIN'),
    trustedProxies: setting(env, 'AGENTX_TRUSTED_PROXIES'),
    rateLimit: setting(env, 'AGENTX_RATE_LIMIT_PER_MINUTE'),
    allowedOrigins: setting(env, 'AGENTX_OUTBOUND_ALLOWED_ORIGINS'),
    coolingOffHours: setting(env, 'AGENTX_PAYEE_COOLING_OFF_HOURS'),
    dbHost: location.host,
    dbPort: location.port,
    dbName: location.database,
    dbTls: location.tls,
    dbUser: setting(env, 'AGENTX_DB_USER'),
    dbPassword: secretSetting(env, 'AGENTX_DB_PASSWORD'),
    dbPoolMax: setting(env, 'AGENTX_DB_POOL_MAX'),
  };
  const { environment, release, logLevel, eventCap, httpPort, origin, trustedProxies, rateLimit, allowedOrigins } =
    checks;

  const problems = [
    ...tlsProblems(env),
    ...pgVariableProblems(env),
    ...unknownSettings(env, 'app'),
    ...failures(Object.values(checks)),
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
    ...(environment.ok && location.tls.ok ? tlsModeProblems(environment.value, location.tls.value) : []),
    ...(environment.ok ? nodeDebugProblems(environment.value, env) : []),
  ];
  // Every failed setting is already among the problems; the type guard narrows the checks to their values.
  if (!allOk(checks) || problems.length > 0) throw new ConfigError(problems);

  return Object.freeze({
    environment: checks.environment.value,
    release: checks.release.value ?? LOCAL_RELEASE,
    log: Object.freeze({ level: checks.logLevel.value, eventCapPerMinute: checks.eventCap.value }),
    http: Object.freeze({
      host: checks.host.value,
      port: checks.httpPort.value,
      // Only development and test get here without one (publicOriginProblems).
      publicOrigin: checks.origin.value ?? LOCAL_PUBLIC_ORIGIN,
      trustedProxies: Object.freeze(checks.trustedProxies.value ?? []),
      rateLimitPerMinute: checks.rateLimit.value,
    }),
    db: Object.freeze({
      host: checks.dbHost.value,
      port: checks.dbPort.value,
      database: checks.dbName.value,
      user: checks.dbUser.value,
      password: checks.dbPassword.value,
      tls: checks.dbTls.value,
      poolMax: checks.dbPoolMax.value,
    }),
    outbound: Object.freeze({ allowedOrigins: Object.freeze(checks.allowedOrigins.value ?? []) }),
    payees: Object.freeze({ coolingOffHours: checks.coolingOffHours.value }),
  });
}
