// The app's deployment config (Rule Book §5, ADR-010 §5, ADR-011 §9, ADR-012
// §6). Every setting comes from an AGENTX_ environment variable, set by
// reviewed infrastructure code, and is checked once at start-up. Anything
// wrong stops the start: a bad value, a broken rule between settings, a value
// below a safety minimum, a misspelt AGENTX_ variable, a setting that belongs
// to another job, a PG* variable, or TLS certificate checks turned off.
// Problems name the variable and the rule, never the value, so a secret pasted
// into the wrong variable can't leak through the error.
import type { KeySettings } from '../keys/load.ts';
import { ConfigError, type Env, type Environment, LOCAL_ONLY, type LogLevel } from './common.ts';
import {
  checkLocation,
  optionalSecretSetting,
  pgVariableProblems,
  secretSetting,
  tlsModeProblems,
} from './database.ts';
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
    /** ADR-011 §4 (B2-5c): the most requests one signed-in person may make per minute, from any address. */
    readonly rateLimitPerUserPerMinute: number;
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
  /**
   * ADR-003 §5: the login service the API is the OIDC client of. Undefined
   * when none is set, and sign-in is then off (B2-3a: staging until B2-6).
   */
  readonly signIn:
    | {
        readonly issuer: string;
        readonly clientId: string;
        /** Never logged, never in the fingerprint. */
        readonly clientSecret: string;
        /**
         * B2-6: where the API reaches the login service inside the platform's
         * own network, naming the issuer's host in Zitadel's own headers;
         * undefined when it calls the issuer itself.
         */
        readonly internalOrigin: string | undefined;
      }
    | undefined;
  /** ADR-003 §7: how long a console session lives unused, and at most. */
  readonly sessions: { readonly idleSeconds: number; readonly absoluteSeconds: number };
  /** ADR-005 §6, ADR-011 §7: how long a security event is kept, in whole days. */
  readonly securityEvents: { readonly retentionDays: number };
  /** ADR-012 §1: how long a new or changed payee waits before it can be paid. */
  readonly payees: { readonly coolingOffHours: number };
  /** ADR-012 §2: how often each audit chain is checked against its last anchor, and anchored again. */
  readonly audit: { readonly anchorSeconds: number };
  /** ADR-011 §2: where the platform mounts the app's keys, and each key's current version where it isn't 1. */
  readonly keys: KeySettings;
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
function rateLimitProblems(
  name: 'AGENTX_RATE_LIMIT_PER_MINUTE' | 'AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE',
  perMinute: number,
  eventCapPerMinute: number,
): string[] {
  const whose = name === 'AGENTX_RATE_LIMIT_PER_MINUTE' ? "one client's" : "one person's";
  return perMinute * 2 > eventCapPerMinute
    ? [
        `${name}: must be at most half of AGENTX_LOG_EVENT_CAP_PER_MINUTE (${eventCapPerMinute}), ` +
          `so ${whose} requests can't fill the request log on their own`,
      ]
    : [];
}

/**
 * ADR-003 §5: the login service is named in full or not at all, and the API
 * must be allowed to call it where it calls it: it fetches the keys and
 * trades codes there. That is the issuer, or the internal origin when one is
 * set (B2-6), which only goes with sign-in.
 */
function signInProblems(
  environment: Environment,
  issuer: string | undefined,
  clientId: string | undefined,
  secretSet: boolean,
  internalOrigin: string | undefined,
  allowedOrigins: readonly string[],
): string[] {
  const set = [issuer !== undefined, clientId !== undefined, secretSet];
  if (set.every((one) => !one)) {
    return internalOrigin === undefined
      ? []
      : ['AGENTX_OIDC_INTERNAL_ORIGIN: set only with AGENTX_OIDC_ISSUER, where it says how to reach it'];
  }
  if (!set.every(Boolean)) {
    return [
      'AGENTX_OIDC_ISSUER, AGENTX_OIDC_CLIENT_ID and AGENTX_OIDC_CLIENT_SECRET: set all three, or none (sign-in is off without them)',
    ];
  }
  if (issuer === undefined) return [];
  const [called, name] =
    internalOrigin === undefined
      ? [issuer, 'AGENTX_OIDC_ISSUER' as const]
      : [internalOrigin, 'AGENTX_OIDC_INTERNAL_ORIGIN' as const];
  return [
    ...plainHttpProblems('AGENTX_OIDC_ISSUER', environment, [issuer]),
    ...(internalOrigin === undefined
      ? []
      : plainHttpProblems('AGENTX_OIDC_INTERNAL_ORIGIN', environment, [internalOrigin])),
    ...(allowedOrigins.includes(called)
      ? []
      : [`${name}: must be on AGENTX_OUTBOUND_ALLOWED_ORIGINS; the API fetches its keys and trades codes there`]),
  ];
}

/** A session can't be let idle for longer than it may live at all. */
function sessionProblems(idleMinutes: number, absoluteHours: number): string[] {
  return idleMinutes > absoluteHours * 60
    ? ['AGENTX_SESSION_IDLE_MINUTES: must be no longer than AGENTX_SESSION_ABSOLUTE_HOURS']
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

/** The login service's settings, once signInProblems has found them all set or none. */
function signInFrom(
  issuer: string | undefined,
  clientId: string | undefined,
  clientSecret: string | undefined,
  internalOrigin: string | undefined,
): Config['signIn'] {
  return issuer === undefined || clientId === undefined || clientSecret === undefined
    ? undefined
    : Object.freeze({ issuer, clientId, clientSecret, internalOrigin });
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
    rateLimitPerUser: setting(env, 'AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE'),
    allowedOrigins: setting(env, 'AGENTX_OUTBOUND_ALLOWED_ORIGINS'),
    oidcIssuer: setting(env, 'AGENTX_OIDC_ISSUER'),
    oidcClientId: setting(env, 'AGENTX_OIDC_CLIENT_ID'),
    oidcClientSecret: optionalSecretSetting(env, 'AGENTX_OIDC_CLIENT_SECRET'),
    oidcInternalOrigin: setting(env, 'AGENTX_OIDC_INTERNAL_ORIGIN'),
    sessionIdle: setting(env, 'AGENTX_SESSION_IDLE_MINUTES'),
    sessionAbsolute: setting(env, 'AGENTX_SESSION_ABSOLUTE_HOURS'),
    securityEventRetention: setting(env, 'AGENTX_SECURITY_EVENT_RETENTION_DAYS'),
    coolingOffHours: setting(env, 'AGENTX_PAYEE_COOLING_OFF_HOURS'),
    anchorSeconds: setting(env, 'AGENTX_AUDIT_ANCHOR_SECONDS'),
    keysDirectory: setting(env, 'AGENTX_KEYS_DIR'),
    keysCurrent: setting(env, 'AGENTX_KEYS_CURRENT'),
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
    ...(rateLimit.ok && eventCap.ok
      ? rateLimitProblems('AGENTX_RATE_LIMIT_PER_MINUTE', rateLimit.value, eventCap.value)
      : []),
    // B2-5c: a person reaching us from many addresses, each under its own limit, is held by theirs.
    ...(checks.rateLimitPerUser.ok && eventCap.ok
      ? rateLimitProblems('AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE', checks.rateLimitPerUser.value, eventCap.value)
      : []),
    ...(environment.ok &&
    checks.oidcIssuer.ok &&
    checks.oidcClientId.ok &&
    checks.oidcClientSecret.ok &&
    checks.oidcInternalOrigin.ok &&
    allowedOrigins.ok
      ? signInProblems(
          environment.value,
          checks.oidcIssuer.value,
          checks.oidcClientId.value,
          checks.oidcClientSecret.value !== undefined,
          checks.oidcInternalOrigin.value,
          allowedOrigins.value ?? [],
        )
      : []),
    ...(checks.sessionIdle.ok && checks.sessionAbsolute.ok
      ? sessionProblems(checks.sessionIdle.value, checks.sessionAbsolute.value)
      : []),
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
      rateLimitPerUserPerMinute: checks.rateLimitPerUser.value,
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
    signIn: signInFrom(
      checks.oidcIssuer.value,
      checks.oidcClientId.value,
      checks.oidcClientSecret.value,
      checks.oidcInternalOrigin.value,
    ),
    sessions: Object.freeze({
      idleSeconds: checks.sessionIdle.value * 60,
      absoluteSeconds: checks.sessionAbsolute.value * 3600,
    }),
    securityEvents: Object.freeze({ retentionDays: checks.securityEventRetention.value }),
    payees: Object.freeze({ coolingOffHours: checks.coolingOffHours.value }),
    audit: Object.freeze({ anchorSeconds: checks.anchorSeconds.value }),
    keys: Object.freeze({
      directory: checks.keysDirectory.value,
      current: Object.freeze(checks.keysCurrent.value ?? {}),
    }),
  });
}
