// SEC-OPS-05 (ADR-012 §6): a fingerprint of the settings a process started
// with, logged at start-up (and written to the platform audit chain from
// Phase 1). When it changes without a deploy that explains it, someone changed
// the config.
//
// It also covers what can change the app's behaviour from outside its
// settings: the variables that change which TLS certificates Node trusts,
// where its traffic goes, how it starts or where it loads modules from, and
// the flags Node was started with. They aren't refused, because a bank may need
// its own certificate authority or proxy, but they must be visible: the
// fingerprint names the ones set, never their values, and their values count
// towards the hash.
//
// The config holds secrets (the database password, the OIDC client secret),
// so the fields that count towards the hash are listed one by one below, and
// neither is among them: a hash of a weak secret can be guessed offline.
//
// The keys the process loaded count too, by version and check value, never
// the keys themselves: a key swapped under the same version changes the hash.
import { createHash } from 'node:crypto';

import type { KeyDescription } from '../keys/key-provider.ts';
import type { Config } from './config.ts';

export const WATCHED_VARIABLES = [
  // Which certificates Node trusts
  'NODE_EXTRA_CA_CERTS',
  'NODE_USE_SYSTEM_CA',
  'OPENSSL_CONF',
  'SSL_CERT_DIR',
  'SSL_CERT_FILE',
  // Where traffic goes (used when NODE_USE_ENV_PROXY is set)
  'NODE_USE_ENV_PROXY',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'no_proxy',
  // How Node starts, and what it loads or prints
  'NODE_OPTIONS',
  'NODE_PATH',
  'NODE_DEBUG',
  'NODE_DEBUG_NATIVE',
  'NODE_REDIRECT_WARNINGS',
] as const;

export interface ConfigFingerprint {
  /** `sha256:` and 64 hex digits. */
  readonly configHash: string;
  /** Each key's versions, current version and check values (KeyProvider.describe), which count towards the hash. */
  readonly keys: readonly KeyDescription[];
  /** Which watched variables are set, by name. Never their values. */
  readonly watchedVariables: readonly string[];
  /** The flags Node was started with, by name only (`--use-system-ca`, not what follows `=`). */
  readonly nodeFlags: readonly string[];
}

type Env = Readonly<Record<string, string | undefined>>;

/**
 * The settings that count, named one by one, in a fixed order, so the same
 * settings always hash the same however the config was built. The release is
 * left out: it changes with every deploy, and the fingerprint should change
 * only when a setting does. The database password and the OIDC client secret
 * are left out: they're secrets.
 */
export function fingerprintedSettings(config: Config): Record<string, unknown> {
  return {
    environment: config.environment,
    log: { level: config.log.level, eventCapPerMinute: config.log.eventCapPerMinute },
    http: {
      host: config.http.host,
      port: config.http.port,
      publicOrigin: config.http.publicOrigin,
      trustedProxies: config.http.trustedProxies,
      rateLimitPerMinute: config.http.rateLimitPerMinute,
    },
    db: {
      host: config.db.host,
      port: config.db.port,
      database: config.db.database,
      user: config.db.user,
      tls: config.db.tls,
      poolMax: config.db.poolMax,
    },
    outbound: { allowedOrigins: config.outbound.allowedOrigins },
    // The client secret is left out: it's a secret.
    signIn: config.signIn === undefined ? null : { issuer: config.signIn.issuer, clientId: config.signIn.clientId },
    sessions: { idleSeconds: config.sessions.idleSeconds, absoluteSeconds: config.sessions.absoluteSeconds },
    payees: { coolingOffHours: config.payees.coolingOffHours },
    audit: { anchorSeconds: config.audit.anchorSeconds },
    keys: { directory: config.keys.directory, current: config.keys.current },
  };
}

export function configFingerprint(
  config: Config,
  keys: readonly KeyDescription[],
  env: Env = process.env,
  nodeArguments: readonly string[] = process.execArgv,
): ConfigFingerprint {
  const settings = fingerprintedSettings(config);
  // In WATCHED_VARIABLES' order, like the settings above: nothing here depends on how the environment was built.
  const watched = Object.fromEntries(
    WATCHED_VARIABLES.flatMap((name) => (env[name] === undefined ? [] : [[name, env[name]]])),
  );
  const hash = createHash('sha256').update(JSON.stringify({ settings, keys, watched, nodeArguments })).digest('hex');
  const flags = [
    ...new Set(nodeArguments.filter((argument) => argument.startsWith('-')).map((flag) => flag.replace(/=.*$/s, ''))),
  ];
  return Object.freeze({
    configHash: `sha256:${hash}`,
    keys,
    watchedVariables: Object.freeze(Object.keys(watched)),
    nodeFlags: Object.freeze(flags),
  });
}
