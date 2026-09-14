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
// When secret settings are added to Config, list the fingerprinted fields
// explicitly instead of hashing the whole config: a hash of a weak secret can
// be guessed offline.
import { createHash } from 'node:crypto';

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
  /** Which watched variables are set, by name. Never their values. */
  readonly watchedVariables: readonly string[];
  /** The flags Node was started with, by name only (`--use-system-ca`, not what follows `=`). */
  readonly nodeFlags: readonly string[];
}

type Env = Readonly<Record<string, string | undefined>>;

/** JSON with every object's fields in sorted order, so the same settings always hash the same. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const fields = Object.entries(value)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([name, item]) => `${JSON.stringify(name)}:${canonical(item)}`);
    return `{${fields.join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * The release is left out: it changes with every deploy, and the fingerprint
 * should change only when a setting does.
 */
export function configFingerprint(
  config: Config,
  env: Env = process.env,
  nodeArguments: readonly string[] = process.execArgv,
): ConfigFingerprint {
  const { release: _release, ...settings } = config;
  const watched = Object.fromEntries(
    WATCHED_VARIABLES.flatMap((name) => (env[name] === undefined ? [] : [[name, env[name]]])),
  );
  const hash = createHash('sha256').update(canonical({ settings, watched, nodeArguments })).digest('hex');
  const flags = [
    ...new Set(nodeArguments.filter((argument) => argument.startsWith('-')).map((flag) => flag.replace(/=.*$/s, ''))),
  ];
  return Object.freeze({
    configHash: `sha256:${hash}`,
    watchedVariables: Object.freeze(Object.keys(watched)),
    nodeFlags: Object.freeze(flags),
  });
}
