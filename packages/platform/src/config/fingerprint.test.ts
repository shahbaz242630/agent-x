import { describe, expect, it } from 'vitest';

import type { KeyDescription } from '../keys/key-provider.ts';
import { type Config, loadConfig } from './config.ts';
import { configFingerprint, fingerprintedSettings, WATCHED_VARIABLES } from './fingerprint.ts';

type Env = Record<string, string | undefined>;

/** Plain words, so secret scanners ignore it. */
const DB_LOGIN = 'app login for these tests';
const SETTINGS: Env = {
  AGENTX_ENV: 'production',
  AGENTX_RELEASE: 'r-1',
  AGENTX_PUBLIC_ORIGIN: 'https://app.agentx.example',
  AGENTX_TRUSTED_PROXIES: '10.0.0.0/23',
  AGENTX_PAYEE_COOLING_OFF_HOURS: '48',
  AGENTX_DB_HOST: 'db.internal.example',
  AGENTX_DB_PASSWORD: DB_LOGIN,
  AGENTX_KEYS_DIR: '/mnt/secrets',
  AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://auth.agentx.example',
  AGENTX_OIDC_ISSUER: 'https://auth.agentx.example',
  AGENTX_OIDC_CLIENT_ID: 'agentx-api',
  AGENTX_OIDC_CLIENT_SECRET: 'client pass words',
};

/** The same, with email on (B5-3). */
const WITH_EMAIL: Env = {
  ...SETTINGS,
  AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://auth.agentx.example,https://acs.agentx.example',
  AGENTX_EMAIL_ENDPOINT: 'https://acs.agentx.example',
  AGENTX_EMAIL_SENDER: 'DoNotReply@agentx.example',
  // Plain words, built at run time, as every stand-in for a secret here.
  AGENTX_EMAIL_ACCESS_KEY: Buffer.from('stand in email words').toString('base64'),
  AGENTX_DIRECTORY_TOKEN: ['directory', 'words'].join('-'),
};

/** What a KeyProvider describes: versions and check values, never keys. */
const AUDIT_MAC: KeyDescription = {
  purpose: 'audit-mac',
  current: 1,
  versions: [{ version: 1, check: '0123456789abcdef0123456789abcdef' }],
};
const AUDIT_ANCHOR: KeyDescription = {
  purpose: 'audit-anchor',
  current: 1,
  versions: [{ version: 1, check: 'fedcba9876543210fedcba9876543210', publicKey: 'a-public-key-for-these-tests' }],
};
const KEYS: readonly KeyDescription[] = [AUDIT_MAC, AUDIT_ANCHOR];

/** Every leaf of a config, as `path: value` strings. */
function leaves(value: unknown, prefix = ''): string[] {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return Object.entries(value as Record<string, unknown>).flatMap(([name, item]) =>
      leaves(item, prefix === '' ? name : `${prefix}.${name}`),
    );
  }
  return [`${prefix}: ${JSON.stringify(value)}`];
}

/** The fingerprint of a process started with these variables and no Node flags. */
const fingerprintOf = (env: Env, flags: readonly string[] = [], keys = KEYS) =>
  configFingerprint(loadConfig(env), keys, env, flags);
const hashOf = (env: Env, flags: readonly string[] = []): string => fingerprintOf(env, flags).configHash;

/** The same config, with its fields (and its sections' fields) in reverse order. */
function reversed(config: Config): Config {
  const entries = Object.entries(config as unknown as Record<string, unknown>)
    .reverse()
    .map(([name, value]): [string, unknown] => [
      name,
      typeof value === 'object' && value !== null && !Array.isArray(value)
        ? Object.fromEntries(Object.entries(value as Record<string, unknown>).reverse())
        : value,
    ]);
  return Object.fromEntries(entries) as unknown as Config;
}

describe('SEC-OPS-05 the config fingerprint', () => {
  it('is a SHA-256 hash, and lists nothing watched when nothing is set', () => {
    const fingerprint = fingerprintOf(SETTINGS);
    expect(fingerprint.configHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fingerprint.watchedVariables).toEqual([]);
    expect(fingerprint.nodeFlags).toEqual([]);
  });

  it('is the same for the same settings, whatever order they were given in', () => {
    const reorderedEnv = Object.fromEntries(Object.entries(SETTINGS).reverse());
    expect(hashOf(reorderedEnv)).toBe(hashOf(SETTINGS));
  });

  it('is the same for a config whose fields were built in a different order', () => {
    const config = loadConfig(SETTINGS);
    expect(Object.keys(reversed(config))).not.toEqual(Object.keys(config));
    expect(configFingerprint(reversed(config), KEYS, SETTINGS, []).configHash).toBe(
      configFingerprint(config, KEYS, SETTINGS, []).configHash,
    );
  });

  it('stays the same when only the release changes, as it does on every deploy', () => {
    expect(hashOf({ ...SETTINGS, AGENTX_RELEASE: 'r-2' })).toBe(hashOf(SETTINGS));
  });

  it.each([
    ['a threshold', { AGENTX_PAYEE_COOLING_OFF_HOURS: '49' }],
    ['the log level', { AGENTX_LOG_LEVEL: 'warn' }],
    [
      'the outbound allowlist',
      { AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example,https://auth.agentx.example' },
    ],
    [
      'the login service',
      {
        AGENTX_OIDC_ISSUER: 'https://login.agentx.example',
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://login.agentx.example',
      },
    ],
    ['the OIDC client', { AGENTX_OIDC_CLIENT_ID: 'agentx-api-2' }],
    [
      "the login service's internal origin",
      {
        AGENTX_OIDC_INTERNAL_ORIGIN: 'https://zitadel.internal.agentx.example',
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://zitadel.internal.agentx.example',
      },
    ],
    [
      'sign-in turned off',
      { AGENTX_OIDC_ISSUER: undefined, AGENTX_OIDC_CLIENT_ID: undefined, AGENTX_OIDC_CLIENT_SECRET: undefined },
    ],
    ['the idle timeout', { AGENTX_SESSION_IDLE_MINUTES: '31' }],
    ['the absolute timeout', { AGENTX_SESSION_ABSOLUTE_HOURS: '11' }],
    ['the trusted proxies', { AGENTX_TRUSTED_PROXIES: '10.0.0.0/24' }],
    ['the public origin', { AGENTX_PUBLIC_ORIGIN: 'https://other.agentx.example' }],
    ['the environment', { AGENTX_ENV: 'staging' }],
    ['the database host', { AGENTX_DB_HOST: 'other.internal.example' }],
    ['the database port', { AGENTX_DB_PORT: '6432' }],
    ['the database name', { AGENTX_DB_NAME: 'agentx_uae' }],
    ['the database role', { AGENTX_DB_USER: 'agentx_app_uae' }],
    ['the pool size', { AGENTX_DB_POOL_MAX: '20' }],
    ['the listen address', { AGENTX_HTTP_HOST: '0.0.0.0' }],
    ['the port', { AGENTX_HTTP_PORT: '8081' }],
    ['the rate limit', { AGENTX_RATE_LIMIT_PER_MINUTE: '200' }],
    ["a person's rate limit", { AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE: '60' }],
    ["the security events' retention", { AGENTX_SECURITY_EVENT_RETENTION_DAYS: '120' }],
    ['the anchor interval', { AGENTX_AUDIT_ANCHOR_SECONDS: '600' }],
    ['the log cap', { AGENTX_LOG_EVENT_CAP_PER_MINUTE: '1200' }],
    ['the keys folder', { AGENTX_KEYS_DIR: '/mnt/keys' }],
    ["a key's current version", { AGENTX_KEYS_CURRENT: 'audit-mac:2' }],
  ])('changes when %s changes', (_what, change) => {
    expect(hashOf({ ...SETTINGS, ...change })).not.toBe(hashOf(SETTINGS));
  });

  it.each([
    [
      'a key swapped under the same version',
      [{ ...AUDIT_MAC, versions: [{ version: 1, check: '1'.repeat(32) }] }, AUDIT_ANCHOR],
    ],
    [
      'a version added',
      [{ ...AUDIT_MAC, versions: [...AUDIT_MAC.versions, { version: 2, check: '2'.repeat(32) }] }, AUDIT_ANCHOR],
    ],
    ['a new current version', [{ ...AUDIT_MAC, current: 2 }, AUDIT_ANCHOR]],
    ['a key gone', [AUDIT_MAC]],
  ])('changes when the keys loaded change: %s', (_what, keys: readonly KeyDescription[]) => {
    expect(fingerprintOf(SETTINGS, [], keys).configHash).not.toBe(hashOf(SETTINGS));
  });

  it('lists the keys it hashed, as the provider described them', () => {
    expect(fingerprintOf(SETTINGS).keys).toEqual(KEYS);
  });

  it('changes when the TLS mode changes (in test, where disable is allowed)', () => {
    const local = {
      AGENTX_ENV: 'test',
      AGENTX_DB_HOST: 'db',
      AGENTX_DB_PASSWORD: DB_LOGIN,
      AGENTX_KEYS_DIR: '/mnt/secrets',
    };
    expect(hashOf({ ...local, AGENTX_DB_TLS: 'disable' })).not.toBe(hashOf(local));
  });

  it("ignores the email service's key and the directory's token (B5-3), as it does the password", () => {
    expect(
      hashOf({ ...WITH_EMAIL, AGENTX_EMAIL_ACCESS_KEY: Buffer.from('other email words').toString('base64') }),
    ).toBe(hashOf(WITH_EMAIL));
    expect(hashOf({ ...WITH_EMAIL, AGENTX_DIRECTORY_TOKEN: ['other', 'directory', 'words'].join('-') })).toBe(
      hashOf(WITH_EMAIL),
    );
    expect(hashOf({ ...WITH_EMAIL, AGENTX_EMAIL_SENDER: 'Notices@agentx.example' })).not.toBe(hashOf(WITH_EMAIL));
    expect(hashOf(WITH_EMAIL)).not.toBe(hashOf(SETTINGS));
  });

  it('ignores the OIDC client secret, as it does the password', () => {
    expect(hashOf({ ...SETTINGS, AGENTX_OIDC_CLIENT_SECRET: 'other pass words' })).toBe(hashOf(SETTINGS));
  });

  it('ignores the database password: a hash of a weak secret could be guessed offline', () => {
    expect(hashOf({ ...SETTINGS, AGENTX_DB_PASSWORD: 'another login for these tests' })).toBe(hashOf(SETTINGS));
    expect(JSON.stringify(fingerprintedSettings(loadConfig(SETTINGS)))).not.toContain(DB_LOGIN);
  });

  it('names every setting one by one: everything in the config but the release and the secrets', () => {
    const config = loadConfig(WITH_EMAIL);
    const left = leaves(config).filter(
      (leaf) =>
        !leaf.startsWith('release: ') &&
        !leaf.startsWith('db.password: ') &&
        !leaf.startsWith('signIn.clientSecret: ') &&
        !leaf.startsWith('email.accessKey: ') &&
        !leaf.startsWith('email.directoryToken: '),
    );
    expect(leaves(fingerprintedSettings(config)).sort()).toEqual(left.sort());
  });

  it('ignores variables that are neither settings nor watched', () => {
    expect(hashOf({ ...SETTINGS, PATH: '/usr/bin', HOSTNAME: 'replica-7' })).toBe(hashOf(SETTINGS));
  });

  it('reads the live environment and Node flags when none are given', () => {
    const config = loadConfig(SETTINGS);
    expect(configFingerprint(config, KEYS).configHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('is frozen', () => {
    const fingerprint = fingerprintOf(SETTINGS, ['--use-system-ca']);
    expect(Object.isFrozen(fingerprint)).toBe(true);
    expect(Object.isFrozen(fingerprint.watchedVariables)).toBe(true);
    expect(Object.isFrozen(fingerprint.nodeFlags)).toBe(true);
  });
});

describe('SEC-OPS-05 what can change the app from outside its settings is visible, by name only', () => {
  // Staging, because production refuses the debug switches at start-up.
  const STAGING: Env = { ...SETTINGS, AGENTX_ENV: 'staging' };

  it.each(WATCHED_VARIABLES)('lists %s when set, and changes the hash', (name) => {
    const env = { ...STAGING, [name]: '/etc/ssl/bank-ca.pem' };
    expect(fingerprintOf(env).watchedVariables).toEqual([name]);
    expect(hashOf(env)).not.toBe(hashOf(STAGING));
  });

  it.each(['NODE_USE_SYSTEM_CA', 'NODE_USE_ENV_PROXY', 'HTTPS_PROXY', 'NODE_PATH', 'NODE_DEBUG'])(
    'watches %s, which changes trust, routing, loading or output',
    (name) => {
      expect(WATCHED_VARIABLES).toContain(name);
    },
  );

  it('changes the hash when a watched value changes, such as a different CA file', () => {
    const one = { ...SETTINGS, NODE_EXTRA_CA_CERTS: '/etc/ssl/bank-ca.pem' };
    const other = { ...SETTINGS, NODE_EXTRA_CA_CERTS: '/tmp/other-ca.pem' };
    expect(hashOf(one)).not.toBe(hashOf(other));
  });

  it('lists every watched variable set, and never their values', () => {
    const env = { ...SETTINGS, NODE_OPTIONS: '--use-openssl-ca', SSL_CERT_FILE: '/etc/ssl/bank-ca.pem' };
    const fingerprint = fingerprintOf(env);
    expect(fingerprint.watchedVariables).toEqual(['SSL_CERT_FILE', 'NODE_OPTIONS']);
    expect(JSON.stringify(fingerprint)).not.toContain('bank-ca');
    expect(JSON.stringify(fingerprint)).not.toContain('--use-openssl-ca');
  });

  it('lists the flags Node was started with by name, without their values, and hashes them in full', () => {
    const flags = [
      '-r',
      './hooks.js',
      '--use-system-ca',
      '--require=/app/preload.js',
      '--max-old-space-size=4096',
      '--use-system-ca',
    ];
    const fingerprint = fingerprintOf(SETTINGS, flags);
    // Short flags too, by name; the file `-r` loads is a value, not a flag.
    expect(fingerprint.nodeFlags).toEqual(['-r', '--use-system-ca', '--require', '--max-old-space-size']);
    expect(JSON.stringify(fingerprint)).not.toContain('preload');
    expect(JSON.stringify(fingerprint)).not.toContain('hooks.js');
    expect(hashOf(SETTINGS, flags)).not.toBe(hashOf(SETTINGS));
    expect(hashOf(SETTINGS, ['--require=/app/other.js'])).not.toBe(hashOf(SETTINGS, ['--require=/app/preload.js']));
  });
});
