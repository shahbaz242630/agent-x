import { describe, expect, it } from 'vitest';

import { type Config, loadConfig } from './config.ts';
import { configFingerprint, WATCHED_VARIABLES } from './fingerprint.ts';

type Env = Record<string, string | undefined>;

const SETTINGS: Env = {
  AGENTX_ENV: 'production',
  AGENTX_RELEASE: 'r-1',
  AGENTX_PUBLIC_ORIGIN: 'https://app.agentx.example',
  AGENTX_TRUSTED_PROXIES: '10.0.0.0/23',
  AGENTX_PAYEE_COOLING_OFF_HOURS: '48',
};

/** The fingerprint of a process started with these variables and no Node flags. */
const fingerprintOf = (env: Env, flags: readonly string[] = []) => configFingerprint(loadConfig(env), env, flags);
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
    expect(configFingerprint(reversed(config), SETTINGS, []).configHash).toBe(
      configFingerprint(config, SETTINGS, []).configHash,
    );
  });

  it('stays the same when only the release changes, as it does on every deploy', () => {
    expect(hashOf({ ...SETTINGS, AGENTX_RELEASE: 'r-2' })).toBe(hashOf(SETTINGS));
  });

  it.each([
    ['a threshold', { AGENTX_PAYEE_COOLING_OFF_HOURS: '49' }],
    ['the log level', { AGENTX_LOG_LEVEL: 'warn' }],
    ['the outbound allowlist', { AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example' }],
    ['the trusted proxies', { AGENTX_TRUSTED_PROXIES: '10.0.0.0/24' }],
    ['the public origin', { AGENTX_PUBLIC_ORIGIN: 'https://other.agentx.example' }],
    ['the environment', { AGENTX_ENV: 'staging' }],
  ])('changes when %s changes', (_what, change) => {
    expect(hashOf({ ...SETTINGS, ...change })).not.toBe(hashOf(SETTINGS));
  });

  it('ignores variables that are neither settings nor watched', () => {
    expect(hashOf({ ...SETTINGS, PATH: '/usr/bin', HOSTNAME: 'replica-7' })).toBe(hashOf(SETTINGS));
  });

  it('reads the live environment and Node flags when none are given', () => {
    const config = loadConfig(SETTINGS);
    expect(configFingerprint(config).configHash).toMatch(/^sha256:[0-9a-f]{64}$/);
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
    const flags = ['--use-system-ca', '--require=/app/preload.js', '--max-old-space-size=4096', '--use-system-ca'];
    const fingerprint = fingerprintOf(SETTINGS, flags);
    expect(fingerprint.nodeFlags).toEqual(['--use-system-ca', '--require', '--max-old-space-size']);
    expect(JSON.stringify(fingerprint)).not.toContain('preload');
    expect(hashOf(SETTINGS, flags)).not.toBe(hashOf(SETTINGS));
    expect(hashOf(SETTINGS, ['--require=/app/other.js'])).not.toBe(hashOf(SETTINGS, ['--require=/app/preload.js']));
  });
});
