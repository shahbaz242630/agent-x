import { describe, expect, it } from 'vitest';

import { ConfigError } from './common.ts';
import { loadConfig } from './config.ts';

type Env = Record<string, string | undefined>;

const RELEASE = '2026.09.14-a1b2c3d';
const PUBLIC_ORIGIN = 'https://app.agentx.example';
const PROXIES = '10.0.0.0/23';
const DB_HOST = 'db.internal.example';
/** Plain words, so secret scanners ignore it. */
const DB_LOGIN = 'app login for these tests';
/** Where the platform mounts the keys; loadConfig checks the setting, and loadKeys reads the files. */
const KEYS_DIR = '/mnt/secrets';
const MINIMAL: Env = {
  AGENTX_ENV: 'production',
  AGENTX_RELEASE: RELEASE,
  AGENTX_PUBLIC_ORIGIN: PUBLIC_ORIGIN,
  AGENTX_TRUSTED_PROXIES: PROXIES,
  AGENTX_DB_HOST: DB_HOST,
  AGENTX_DB_PASSWORD: DB_LOGIN,
  AGENTX_KEYS_DIR: KEYS_DIR,
};
const DB_DEFAULTS = {
  host: DB_HOST,
  port: 5432,
  database: 'agentx',
  user: 'agentx_app',
  password: DB_LOGIN,
  tls: 'verify-full',
  poolMax: 10,
};
/** The database settings a local run can't do without, for tests of the other settings' local defaults. */
const LOCAL: Env = { AGENTX_DB_HOST: 'db', AGENTX_DB_PASSWORD: DB_LOGIN, AGENTX_KEYS_DIR: KEYS_DIR };

/** The problems loadConfig reports, or [] when it accepts the config. */
function problemsWith(env: Env): readonly string[] {
  try {
    loadConfig(env);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
}

describe('config: a correct config loads', () => {
  it('needs only the environment, the release, the public origin and where the keys are, and fills in the defaults', () => {
    expect(loadConfig(MINIMAL)).toEqual({
      environment: 'production',
      release: RELEASE,
      log: { level: 'info', eventCapPerMinute: 600 },
      http: {
        host: '127.0.0.1',
        port: 8080,
        publicOrigin: PUBLIC_ORIGIN,
        trustedProxies: [PROXIES],
        rateLimitPerMinute: 300,
      },
      db: DB_DEFAULTS,
      outbound: { allowedOrigins: [] },
      payees: { coolingOffHours: 24 },
      audit: { anchorSeconds: 300 },
      keys: { directory: KEYS_DIR, current: {} },
    });
  });

  it.each(['development', 'test', 'staging', 'production'])('accepts the %s environment', (environment) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_ENV: environment }).environment).toBe(environment);
  });

  it('reads every setting, sorting the lists and dropping repeats', () => {
    const config = loadConfig({
      AGENTX_ENV: 'staging',
      AGENTX_RELEASE: RELEASE,
      AGENTX_LOG_LEVEL: 'warn',
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: '1200',
      AGENTX_HTTP_HOST: '0.0.0.0',
      AGENTX_HTTP_PORT: '3000',
      AGENTX_PUBLIC_ORIGIN: 'https://staging.agentx.example',
      AGENTX_TRUSTED_PROXIES: '10.0.0.0/23,100.100.0.1,10.0.0.0/23',
      AGENTX_RATE_LIMIT_PER_MINUTE: '120',
      AGENTX_OUTBOUND_ALLOWED_ORIGINS:
        'https://telemetry.example,https://api.partner.example:8443,https://telemetry.example',
      AGENTX_PAYEE_COOLING_OFF_HOURS: '48',
      AGENTX_AUDIT_ANCHOR_SECONDS: '600',
      AGENTX_DB_HOST: '10.0.0.5',
      AGENTX_DB_PORT: '6432',
      AGENTX_DB_NAME: 'agentx_uae',
      AGENTX_DB_USER: 'agentx_app_uae',
      AGENTX_DB_PASSWORD: DB_LOGIN,
      AGENTX_DB_TLS: 'verify-full',
      AGENTX_DB_POOL_MAX: '25',
      AGENTX_KEYS_DIR: '/mnt/keys',
      AGENTX_KEYS_CURRENT: 'field-encryption:3,audit-mac:2,request-hash:1',
    });
    expect(config).toEqual({
      environment: 'staging',
      release: RELEASE,
      log: { level: 'warn', eventCapPerMinute: 1200 },
      http: {
        host: '0.0.0.0',
        port: 3000,
        publicOrigin: 'https://staging.agentx.example',
        trustedProxies: ['10.0.0.0/23', '100.100.0.1'],
        rateLimitPerMinute: 120,
      },
      db: {
        host: '10.0.0.5',
        port: 6432,
        database: 'agentx_uae',
        user: 'agentx_app_uae',
        password: DB_LOGIN,
        tls: 'verify-full',
        poolMax: 25,
      },
      outbound: { allowedOrigins: ['https://api.partner.example:8443', 'https://telemetry.example'] },
      payees: { coolingOffHours: 48 },
      audit: { anchorSeconds: 600 },
      keys: { directory: '/mnt/keys', current: { 'request-hash': 1, 'audit-mac': 2, 'field-encryption': 3 } },
    });
    // In the keys' own order, whatever order they were set in, so the fingerprint doesn't depend on it.
    expect(Object.keys(config.keys.current)).toEqual(['request-hash', 'audit-mac', 'field-encryption']);
  });

  it('ignores variables that are not AGENTX_ settings', () => {
    expect(problemsWith({ ...MINIMAL, PATH: '/usr/bin', NODE_ENV: 'production', AGENT_X: 'x' })).toEqual([]);
  });

  it('returns a config nothing can change afterwards', () => {
    const config = loadConfig({
      ...MINIMAL,
      AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example',
      AGENTX_TRUSTED_PROXIES: '10.0.0.0/23',
    });
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.log)).toBe(true);
    expect(Object.isFrozen(config.http)).toBe(true);
    expect(Object.isFrozen(config.http.trustedProxies)).toBe(true);
    expect(Object.isFrozen(config.outbound)).toBe(true);
    expect(Object.isFrozen(config.outbound.allowedOrigins)).toBe(true);
    expect(Object.isFrozen(config.payees)).toBe(true);
    expect(Object.isFrozen(config.db)).toBe(true);
    expect(Object.isFrozen(config.keys)).toBe(true);
    expect(Object.isFrozen(config.keys.current)).toBe(true);
    expect(() => (config.outbound.allowedOrigins as string[]).push('https://evil.example')).toThrow(TypeError);
    expect(() => (config.http.trustedProxies as string[]).push('0.0.0.0/0')).toThrow(TypeError);
  });
});

describe('SEC-AV-03 config refuses to start when a setting is wrong', () => {
  it('refuses a missing environment: the app must know if it is in production', () => {
    expect(problemsWith({})).toEqual([
      'AGENTX_ENV: is required',
      'AGENTX_KEYS_DIR: is required',
      'AGENTX_DB_HOST: is required',
      expect.stringMatching(/^AGENTX_DB_PASSWORD is required/),
    ]);
  });

  it('refuses an unknown environment', () => {
    expect(problemsWith({ ...LOCAL, AGENTX_ENV: 'prod' })).toEqual([
      'AGENTX_ENV: must be one of: development, test, staging, production',
    ]);
  });

  it.each([
    'AGENTX_ENV',
    'AGENTX_RELEASE',
    'AGENTX_LOG_LEVEL',
    'AGENTX_LOG_EVENT_CAP_PER_MINUTE',
    'AGENTX_HTTP_HOST',
    'AGENTX_HTTP_PORT',
    'AGENTX_PUBLIC_ORIGIN',
    'AGENTX_TRUSTED_PROXIES',
    'AGENTX_RATE_LIMIT_PER_MINUTE',
    'AGENTX_OUTBOUND_ALLOWED_ORIGINS',
    'AGENTX_PAYEE_COOLING_OFF_HOURS',
    'AGENTX_AUDIT_ANCHOR_SECONDS',
    'AGENTX_KEYS_DIR',
    'AGENTX_KEYS_CURRENT',
    'AGENTX_DB_HOST',
    'AGENTX_DB_PORT',
    'AGENTX_DB_NAME',
    'AGENTX_DB_TLS',
    'AGENTX_DB_USER',
    'AGENTX_DB_POOL_MAX',
  ])('refuses %s set to an empty value', (name) => {
    expect(problemsWith({ ...MINIMAL, [name]: '' })).toEqual([
      `${name}: is empty: give it a value, or remove it to use the default`,
    ]);
  });

  it('refuses a misspelt AGENTX_ variable instead of silently ignoring it', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_PAYEE_COOLING_OF_HOURS: '48' })).toEqual([
      'AGENTX_PAYEE_COOLING_OF_HOURS is not a setting the app knows; check the spelling and the capitals',
    ]);
  });

  it.each(['agentx_payee_cooling_off_hours', 'Agentx_Payee_Cooling_Off_Hours'])(
    'refuses %s, a setting in the wrong case, instead of silently using the default',
    (name) => {
      expect(problemsWith({ ...MINIMAL, [name]: '168' })).toEqual([
        `${name} is not a setting the app knows; check the spelling and the capitals`,
      ]);
    },
  );

  describe("the app's keys (ADR-011 §2)", () => {
    it.each(['development', 'test', 'staging', 'production'])('needs to know where they are in %s', (environment) => {
      const { AGENTX_KEYS_DIR: _keys, ...withoutKeys } = MINIMAL;
      expect(problemsWith({ ...withoutKeys, AGENTX_ENV: environment })).toEqual(['AGENTX_KEYS_DIR: is required']);
    });

    it.each(['secrets', './secrets', 'mnt/secrets'])(
      'refuses %s, a folder named relative to where the app started',
      (folder) => {
        expect(problemsWith({ ...MINIMAL, AGENTX_KEYS_DIR: folder })).toEqual([
          'AGENTX_KEYS_DIR: must be an absolute path, such as /mnt/secrets',
        ]);
      },
    );

    it.each([
      ['a purpose alone', 'audit-mac'],
      ['version 0', 'audit-mac:0'],
      ['a leading zero', 'audit-mac:02'],
      ['a v before the version', 'audit-mac:v2'],
      ['a space', 'audit-mac: 2'],
      ['a purpose the app has no key for', 'api-token:2'],
      ['a trailing comma', 'audit-mac:2,'],
      ['an equals sign', 'audit-mac=2'],
    ])("refuses a key's current version written with %s", (_what, value) => {
      const problems = problemsWith({ ...MINIMAL, AGENTX_KEYS_CURRENT: `request-hash:2,${value}` });
      expect(problems).toEqual([
        expect.stringMatching(
          /^AGENTX_KEYS_CURRENT: entry [23] is not a key's current version\. Write each as <purpose>:<version>, /,
        ),
      ]);
    });

    it('names every purpose it knows, so the operator can see the right spelling', () => {
      expect(problemsWith({ ...MINIMAL, AGENTX_KEYS_CURRENT: 'audit:2' })).toEqual([
        "AGENTX_KEYS_CURRENT: entry 1 is not a key's current version. Write each as <purpose>:<version>, " +
          'the purpose one of agent-key-pepper, request-hash, audit-mac, payee-index, field-encryption, audit-anchor ' +
          'and the version a whole number from 1, comma-separated with no spaces',
      ]);
    });

    it('refuses one key given two current versions', () => {
      expect(problemsWith({ ...MINIMAL, AGENTX_KEYS_CURRENT: 'audit-mac:2,request-hash:2,audit-mac:3' })).toEqual([
        'AGENTX_KEYS_CURRENT: names a key more than once: give each key one current version',
      ]);
    });
  });

  describe('the audit anchor check, every 1 to 60 minutes (ADR-012 §2)', () => {
    it.each([
      ['60', 60],
      ['3600', 3600],
    ])('accepts %s seconds', (seconds, expected) => {
      expect(loadConfig({ ...MINIMAL, AGENTX_AUDIT_ANCHOR_SECONDS: seconds }).audit.anchorSeconds).toBe(expected);
    });

    it('refuses more often than once a minute', () => {
      expect(problemsWith({ ...MINIMAL, AGENTX_AUDIT_ANCHOR_SECONDS: '59' })).toEqual([
        'AGENTX_AUDIT_ANCHOR_SECONDS: must be at least 60 seconds (more often only repeats the whole check of every chain)',
      ]);
    });

    it('refuses less often than once an hour, which would leave a rollback unseen for longer', () => {
      expect(problemsWith({ ...MINIMAL, AGENTX_AUDIT_ANCHOR_SECONDS: '3601' })).toEqual([
        'AGENTX_AUDIT_ANCHOR_SECONDS: must be at most 3600 seconds',
      ]);
    });
  });

  describe('payee cooling-off (ADR-012 safety minimum: 24 hours)', () => {
    it.each(['0', '23'])('refuses %s hours, below the minimum', (hours) => {
      expect(problemsWith({ ...MINIMAL, AGENTX_PAYEE_COOLING_OFF_HOURS: hours })).toEqual([
        'AGENTX_PAYEE_COOLING_OFF_HOURS: must be at least 24 hours (the ADR-012 safety minimum for payee changes)',
      ]);
    });

    it.each([
      ['24', 24],
      ['0024', 24],
      ['8760', 8760],
    ])('accepts %s hours', (hours, expected) => {
      expect(loadConfig({ ...MINIMAL, AGENTX_PAYEE_COOLING_OFF_HOURS: hours }).payees.coolingOffHours).toBe(expected);
    });

    it.each([
      ['8761', '8761'],
      ['a 400-digit number, which overflows', '9'.repeat(400)],
    ])('refuses %s: more than a year is almost certainly a typo', (_what, hours) => {
      expect(problemsWith({ ...MINIMAL, AGENTX_PAYEE_COOLING_OFF_HOURS: hours })).toEqual([
        'AGENTX_PAYEE_COOLING_OFF_HOURS: must be at most 8760 hours',
      ]);
    });

    it.each(['24.5', '2.4e1', '0x18', ' 24', '24 ', '-24', '+24', 'twenty-four'])(
      'refuses %j, which is not a whole number in digits',
      (hours) => {
        expect(problemsWith({ ...MINIMAL, AGENTX_PAYEE_COOLING_OFF_HOURS: hours })).toEqual([
          'AGENTX_PAYEE_COOLING_OFF_HOURS: must be a whole number, written in digits only',
        ]);
      },
    );
  });

  describe('outbound allowlist entries are exact origins', () => {
    it.each([
      ['a bare host name', 'api.partner.example'],
      ['a trailing slash', 'https://api.partner.example/'],
      ['a path', 'https://api.partner.example/v1'],
      ['capital letters', 'https://API.partner.example'],
      ['the default https port', 'https://api.partner.example:443'],
      ['the default http port', 'http://localhost:80'],
      ['a user name and password', 'https://user:pass@api.partner.example'],
      ['a query', 'https://api.partner.example?x=1'],
      ['a fragment', 'https://api.partner.example#top'],
      ['an ftp URL', 'ftp://files.partner.example'],
      ['a websocket URL', 'wss://stream.partner.example'],
      ['a file URL', 'file:///etc/passwd'],
      ['a leading space', ' https://api.partner.example'],
      ['a wildcard, which would never match', 'https://*.partner.example'],
    ])('refuses %s', (_what, entry) => {
      expect(problemsWith({ ...LOCAL, AGENTX_ENV: 'test', AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry })).toEqual([
        expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry 1 is not an origin\./),
      ]);
    });

    it('names every bad entry by its position', () => {
      const entries = 'https://a.example,https://B.example,,https://c.example/';
      expect(problemsWith({ ...LOCAL, AGENTX_ENV: 'test', AGENTX_OUTBOUND_ALLOWED_ORIGINS: entries })).toEqual([
        expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry 2, 3, 4 is not an origin\./),
      ]);
    });

    it.each([
      'https://api.partner.example:8443',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://[::1]:5432',
    ])('accepts %s', (entry) => {
      expect(problemsWith({ ...LOCAL, AGENTX_ENV: 'test', AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry })).toEqual([]);
    });
  });

  it('reports every problem at once, so one start shows them all', () => {
    expect(
      problemsWith({
        AGENTX_ENV: 'live',
        AGENTX_RELEASE: 'has spaces',
        AGENTX_LOG_LEVEL: 'verbose',
        AGENTX_LOG_EVENT_CAP_PER_MINUTE: '5',
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'api.partner.example',
        AGENTX_PAYEE_COOLING_OFF_HOURS: '1',
        AGENTX_KEYS_DIR: 'keys',
        AGENTX_KEYS_CURRENT: 'audit-mac:0',
        AGENTX_LOG_LEVLE: 'debug',
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
      }),
    ).toEqual([
      expect.stringMatching(/^NODE_TLS_REJECT_UNAUTHORIZED: /),
      expect.stringMatching(/^AGENTX_LOG_LEVLE is not a setting/),
      expect.stringMatching(/^AGENTX_ENV: /),
      expect.stringMatching(/^AGENTX_RELEASE: /),
      expect.stringMatching(/^AGENTX_LOG_LEVEL: /),
      expect.stringMatching(/^AGENTX_LOG_EVENT_CAP_PER_MINUTE: /),
      expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: /),
      expect.stringMatching(/^AGENTX_PAYEE_COOLING_OFF_HOURS: /),
      expect.stringMatching(/^AGENTX_KEYS_DIR: /),
      expect.stringMatching(/^AGENTX_KEYS_CURRENT: /),
      expect.stringMatching(/^AGENTX_DB_HOST: is required$/),
      expect.stringMatching(/^AGENTX_DB_PASSWORD is required, or AGENTX_DB_PASSWORD_FILE /),
    ]);
  });

  it('reports a broken rule between settings alongside a problem in another setting', () => {
    expect(
      problemsWith({
        ...MINIMAL,
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://api.partner.example',
        AGENTX_PAYEE_COOLING_OFF_HOURS: '1',
      }),
    ).toEqual([
      expect.stringMatching(/^AGENTX_PAYEE_COOLING_OFF_HOURS: must be at least 24/),
      expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: plain http is allowed only/),
    ]);
  });

  it('reports the database TLS rule alongside a problem in another setting', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_DB_TLS: 'disable', AGENTX_HTTP_PORT: 'eighty' })).toEqual([
      expect.stringMatching(/^AGENTX_HTTP_PORT: must be a whole number/),
      expect.stringMatching(/^AGENTX_DB_TLS: disable is allowed only in development and test; production/),
    ]);
  });

  it('reports every broken rule between settings together', () => {
    expect(
      problemsWith({
        AGENTX_ENV: 'production',
        AGENTX_LOG_LEVEL: 'debug',
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://api.partner.example',
        AGENTX_DB_HOST: DB_HOST,
        AGENTX_DB_PASSWORD: DB_LOGIN,
        AGENTX_KEYS_DIR: KEYS_DIR,
      }),
    ).toEqual([
      expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: plain http/),
      expect.stringMatching(/^AGENTX_RELEASE: is required in production/),
      expect.stringMatching(/^AGENTX_LOG_LEVEL: debug is off in production/),
      expect.stringMatching(/^AGENTX_PUBLIC_ORIGIN: is required in production/),
      expect.stringMatching(/^AGENTX_TRUSTED_PROXIES: is required in production/),
    ]);
  });

  it('puts every problem in the error message, for the operator reading the start-up output', () => {
    expect(() =>
      loadConfig({
        AGENTX_ENV: 'live',
        AGENTX_PAYEE_COOLING_OFF_HOURS: '1',
        AGENTX_DB_HOST: DB_HOST,
        AGENTX_DB_PASSWORD: DB_LOGIN,
        AGENTX_KEYS_DIR: KEYS_DIR,
      }),
    ).toThrow(
      'Refusing to start: 2 config problem(s).\n' +
        '- AGENTX_ENV: must be one of: development, test, staging, production\n' +
        '- AGENTX_PAYEE_COOLING_OFF_HOURS: must be at least 24 hours (the ADR-012 safety minimum for payee changes)',
    );
  });

  it('never repeats a value in a problem, so a secret in the wrong variable does not leak', () => {
    // Plain words and a plain name, so secret scanners don't mistake the test for a leaked key.
    const misplaced = 'value that must never be printed';
    const env: Env = {
      AGENTX_ENV: misplaced,
      AGENTX_RELEASE: misplaced,
      AGENTX_LOG_LEVEL: misplaced,
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: misplaced,
      AGENTX_HTTP_HOST: misplaced,
      AGENTX_HTTP_PORT: misplaced,
      AGENTX_PUBLIC_ORIGIN: misplaced,
      AGENTX_TRUSTED_PROXIES: `10.0.0.1,${misplaced}`,
      AGENTX_RATE_LIMIT_PER_MINUTE: misplaced,
      AGENTX_OUTBOUND_ALLOWED_ORIGINS: `https://api.partner.example,${misplaced}`,
      AGENTX_PAYEE_COOLING_OFF_HOURS: misplaced,
      AGENTX_KEYS_DIR: misplaced,
      AGENTX_KEYS_CURRENT: misplaced,
      AGENTX_DB_HOST: misplaced,
      AGENTX_DB_PORT: misplaced,
      AGENTX_DB_NAME: misplaced,
      AGENTX_DB_TLS: misplaced,
      AGENTX_DB_USER: misplaced,
      AGENTX_DB_PASSWORD: misplaced,
      AGENTX_DB_POOL_MAX: misplaced,
      AGENTX_DB_MIGRATION_PASSWORD: misplaced,
      AGENTX_MISSPELT: misplaced,
      NODE_TLS_REJECT_UNAUTHORIZED: misplaced,
      PGPASSWORD: misplaced,
    };
    const problems = problemsWith(env);
    // Every variable but the app's password, which any text may be. The migration login is refused by name.
    expect(problems).toHaveLength(23);
    expect(problems.filter((problem) => problem.toLowerCase().includes(misplaced))).toEqual([]);
  });
});

describe('SEC-AV-03 release: every deployed build is named', () => {
  it.each(['staging', 'production'])('refuses %s without a release', (environment) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_ENV: environment, AGENTX_RELEASE: undefined })).toEqual([
      `AGENTX_RELEASE: is required in ${environment}, so every log line and error names the build that ran`,
    ]);
  });

  it.each(['development', 'test'])('names a %s run without a release "local"', (environment) => {
    expect(loadConfig({ ...LOCAL, AGENTX_ENV: environment }).release).toBe('local');
  });

  it.each(['v1.2.3', '2026.09.14-a1b2c3d', 'a1b2c3d4e5f6', 'build_17', 'a'.repeat(64)])(
    'accepts the release %j',
    (release) => {
      expect(loadConfig({ ...MINIMAL, AGENTX_RELEASE: release }).release).toBe(release);
    },
  );

  it.each([
    ['a space', 'v1 2'],
    ['a slash', 'feature/x'],
    ['a leading dash', '-v1'],
    ['a leading dot', '.v1'],
    ['65 characters', 'a'.repeat(65)],
  ])('refuses a release with %s', (_what, release) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_RELEASE: release })).toEqual([
      'AGENTX_RELEASE: must be 1 to 64 letters, digits, dots, dashes or underscores, starting with a letter or digit',
    ]);
  });
});

describe('SEC-AV-03 logging settings', () => {
  it.each(['error', 'warn', 'info'])('accepts the log level %s in production', (level) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_LOG_LEVEL: level }).log.level).toBe(level);
  });

  it.each(['development', 'test', 'staging'])('accepts debug in %s', (environment) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_ENV: environment, AGENTX_LOG_LEVEL: 'debug' }).log.level).toBe('debug');
  });

  it('refuses debug in production, where lines could carry more detail than needed', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_LOG_LEVEL: 'debug' })).toEqual([
      'AGENTX_LOG_LEVEL: debug is off in production; use info, warn or error',
    ]);
  });

  it.each(['verbose', 'INFO', 'trace', 'fatal'])('refuses the log level %j', (level) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_LOG_LEVEL: level })).toEqual([
      'AGENTX_LOG_LEVEL: must be one of: error, warn, info, debug',
    ]);
  });

  it.each([
    // The smallest pair that works: the rate limit's minimum is 10, and it must be at most half the cap.
    ['20', 20],
    ['600', 600],
    ['1000000', 1_000_000],
  ])('accepts an event cap of %s lines a minute', (cap, expected) => {
    const env = { ...MINIMAL, AGENTX_LOG_EVENT_CAP_PER_MINUTE: cap, AGENTX_RATE_LIMIT_PER_MINUTE: '10' };
    expect(loadConfig(env).log.eventCapPerMinute).toBe(expected);
  });

  it('refuses an event cap below 10, which would hide ordinary activity', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_LOG_EVENT_CAP_PER_MINUTE: '9' })).toEqual([
      'AGENTX_LOG_EVENT_CAP_PER_MINUTE: must be at least 10 lines (fewer would hide ordinary activity)',
    ]);
  });

  it.each(['1000001', '1e6', 'lots'])('refuses the event cap %j', (cap) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_LOG_EVENT_CAP_PER_MINUTE: cap })).toHaveLength(1);
  });
});

describe('SEC-DATA-01 Node’s own debug output is off in production', () => {
  it('refuses NODE_DEBUG in production even when empty: unset means unset', () => {
    expect(problemsWith({ ...MINIMAL, NODE_DEBUG: '' })).toEqual([
      'NODE_DEBUG: must be unset in production; Node would print its own debug output outside the logger',
    ]);
  });

  it.each(['NODE_DEBUG', 'NODE_DEBUG_NATIVE'])('refuses %s in production, as it prints outside the logger', (name) => {
    expect(problemsWith({ ...MINIMAL, [name]: 'fetch' })).toEqual([
      `${name}: must be unset in production; Node would print its own debug output outside the logger`,
    ]);
  });

  it.each(['development', 'test', 'staging'])('allows NODE_DEBUG in %s, for troubleshooting', (environment) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_ENV: environment, NODE_DEBUG: 'fetch' })).toEqual([]);
  });
});

describe('SEC-AV-03 cross-field rule: plain http only where nothing real is at stake', () => {
  it.each(['staging', 'production'])('refuses a plain http origin in %s', (environment) => {
    expect(
      problemsWith({
        ...MINIMAL,
        AGENTX_ENV: environment,
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example,http://api.partner.example',
      }),
    ).toEqual([
      `AGENTX_OUTBOUND_ALLOWED_ORIGINS: plain http is allowed only in development and test; ${environment} must use https`,
    ]);
  });

  it.each(['development', 'test'])('accepts a plain http origin in %s, for the local stack', (environment) => {
    expect(
      problemsWith({ ...LOCAL, AGENTX_ENV: environment, AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://localhost:8080' }),
    ).toEqual([]);
  });

  it('accepts https origins in production', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example' })).toEqual([]);
  });
});

describe('SEC-WEB-01 the public origin: the one address browser writes are accepted from', () => {
  it.each(['staging', 'production'])('is required in %s', (environment) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_ENV: environment, AGENTX_PUBLIC_ORIGIN: undefined })).toEqual([
      `AGENTX_PUBLIC_ORIGIN: is required in ${environment}; browser writes are accepted only from it`,
    ]);
  });

  it.each(['development', 'test'])('is the local address in %s, when not set', (environment) => {
    expect(loadConfig({ ...LOCAL, AGENTX_ENV: environment }).http.publicOrigin).toBe('http://localhost:8080');
  });

  it.each(['https://app.agentx.example', 'https://app.agentx.example:8443'])('accepts %s', (origin) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_PUBLIC_ORIGIN: origin }).http.publicOrigin).toBe(origin);
  });

  it.each([
    ['a bare host name', 'app.agentx.example'],
    ['a trailing slash', 'https://app.agentx.example/'],
    ['a path', 'https://app.agentx.example/console'],
    ['capital letters', 'https://App.agentx.example'],
    ['the default port', 'https://app.agentx.example:443'],
    ['a user name', 'https://someone@app.agentx.example'],
    ['two origins', 'https://app.agentx.example,https://other.example'],
    ['a websocket URL', 'wss://app.agentx.example'],
  ])('refuses %s', (_what, origin) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_PUBLIC_ORIGIN: origin })).toEqual([
      'AGENTX_PUBLIC_ORIGIN: is not an origin. Write it as scheme://host[:port]: ' +
        'http or https, lowercase, no default port, no path, no user name',
    ]);
  });

  it.each(['staging', 'production'])('refuses plain http in %s', (environment) => {
    expect(
      problemsWith({ ...MINIMAL, AGENTX_ENV: environment, AGENTX_PUBLIC_ORIGIN: 'http://app.agentx.example' }),
    ).toEqual([
      `AGENTX_PUBLIC_ORIGIN: plain http is allowed only in development and test; ${environment} must use https`,
    ]);
  });

  it.each(['development', 'test'])('accepts plain http in %s, for the local stack', (environment) => {
    expect(problemsWith({ ...LOCAL, AGENTX_ENV: environment, AGENTX_PUBLIC_ORIGIN: 'http://localhost:3000' })).toEqual(
      [],
    );
  });
});

describe('SEC-AV-03 where the API listens', () => {
  it.each(['127.0.0.1', '0.0.0.0', '::', '::1'])('accepts the address %s', (host) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_HTTP_HOST: host }).http.host).toBe(host);
  });

  it.each(['localhost', 'api.agentx.example', '256.0.0.1', '0.0.0.0:8080', ' 127.0.0.1'])(
    'refuses %j, which is not an IP address',
    (host) => {
      expect(problemsWith({ ...MINIMAL, AGENTX_HTTP_HOST: host })).toEqual([
        'AGENTX_HTTP_HOST: must be an IP address, such as 127.0.0.1 or 0.0.0.0, not a host name',
      ]);
    },
  );

  it.each([
    ['1', 1],
    ['8080', 8080],
    ['65535', 65_535],
  ])('accepts the port %s', (value, expected) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_HTTP_PORT: value }).http.port).toBe(expected);
  });

  it.each([
    ['65536', 'AGENTX_HTTP_PORT: must be at most 65535'],
    ['9'.repeat(400), 'AGENTX_HTTP_PORT: must be at most 65535'],
    ['80a', 'AGENTX_HTTP_PORT: must be a whole number, written in digits only'],
    ['-1', 'AGENTX_HTTP_PORT: must be a whole number, written in digits only'],
    [' 80', 'AGENTX_HTTP_PORT: must be a whole number, written in digits only'],
  ])('refuses the port %j', (value, problem) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_HTTP_PORT: value })).toEqual([problem]);
  });

  it.each(['development', 'test'])('accepts port 0 (any free port) in %s, for tests', (environment) => {
    expect(loadConfig({ ...LOCAL, AGENTX_ENV: environment, AGENTX_HTTP_PORT: '0' }).http.port).toBe(0);
  });

  it.each(['staging', 'production'])('refuses port 0 in %s, where the ingress needs a known port', (environment) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_ENV: environment, AGENTX_HTTP_PORT: '0' })).toEqual([
      `AGENTX_HTTP_PORT: 0 (any free port) is allowed only in development and test; ${environment} must name its port`,
    ]);
  });
});

describe('SEC-AV-07 trusted proxies are addresses or narrow ranges', () => {
  it.each([
    ['an IPv4 address', '10.0.0.1'],
    ['an Azure-sized IPv4 range', '10.0.0.0/23'],
    ['the widest IPv4 range allowed', '10.1.0.0/16'],
    ['an IPv6 address', '2001:db8::1'],
    ['the widest IPv6 range allowed', '2001:db8:1::/48'],
    ['an IPv6 range written in full', '2001:0db8:0001:0000:0000:0000:0000:0000/64'],
    ['an IPv4-mapped address, which is one IPv4 address', '::ffff:10.0.0.1'],
    ['a NAT64 range, outside the mapped block', '64:ff9b::/96'],
    ['a range whose groups before `::` look like the mapped block, elsewhere', '2001:db8:0:0:0:ffff::/96'],
    ['an IPv6 range whose last groups hold a dotted IPv4 address', '2001:db8:1:2::10.0.0.0/120'],
  ])('accepts %s', (_what, entry) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_TRUSTED_PROXIES: entry }).http.trustedProxies).toEqual([entry]);
  });

  it.each([
    ['a host name', 'ingress.agentx.example'],
    ['every IPv4 address', '0.0.0.0/0'],
    ['every IPv6 address', '::/0'],
    ['every IPv4 address, as two halves', '0.0.0.0/1,128.0.0.0/1'],
    ['every IPv6 address, as two halves', '8000::/1,::/1'],
    ['an IPv4 range wider than /16', '10.0.0.0/15'],
    ['an IPv6 range wider than /48', '2001:db8::/47'],
    ['the IPv4-mapped block, which trusts every IPv4 client', '::ffff:0:0/96'],
    ['the mapped block written in full', '0:0:0:0:0:ffff:0:0/96'],
    ['the mapped block with its zeros last', '0:0:0:0:0:ffff::/96'],
    ['an IPv4 range in mapped form', '::ffff:10.0.0.0/120'],
    ['an IPv4 range in mapped form, written in hex', '::ffff:a00:0/120'],
    ['a range that holds the mapped block', '::/64'],
    ['a range too wide to exist', '10.0.0.0/33'],
    ['a space after a comma', '10.0.0.1, 10.0.0.2'],
    ['an empty entry', '10.0.0.1,,10.0.0.2'],
    ['a port', '10.0.0.1:443'],
  ])('refuses %s', (_what, entries) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_TRUSTED_PROXIES: entries })).toEqual([
      expect.stringMatching(/^AGENTX_TRUSTED_PROXIES: entry [\d, ]+ is not a proxy address\./),
    ]);
  });

  it('names every bad entry by its position', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_TRUSTED_PROXIES: '10.0.0.1,proxy,10.0.0.0/16,::/0' })).toEqual([
      'AGENTX_TRUSTED_PROXIES: entry 2, 4 is not a proxy address. Write each as an IP address or a CIDR range ' +
        'no wider than /16 (IPv4) or /48 (IPv6), with IPv4 ranges in IPv4 form, comma-separated with no spaces',
    ]);
  });

  it.each(['staging', 'production'])('is required in %s, where a TLS proxy is always in front', (environment) => {
    expect(problemsWith({ ...MINIMAL, AGENTX_ENV: environment, AGENTX_TRUSTED_PROXIES: undefined })).toEqual([
      `AGENTX_TRUSTED_PROXIES: is required in ${environment}; without the TLS proxy's address, ` +
        'every client would share one rate limit',
    ]);
  });

  it.each(['development', 'test'])('is optional in %s, where the app is reached directly', (environment) => {
    expect(loadConfig({ ...LOCAL, AGENTX_ENV: environment }).http.trustedProxies).toEqual([]);
  });
});

describe('SEC-AV-03 the rate limit per client address', () => {
  it.each([
    ['10', 10],
    ['300', 300],
  ])('accepts %s requests a minute (300 is half the default log cap)', (value, expected) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_RATE_LIMIT_PER_MINUTE: value }).http.rateLimitPerMinute).toBe(expected);
  });

  it('accepts 100000, with a log cap above it', () => {
    const config = loadConfig({
      ...MINIMAL,
      AGENTX_RATE_LIMIT_PER_MINUTE: '100000',
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: '200000',
    });
    expect(config.http.rateLimitPerMinute).toBe(100_000);
  });

  it.each([
    ['one over half the default log cap', '301', '600'],
    ['equal to the default log cap', '600', '600'],
    ['over half a raised log cap', '501', '1000'],
  ])("refuses a limit %s: one client's requests could fill the request log (ADR-012 §9)", (_what, limit, cap) => {
    const env = { ...MINIMAL, AGENTX_LOG_EVENT_CAP_PER_MINUTE: cap, AGENTX_RATE_LIMIT_PER_MINUTE: limit };
    expect(problemsWith(env)).toEqual([
      `AGENTX_RATE_LIMIT_PER_MINUTE: must be at most half of AGENTX_LOG_EVENT_CAP_PER_MINUTE (${cap}), ` +
        "so one client's requests can't fill the request log on their own",
    ]);
  });

  it('refuses fewer than 10, which would stop ordinary use of the console', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_RATE_LIMIT_PER_MINUTE: '9' })).toEqual([
      'AGENTX_RATE_LIMIT_PER_MINUTE: must be at least 10 requests (fewer would stop ordinary use of the console)',
    ]);
  });

  it('refuses more than 100000', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_RATE_LIMIT_PER_MINUTE: '100001' })).toEqual([
      'AGENTX_RATE_LIMIT_PER_MINUTE: must be at most 100000 requests',
    ]);
  });
});

describe('SEC-PTR-07 config refuses to turn off TLS certificate checks', () => {
  it('refuses NODE_TLS_REJECT_UNAUTHORIZED=0, which turns them off for every connection', () => {
    expect(problemsWith({ ...MINIMAL, NODE_TLS_REJECT_UNAUTHORIZED: '0' })).toEqual([
      'NODE_TLS_REJECT_UNAUTHORIZED: must be unset (or 1); 0 turns off TLS certificate checks for every connection',
    ]);
  });

  it.each(['false', 'no', '', '00'])('refuses NODE_TLS_REJECT_UNAUTHORIZED=%j too', (value) => {
    expect(problemsWith({ ...MINIMAL, NODE_TLS_REJECT_UNAUTHORIZED: value })).toHaveLength(1);
  });

  it('accepts it unset, or set to 1 (checks on)', () => {
    expect(problemsWith(MINIMAL)).toEqual([]);
    expect(problemsWith({ ...MINIMAL, NODE_TLS_REJECT_UNAUTHORIZED: '1' })).toEqual([]);
  });
});
