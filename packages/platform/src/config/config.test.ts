import { describe, expect, it } from 'vitest';

import { ConfigError, loadConfig } from './config.ts';

type Env = Record<string, string | undefined>;

const RELEASE = '2026.09.14-a1b2c3d';
const MINIMAL: Env = { AGENTX_ENV: 'production', AGENTX_RELEASE: RELEASE };

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
  it('needs only the environment and the release, and fills in the defaults', () => {
    expect(loadConfig(MINIMAL)).toEqual({
      environment: 'production',
      release: RELEASE,
      log: { level: 'info', eventCapPerMinute: 600 },
      outbound: { allowedOrigins: [] },
      payees: { coolingOffHours: 24 },
    });
  });

  it.each(['development', 'test', 'staging', 'production'])('accepts the %s environment', (environment) => {
    expect(loadConfig({ AGENTX_ENV: environment, AGENTX_RELEASE: RELEASE }).environment).toBe(environment);
  });

  it('reads every setting, sorting the allowlist and dropping repeats', () => {
    const config = loadConfig({
      AGENTX_ENV: 'staging',
      AGENTX_RELEASE: RELEASE,
      AGENTX_LOG_LEVEL: 'warn',
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: '1200',
      AGENTX_OUTBOUND_ALLOWED_ORIGINS:
        'https://telemetry.example,https://api.partner.example:8443,https://telemetry.example',
      AGENTX_PAYEE_COOLING_OFF_HOURS: '48',
    });
    expect(config).toEqual({
      environment: 'staging',
      release: RELEASE,
      log: { level: 'warn', eventCapPerMinute: 1200 },
      outbound: { allowedOrigins: ['https://api.partner.example:8443', 'https://telemetry.example'] },
      payees: { coolingOffHours: 48 },
    });
  });

  it('ignores variables that are not AGENTX_ settings', () => {
    expect(problemsWith({ ...MINIMAL, PATH: '/usr/bin', NODE_ENV: 'production', AGENT_X: 'x' })).toEqual([]);
  });

  it('returns a config nothing can change afterwards', () => {
    const config = loadConfig({ ...MINIMAL, AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example' });
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.log)).toBe(true);
    expect(Object.isFrozen(config.outbound)).toBe(true);
    expect(Object.isFrozen(config.outbound.allowedOrigins)).toBe(true);
    expect(Object.isFrozen(config.payees)).toBe(true);
    expect(() => (config.outbound.allowedOrigins as string[]).push('https://evil.example')).toThrow(TypeError);
  });
});

describe('SEC-AV-03 config refuses to start when a setting is wrong', () => {
  it('refuses a missing environment: the app must know if it is in production', () => {
    expect(problemsWith({})).toEqual(['AGENTX_ENV: is required']);
  });

  it('refuses an unknown environment', () => {
    expect(problemsWith({ AGENTX_ENV: 'prod' })).toEqual([
      'AGENTX_ENV: must be one of: development, test, staging, production',
    ]);
  });

  it.each([
    'AGENTX_ENV',
    'AGENTX_RELEASE',
    'AGENTX_LOG_LEVEL',
    'AGENTX_LOG_EVENT_CAP_PER_MINUTE',
    'AGENTX_OUTBOUND_ALLOWED_ORIGINS',
    'AGENTX_PAYEE_COOLING_OFF_HOURS',
  ])('refuses %s set to an empty value', (name) => {
    expect(problemsWith({ ...MINIMAL, [name]: '' })).toEqual([
      `${name}: is empty: give it a value, or remove it to use the default`,
    ]);
  });

  it('refuses a misspelt AGENTX_ variable instead of silently ignoring it', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_PAYEE_COOLING_OF_HOURS: '48' })).toEqual([
      'AGENTX_PAYEE_COOLING_OF_HOURS: not a setting the app knows; check the spelling and the capitals',
    ]);
  });

  it.each(['agentx_payee_cooling_off_hours', 'Agentx_Payee_Cooling_Off_Hours'])(
    'refuses %s, a setting in the wrong case, instead of silently using the default',
    (name) => {
      expect(problemsWith({ ...MINIMAL, [name]: '168' })).toEqual([
        `${name}: not a setting the app knows; check the spelling and the capitals`,
      ]);
    },
  );

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
      expect(problemsWith({ AGENTX_ENV: 'test', AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry })).toEqual([
        expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry 1 is not an origin\./),
      ]);
    });

    it('names every bad entry by its position', () => {
      const entries = 'https://a.example,https://B.example,,https://c.example/';
      expect(problemsWith({ AGENTX_ENV: 'test', AGENTX_OUTBOUND_ALLOWED_ORIGINS: entries })).toEqual([
        expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry 2, 3, 4 is not an origin\./),
      ]);
    });

    it.each([
      'https://api.partner.example:8443',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://[::1]:5432',
    ])('accepts %s', (entry) => {
      expect(problemsWith({ AGENTX_ENV: 'test', AGENTX_OUTBOUND_ALLOWED_ORIGINS: entry })).toEqual([]);
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
        AGENTX_LOG_LEVLE: 'debug',
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
      }),
    ).toEqual([
      expect.stringMatching(/^NODE_TLS_REJECT_UNAUTHORIZED: /),
      expect.stringMatching(/^AGENTX_LOG_LEVLE: /),
      expect.stringMatching(/^AGENTX_ENV: /),
      expect.stringMatching(/^AGENTX_RELEASE: /),
      expect.stringMatching(/^AGENTX_LOG_LEVEL: /),
      expect.stringMatching(/^AGENTX_LOG_EVENT_CAP_PER_MINUTE: /),
      expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: /),
      expect.stringMatching(/^AGENTX_PAYEE_COOLING_OFF_HOURS: /),
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

  it('reports every broken rule between settings together', () => {
    expect(
      problemsWith({
        AGENTX_ENV: 'production',
        AGENTX_LOG_LEVEL: 'debug',
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://api.partner.example',
      }),
    ).toEqual([
      expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: plain http/),
      expect.stringMatching(/^AGENTX_RELEASE: is required in production/),
      expect.stringMatching(/^AGENTX_LOG_LEVEL: debug is off in production/),
    ]);
  });

  it('puts every problem in the error message, for the operator reading the start-up output', () => {
    expect(() => loadConfig({ AGENTX_ENV: 'live', AGENTX_PAYEE_COOLING_OFF_HOURS: '1' })).toThrow(
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
      AGENTX_OUTBOUND_ALLOWED_ORIGINS: `https://api.partner.example,${misplaced}`,
      AGENTX_PAYEE_COOLING_OFF_HOURS: misplaced,
      AGENTX_MISSPELT: misplaced,
      NODE_TLS_REJECT_UNAUTHORIZED: misplaced,
    };
    const problems = problemsWith(env);
    expect(problems).toHaveLength(8);
    expect(problems.filter((problem) => problem.toLowerCase().includes(misplaced))).toEqual([]);
  });
});

describe('SEC-AV-03 release: every deployed build is named', () => {
  it.each(['staging', 'production'])('refuses %s without a release', (environment) => {
    expect(problemsWith({ AGENTX_ENV: environment })).toEqual([
      `AGENTX_RELEASE: is required in ${environment}, so every log line and error names the build that ran`,
    ]);
  });

  it.each(['development', 'test'])('names a %s run without a release "local"', (environment) => {
    expect(loadConfig({ AGENTX_ENV: environment }).release).toBe('local');
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
    expect(loadConfig({ AGENTX_ENV: environment, AGENTX_RELEASE: RELEASE, AGENTX_LOG_LEVEL: 'debug' }).log.level).toBe(
      'debug',
    );
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
    ['10', 10],
    ['600', 600],
    ['1000000', 1_000_000],
  ])('accepts an event cap of %s lines a minute', (cap, expected) => {
    expect(loadConfig({ ...MINIMAL, AGENTX_LOG_EVENT_CAP_PER_MINUTE: cap }).log.eventCapPerMinute).toBe(expected);
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
  it.each(['NODE_DEBUG', 'NODE_DEBUG_NATIVE'])('refuses %s in production, as it prints outside the logger', (name) => {
    expect(problemsWith({ ...MINIMAL, [name]: 'fetch' })).toEqual([
      `${name}: must be unset in production; Node would print its own debug output outside the logger`,
    ]);
  });

  it.each(['development', 'test', 'staging'])('allows NODE_DEBUG in %s, for troubleshooting', (environment) => {
    expect(problemsWith({ AGENTX_ENV: environment, AGENTX_RELEASE: RELEASE, NODE_DEBUG: 'fetch' })).toEqual([]);
  });
});

describe('SEC-AV-03 cross-field rule: plain http only where nothing real is at stake', () => {
  it.each(['staging', 'production'])('refuses a plain http origin in %s', (environment) => {
    expect(
      problemsWith({
        AGENTX_ENV: environment,
        AGENTX_RELEASE: RELEASE,
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example,http://api.partner.example',
      }),
    ).toEqual([
      `AGENTX_OUTBOUND_ALLOWED_ORIGINS: plain http is allowed only in development and test; ${environment} must use https`,
    ]);
  });

  it.each(['development', 'test'])('accepts a plain http origin in %s, for the local stack', (environment) => {
    expect(problemsWith({ AGENTX_ENV: environment, AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://localhost:8080' })).toEqual(
      [],
    );
  });

  it('accepts https origins in production', () => {
    expect(problemsWith({ ...MINIMAL, AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example' })).toEqual([]);
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
