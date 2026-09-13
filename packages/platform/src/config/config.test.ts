import { describe, expect, it } from 'vitest';

import { ConfigError, loadConfig } from './config.ts';

type Env = Record<string, string | undefined>;

const MINIMAL: Env = { AGENTX_ENV: 'production' };

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
  it('needs only the environment, and fills in the defaults', () => {
    expect(loadConfig(MINIMAL)).toEqual({
      environment: 'production',
      outbound: { allowedOrigins: [] },
      payees: { coolingOffHours: 24 },
    });
  });

  it.each(['development', 'test', 'staging', 'production'])('accepts the %s environment', (environment) => {
    expect(loadConfig({ AGENTX_ENV: environment }).environment).toBe(environment);
  });

  it('reads every setting, sorting the allowlist and dropping repeats', () => {
    const config = loadConfig({
      AGENTX_ENV: 'staging',
      AGENTX_OUTBOUND_ALLOWED_ORIGINS:
        'https://telemetry.example,https://api.partner.example:8443,https://telemetry.example',
      AGENTX_PAYEE_COOLING_OFF_HOURS: '48',
    });
    expect(config).toEqual({
      environment: 'staging',
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

  it.each(['AGENTX_ENV', 'AGENTX_OUTBOUND_ALLOWED_ORIGINS', 'AGENTX_PAYEE_COOLING_OFF_HOURS'])(
    'refuses %s set to an empty value',
    (name) => {
      expect(problemsWith({ ...MINIMAL, [name]: '' })).toEqual([
        `${name}: is empty: give it a value, or remove it to use the default`,
      ]);
    },
  );

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
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'api.partner.example',
        AGENTX_PAYEE_COOLING_OFF_HOURS: '1',
        AGENTX_LOG_LEVLE: 'debug',
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
      }),
    ).toEqual([
      expect.stringMatching(/^NODE_TLS_REJECT_UNAUTHORIZED: /),
      expect.stringMatching(/^AGENTX_LOG_LEVLE: /),
      expect.stringMatching(/^AGENTX_ENV: /),
      expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: /),
      expect.stringMatching(/^AGENTX_PAYEE_COOLING_OFF_HOURS: /),
    ]);
  });

  it('reports a broken rule between settings alongside a problem in another setting', () => {
    expect(
      problemsWith({
        AGENTX_ENV: 'production',
        AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'http://api.partner.example',
        AGENTX_PAYEE_COOLING_OFF_HOURS: '1',
      }),
    ).toEqual([
      expect.stringMatching(/^AGENTX_PAYEE_COOLING_OFF_HOURS: must be at least 24/),
      expect.stringMatching(/^AGENTX_OUTBOUND_ALLOWED_ORIGINS: plain http is allowed only/),
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
    const misplaced = 'value-that-must-never-be-printed';
    const env: Env = {
      AGENTX_ENV: misplaced,
      AGENTX_OUTBOUND_ALLOWED_ORIGINS: `https://api.partner.example,${misplaced}`,
      AGENTX_PAYEE_COOLING_OFF_HOURS: misplaced,
      AGENTX_MISSPELT: misplaced,
      NODE_TLS_REJECT_UNAUTHORIZED: misplaced,
    };
    const problems = problemsWith(env);
    expect(problems).toHaveLength(5);
    expect(problems.filter((problem) => problem.toLowerCase().includes(misplaced))).toEqual([]);
  });
});

describe('SEC-AV-03 cross-field rule: plain http only where nothing real is at stake', () => {
  it.each(['staging', 'production'])('refuses a plain http origin in %s', (environment) => {
    expect(
      problemsWith({
        AGENTX_ENV: environment,
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
    expect(
      problemsWith({ AGENTX_ENV: 'production', AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://api.partner.example' }),
    ).toEqual([]);
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
