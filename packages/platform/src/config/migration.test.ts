import { describe, expect, it } from 'vitest';

import { ConfigError } from './common.ts';
import { loadMigrationConfig } from './migration.ts';

type Env = Record<string, string | undefined>;

/** Plain words, so secret scanners ignore it. */
const OWNER_LOGIN = 'owner login for these tests';
const LOCAL: Env = { AGENTX_ENV: 'development', AGENTX_DB_HOST: 'db', AGENTX_DB_MIGRATION_PASSWORD: OWNER_LOGIN };
const DEPLOYED: Env = {
  AGENTX_ENV: 'production',
  AGENTX_RELEASE: 'r-1',
  AGENTX_DB_HOST: 'db.internal.example',
  AGENTX_DB_MIGRATION_PASSWORD: OWNER_LOGIN,
};

function problemsWith(env: Env): readonly string[] {
  try {
    loadMigrationConfig(env);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
}

describe('the migration job config loads', () => {
  it('needs only the environment, the host and the login, and fills in the defaults', () => {
    expect(loadMigrationConfig(LOCAL)).toEqual({
      environment: 'development',
      release: 'local',
      log: { level: 'info', eventCapPerMinute: 600 },
      db: {
        host: 'db',
        port: 5432,
        database: 'agentx',
        user: 'agentx_owner',
        password: OWNER_LOGIN,
        tls: 'verify-full',
      },
    });
  });

  it('reads every setting', () => {
    expect(
      loadMigrationConfig({
        AGENTX_ENV: 'test',
        AGENTX_RELEASE: 'r-2',
        AGENTX_LOG_LEVEL: 'warn',
        AGENTX_LOG_EVENT_CAP_PER_MINUTE: '1200',
        AGENTX_DB_HOST: '10.0.0.5',
        AGENTX_DB_PORT: '6432',
        AGENTX_DB_NAME: 'agentx_uae',
        AGENTX_DB_TLS: 'disable',
        AGENTX_DB_MIGRATION_USER: 'agentx_owner_uae',
        AGENTX_DB_MIGRATION_PASSWORD: OWNER_LOGIN,
      }),
    ).toEqual({
      environment: 'test',
      release: 'r-2',
      log: { level: 'warn', eventCapPerMinute: 1200 },
      db: {
        host: '10.0.0.5',
        port: 6432,
        database: 'agentx_uae',
        user: 'agentx_owner_uae',
        password: OWNER_LOGIN,
        tls: 'disable',
      },
    });
  });

  it('returns a config nothing can change afterwards', () => {
    const config = loadMigrationConfig(DEPLOYED);
    expect([config, config.log, config.db].map((part) => Object.isFrozen(part))).toEqual([true, true, true]);
  });

  it('ignores variables that are not AGENTX_ or PG settings', () => {
    expect(problemsWith({ ...DEPLOYED, PATH: '/usr/bin', HOME: '/home/app', pghost: 'x' })).toEqual([]);
  });
});

describe('SEC-AV-03 the migration job refuses to start on a bad config', () => {
  it('reports every problem at once, in the same order the app uses', () => {
    expect(
      problemsWith({
        AGENTX_ENV: 'live',
        AGENTX_RELEASE: 'has spaces',
        AGENTX_LOG_LEVEL: 'verbose',
        AGENTX_DB_PORT: '0',
        AGENTX_DB_HSOT: 'db',
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
        PGOPTIONS: '-c app.org_id=x',
      }),
    ).toEqual([
      expect.stringMatching(/^NODE_TLS_REJECT_UNAUTHORIZED: /),
      expect.stringMatching(/^PGOPTIONS: must be unset/),
      'AGENTX_DB_HSOT is not a setting the app knows; check the spelling and the capitals',
      expect.stringMatching(/^AGENTX_ENV: must be one of/),
      expect.stringMatching(/^AGENTX_RELEASE: /),
      expect.stringMatching(/^AGENTX_LOG_LEVEL: /),
      'AGENTX_DB_HOST: is required',
      expect.stringMatching(/^AGENTX_DB_PORT: must be at least 1$/),
      expect.stringMatching(/^AGENTX_DB_MIGRATION_PASSWORD is required, or AGENTX_DB_MIGRATION_PASSWORD_FILE /),
    ]);
  });

  it.each([
    [
      'a missing release in staging',
      { ...DEPLOYED, AGENTX_ENV: 'staging', AGENTX_RELEASE: undefined },
      /^AGENTX_RELEASE: is required in staging/,
    ],
    [
      'debug logging in production',
      { ...DEPLOYED, AGENTX_LOG_LEVEL: 'debug' },
      /^AGENTX_LOG_LEVEL: debug is off in production/,
    ],
    [
      'TLS off in production',
      { ...DEPLOYED, AGENTX_DB_TLS: 'disable' },
      /^AGENTX_DB_TLS: disable is allowed only in development and test; production/,
    ],
    ['NODE_DEBUG in production', { ...DEPLOYED, NODE_DEBUG: 'net' }, /^NODE_DEBUG: must be unset in production/],
  ])('applies the rules the app applies: %s', (_what, env, problem) => {
    expect(problemsWith(env)).toEqual([expect.stringMatching(problem)]);
  });

  it.each(['development', 'test'])('accepts TLS off and no release in %s, for the local stack', (environment) => {
    expect(problemsWith({ ...LOCAL, AGENTX_ENV: environment, AGENTX_DB_TLS: 'disable' })).toEqual([]);
  });

  it('puts every problem in the error message', () => {
    expect(() => loadMigrationConfig({ ...LOCAL, AGENTX_DB_PORT: 'five' })).toThrow(
      'Refusing to start: 1 config problem(s).\n- AGENTX_DB_PORT: must be a whole number, written in digits only',
    );
  });

  it('never repeats a value in a problem, so a secret in the wrong variable does not leak', () => {
    const misplaced = 'value that must never be printed';
    const problems = problemsWith({
      AGENTX_ENV: misplaced,
      AGENTX_RELEASE: misplaced,
      AGENTX_LOG_LEVEL: misplaced,
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: misplaced,
      AGENTX_DB_HOST: misplaced,
      AGENTX_DB_PORT: misplaced,
      AGENTX_DB_NAME: misplaced,
      AGENTX_DB_TLS: misplaced,
      AGENTX_DB_MIGRATION_USER: misplaced,
      AGENTX_DB_MIGRATION_PASSWORD: misplaced,
      AGENTX_DB_PASSWORD: misplaced,
      AGENTX_MISSPELT: misplaced,
      PGPASSWORD: misplaced,
    });
    // Every variable but the migration login, which any text may be. The app's login is refused by name.
    expect(problems).toHaveLength(12);
    expect(problems.filter((problem) => problem.toLowerCase().includes(misplaced))).toEqual([]);
  });
});
