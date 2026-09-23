import { describe, expect, it } from 'vitest';

import { ConfigError } from './common.ts';
import { loadOperatorConfig } from './operator.ts';

type Env = Record<string, string | undefined>;

/** Plain words, so secret scanners ignore it. */
const APP_LOGIN = 'app login for these tests';
const KEYS_DIR = '/mnt/keys';
/** Where Azure names each run of a job (Container Apps' built-in environment variables). */
const RUN_VARIABLE = 'CONTAINER_APP_JOB_EXECUTION_NAME';
/** A run's name as Azure gives one: the job's name, a hyphen, the run's own letters and digits. */
const RUN = 'job-agentx-prd-operator-7x2kq9m';
const LOCAL: Env = {
  AGENTX_ENV: 'development',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_PASSWORD: APP_LOGIN,
  AGENTX_KEYS_DIR: KEYS_DIR,
};
const DEPLOYED: Env = {
  AGENTX_ENV: 'production',
  AGENTX_RELEASE: 'r-1',
  AGENTX_DB_HOST: 'db.internal.example',
  AGENTX_DB_PASSWORD: APP_LOGIN,
  AGENTX_KEYS_DIR: KEYS_DIR,
  [RUN_VARIABLE]: RUN,
};
const RUN_RULE = `${RUN_VARIABLE}: must be a job run's name as Azure gives it, at most 64 characters: lower-case words of letters and digits joined by single hyphens, the first starting with a letter`;

function problemsWith(env: Env): readonly string[] {
  try {
    loadOperatorConfig(env);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
}

describe("the operator's command's config loads", () => {
  it("needs only the environment, the host, the app's login and the keys' folder, and fills in the defaults", () => {
    expect(loadOperatorConfig(LOCAL)).toEqual({
      environment: 'development',
      release: 'local',
      run: null,
      log: { level: 'info', eventCapPerMinute: 600 },
      db: { host: 'db', port: 5432, database: 'agentx', user: 'agentx_app', password: APP_LOGIN, tls: 'verify-full' },
      keys: { directory: KEYS_DIR, current: {} },
    });
  });

  it('reads every setting', () => {
    expect(
      loadOperatorConfig({
        AGENTX_ENV: 'test',
        AGENTX_RELEASE: 'r-2',
        AGENTX_LOG_LEVEL: 'warn',
        AGENTX_LOG_EVENT_CAP_PER_MINUTE: '1200',
        AGENTX_KEYS_DIR: '/mnt/other-keys',
        AGENTX_KEYS_CURRENT: 'audit-mac:2',
        AGENTX_DB_HOST: '10.0.0.5',
        AGENTX_DB_PORT: '6432',
        AGENTX_DB_NAME: 'agentx_uae',
        AGENTX_DB_TLS: 'disable',
        AGENTX_DB_USER: 'agentx_app_uae',
        AGENTX_DB_PASSWORD: APP_LOGIN,
        [RUN_VARIABLE]: RUN,
      }),
    ).toEqual({
      environment: 'test',
      release: 'r-2',
      run: RUN,
      log: { level: 'warn', eventCapPerMinute: 1200 },
      db: {
        host: '10.0.0.5',
        port: 6432,
        database: 'agentx_uae',
        user: 'agentx_app_uae',
        password: APP_LOGIN,
        tls: 'disable',
      },
      keys: { directory: '/mnt/other-keys', current: { 'audit-mac': 2 } },
    });
  });

  it('returns a config nothing can change afterwards', () => {
    const config = loadOperatorConfig({ ...DEPLOYED, AGENTX_KEYS_CURRENT: 'audit-mac:2' });
    expect(
      [config, config.log, config.db, config.keys, config.keys.current].map((part) => Object.isFrozen(part)),
    ).toEqual([true, true, true, true, true]);
  });

  it("ignores variables that are not AGENTX_ or PG settings, or the run's name", () => {
    expect(
      problemsWith({
        ...DEPLOYED,
        PATH: '/usr/bin',
        HOME: '/home/app',
        HOSTNAME: 'replica-7',
        CONTAINER_APP_JOB_NAME: 'Not A Name Azure Gives',
      }),
    ).toEqual([]);
  });
});

describe("B1c-2b the operator's config names the job's run, as Azure does", () => {
  it.each(['staging', 'production'])('reads the run in %s', (environment) => {
    expect(loadOperatorConfig({ ...DEPLOYED, AGENTX_ENV: environment }).run).toBe(RUN);
  });

  it.each(['staging', 'production'])(
    'needs it in %s, where the command only ever runs as a job, so no platform event goes without it',
    (environment) => {
      expect(problemsWith({ ...DEPLOYED, AGENTX_ENV: environment, [RUN_VARIABLE]: undefined })).toEqual([
        `${RUN_VARIABLE}: is required in ${environment}, so the platform's event names the run that did it (Azure sets it in every run of a job)`,
      ]);
    },
  );

  it.each(['development', 'test'])('takes a run by hand in %s as no run at all', (environment) => {
    expect(loadOperatorConfig({ ...LOCAL, AGENTX_ENV: environment }).run).toBeNull();
  });

  it('takes a run name of exactly 64 characters', () => {
    const longest = `job-${'q'.repeat(60)}`;
    expect(loadOperatorConfig({ ...DEPLOYED, [RUN_VARIABLE]: longest }).run).toBe(longest);
  });

  it.each([
    ['empty', ''],
    ['one character more than 64', `job-${'q'.repeat(61)}`],
    ['in capitals', 'Job-agentx-prd-operator-7x2kq9m'],
    ['starting with a digit', '7job-agentx-prd-operator-7x2kq9m'],
    ['starting with a hyphen', '-job-agentx-prd-operator-7x2kq9m'],
    ['ending with a hyphen', 'job-agentx-prd-operator-'],
    ['with two hyphens together', 'job-agentx--prd-operator-7x2kq9m'],
    ['one word, with no run of its own', 'operator'],
    ['with a space', 'job-agentx-prd operator-7x2kq9m'],
    ['with a dot', 'job-agentx-prd.operator-7x2kq9m'],
    ['with a line break after it', `${RUN}\n`],
    ['with a letter from another script', 'job-agentx-prd-operator-7x2kq9с'],
  ])('refuses a run name %s, never repeating it', (_what, run) => {
    expect(problemsWith({ ...DEPLOYED, [RUN_VARIABLE]: run })).toEqual([RUN_RULE]);
  });

  it('refuses a malformed run name in development and test too', () => {
    expect(problemsWith({ ...LOCAL, AGENTX_ENV: 'test', [RUN_VARIABLE]: 'operator' })).toEqual([RUN_RULE]);
  });
});

describe("SEC-AV-03 the operator's command refuses to start on a bad config", () => {
  it('reports every problem at once, in the same order the app uses', () => {
    expect(
      problemsWith({
        AGENTX_ENV: 'live',
        AGENTX_RELEASE: 'has spaces',
        AGENTX_LOG_LEVEL: 'verbose',
        AGENTX_KEYS_DIR: 'keys',
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
      'AGENTX_KEYS_DIR: must be an absolute path, such as /mnt/secrets',
      'AGENTX_DB_HOST: is required',
      expect.stringMatching(/^AGENTX_DB_PORT: must be at least 1$/),
      expect.stringMatching(/^AGENTX_DB_PASSWORD is required, or AGENTX_DB_PASSWORD_FILE /),
    ]);
  });

  it("needs the keys' folder", () => {
    expect(problemsWith({ ...DEPLOYED, AGENTX_KEYS_DIR: undefined })).toEqual(['AGENTX_KEYS_DIR: is required']);
  });

  it.each([
    ['AGENTX_HTTP_PORT', 'the app (apps/api)'],
    ['AGENTX_DB_POOL_MAX', 'the app (apps/api)'],
    ['AGENTX_AUDIT_ANCHOR_SECONDS', 'the app (apps/api)'],
    ['AGENTX_DB_MIGRATION_USER', 'the migration job (apps/migrate)'],
    ['AGENTX_DB_MIGRATION_PASSWORD', 'the migration job (apps/migrate)'],
    ['AGENTX_DB_ADMIN_PASSWORD', 'the database set-up job (apps/db-setup)'],
    ['AGENTX_DB_OWNER_PASSWORD_FILE', 'the database set-up job (apps/db-setup)'],
  ])("refuses %s, another job's setting, by name", (name, job) => {
    expect(problemsWith({ ...LOCAL, [name]: 'x' })).toEqual([
      `${name} belongs to ${job}; the operator's command reads only the database, log and key settings it needs, as the app's role`,
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

  it('reports the database TLS rule alongside a problem in another setting', () => {
    expect(problemsWith({ ...DEPLOYED, AGENTX_DB_TLS: 'disable', AGENTX_DB_PORT: 'five' })).toEqual([
      expect.stringMatching(/^AGENTX_DB_PORT: must be a whole number/),
      expect.stringMatching(/^AGENTX_DB_TLS: disable is allowed only in development and test; production/),
    ]);
  });

  it.each(['development', 'test'])('accepts TLS off and no release in %s, for the local stack', (environment) => {
    expect(problemsWith({ ...LOCAL, AGENTX_ENV: environment, AGENTX_DB_TLS: 'disable' })).toEqual([]);
  });

  it('never repeats a value in a problem, so a secret in the wrong variable does not leak', () => {
    const misplaced = 'value that must never be printed';
    const problems = problemsWith({
      AGENTX_ENV: misplaced,
      AGENTX_RELEASE: misplaced,
      AGENTX_LOG_LEVEL: misplaced,
      AGENTX_LOG_EVENT_CAP_PER_MINUTE: misplaced,
      AGENTX_KEYS_DIR: misplaced,
      AGENTX_KEYS_CURRENT: misplaced,
      AGENTX_DB_HOST: misplaced,
      AGENTX_DB_PORT: misplaced,
      AGENTX_DB_NAME: misplaced,
      AGENTX_DB_TLS: misplaced,
      AGENTX_DB_USER: misplaced,
      AGENTX_DB_PASSWORD: misplaced,
      AGENTX_DB_MIGRATION_PASSWORD: misplaced,
      AGENTX_MISSPELT: misplaced,
      PGPASSWORD: misplaced,
      [RUN_VARIABLE]: misplaced,
    });
    // Every variable but the app's login, which any text may be. The migration login is refused by name.
    expect(problems).toHaveLength(15);
    expect(problems.filter((problem) => problem.toLowerCase().includes(misplaced))).toEqual([]);
  });
});
