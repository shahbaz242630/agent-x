import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { ConfigError } from './common.ts';
import { loadConfig } from './config.ts';
import { pgVariableProblems, secretSetting } from './database.ts';
import { loadMigrationConfig } from './migration.ts';

type Env = Record<string, string | undefined>;

/** Plain words, so secret scanners ignore them. */
const APP_LOGIN = 'app login for these tests';
const OWNER_LOGIN = 'owner login for these tests';

const APP: Env = {
  AGENTX_ENV: 'production',
  AGENTX_RELEASE: 'r-1',
  AGENTX_PUBLIC_ORIGIN: 'https://app.agentx.example',
  AGENTX_TRUSTED_PROXIES: '10.0.0.0/23',
  AGENTX_DB_HOST: 'db.internal.example',
  AGENTX_DB_PASSWORD: APP_LOGIN,
  AGENTX_KEYS_DIR: '/mnt/secrets',
};
const LOCAL_APP: Env = {
  AGENTX_ENV: 'development',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_PASSWORD: APP_LOGIN,
  AGENTX_KEYS_DIR: '/mnt/secrets',
};
const JOB: Env = {
  AGENTX_ENV: 'production',
  AGENTX_RELEASE: 'r-1',
  AGENTX_DB_HOST: 'db.internal.example',
  AGENTX_DB_MIGRATION_PASSWORD: OWNER_LOGIN,
};

function problemsOf(load: (env: Env) => unknown, env: Env): readonly string[] {
  try {
    load(env);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
}
const appProblems = (env: Env): readonly string[] => problemsOf(loadConfig, env);
const jobProblems = (env: Env): readonly string[] => problemsOf(loadMigrationConfig, env);

const PG_PROBLEM = (name: string): string =>
  `${name}: must be unset; the database is reached only through the AGENTX_DB_* settings, and a PG* variable could redirect the connection or add session settings`;

describe('SEC-AV-03 database settings', () => {
  it('fills in the defaults: port 5432, database agentx, the app role, TLS verified, 10 connections', () => {
    expect(loadConfig(APP).db).toEqual({
      host: 'db.internal.example',
      port: 5432,
      database: 'agentx',
      user: 'agentx_app',
      password: APP_LOGIN,
      tls: 'verify-full',
      poolMax: 10,
    });
  });

  it.each([
    'db',
    'localhost',
    'pg.internal.example',
    'agentx-db.postgres.database.azure.com',
    '10.0.0.5',
    '::1',
    'fd00::5',
  ])('accepts the host %s', (host) => {
    expect(loadConfig({ ...APP, AGENTX_DB_HOST: host }).db.host).toBe(host);
  });

  it.each(['DB', 'db_1', '-db', 'db-', 'a..b', 'db.', 'db:5432', 'postgres://db', ' db', '10.0.0.5:5432'])(
    'refuses the host %j',
    (host) => {
      expect(appProblems({ ...APP, AGENTX_DB_HOST: host })).toEqual([
        'AGENTX_DB_HOST: must be a host name in lower case (letters, digits, dots and dashes) or an IP address',
      ]);
    },
  );

  it('accepts a host label of 63 characters, the DNS limit, and refuses 64', () => {
    expect(loadConfig({ ...APP, AGENTX_DB_HOST: `${'a'.repeat(63)}.example` }).db.host).toBe(
      `${'a'.repeat(63)}.example`,
    );
    expect(appProblems({ ...APP, AGENTX_DB_HOST: `${'a'.repeat(64)}.example` })).toEqual([
      expect.stringMatching(/^AGENTX_DB_HOST: must be a host name/),
    ]);
  });

  it.each(['agentx', 'agentx_uae', '_x', 'a1', 'a'.repeat(63)])('accepts the database name and role %s', (name) => {
    const config = loadConfig({ ...APP, AGENTX_DB_NAME: name, AGENTX_DB_USER: name });
    expect([config.db.database, config.db.user]).toEqual([name, name]);
  });

  it.each(['Agentx', '1agentx', 'agent-x', 'agentx uae', 'a'.repeat(64), 'agentx;drop', 'agentx.public'])(
    'refuses the database name and role %j',
    (name) => {
      expect(appProblems({ ...APP, AGENTX_DB_NAME: name, AGENTX_DB_USER: name })).toEqual([
        expect.stringMatching(/^AGENTX_DB_NAME: must be a plain Postgres name/),
        expect.stringMatching(/^AGENTX_DB_USER: must be a plain Postgres name/),
      ]);
    },
  );

  it.each([
    ['0', 'must be at least 1'],
    ['65536', 'must be at most 65535'],
    ['54.32', 'must be a whole number, written in digits only'],
    ['five', 'must be a whole number, written in digits only'],
  ])('refuses the port %j', (port, problem) => {
    expect(appProblems({ ...APP, AGENTX_DB_PORT: port })).toEqual([`AGENTX_DB_PORT: ${problem}`]);
  });

  it.each(['1', '100'])('accepts a pool of %s connections', (max) => {
    expect(loadConfig({ ...APP, AGENTX_DB_POOL_MAX: max }).db.poolMax).toBe(Number(max));
  });

  it.each([
    ['0', 'must be at least 1 connections'],
    ['101', 'must be at most 100 connections'],
  ])('refuses a pool of %s connections', (max, problem) => {
    expect(appProblems({ ...APP, AGENTX_DB_POOL_MAX: max })).toEqual([`AGENTX_DB_POOL_MAX: ${problem}`]);
  });

  it.each(['verify-ca', 'require', 'true', 'DISABLE', 'off'])('refuses the TLS mode %j', (mode) => {
    expect(appProblems({ ...APP, AGENTX_DB_TLS: mode })).toEqual([
      'AGENTX_DB_TLS: must be one of: verify-full, disable',
    ]);
  });

  it.each(['staging', 'production'])('refuses TLS disable in %s, where the server must be verified', (environment) => {
    expect(appProblems({ ...APP, AGENTX_ENV: environment, AGENTX_DB_TLS: 'disable' })).toEqual([
      `AGENTX_DB_TLS: disable is allowed only in development and test; ${environment} must verify the server's certificate (verify-full)`,
    ]);
  });

  it.each(['development', 'test'])('accepts TLS disable in %s, for the local stack', (environment) => {
    expect(loadConfig({ ...LOCAL_APP, AGENTX_ENV: environment, AGENTX_DB_TLS: 'disable' }).db.tls).toBe('disable');
  });
});

describe('ADR-010 §4 the database password comes directly, or from a file the platform mounted', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentx-config-'));
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  const file = (name: string, contents: string): string => {
    const full = path.join(dir, name);
    writeFileSync(full, contents);
    return full;
  };

  it.each([
    ['one trailing line break dropped', 'from the file\n', 'from the file'],
    ['a Windows line break dropped', 'from the file\r\n', 'from the file'],
    ['no line break kept as is', 'from the file', 'from the file'],
    ['only one of two line breaks dropped', 'from the file\n\n', 'from the file\n'],
  ])('reads the file: %s', (name, contents, expected) => {
    const env = { AGENTX_DB_PASSWORD_FILE: file(name.replaceAll(' ', '-'), contents) };
    expect(secretSetting(env, 'AGENTX_DB_PASSWORD')).toEqual({ ok: true, value: expected });
  });

  it('serves both loaders', () => {
    const appFile = file('app', `${APP_LOGIN}\n`);
    const ownerFile = file('owner', `${OWNER_LOGIN}\n`);
    const { AGENTX_DB_PASSWORD: _app, ...app } = APP;
    const { AGENTX_DB_MIGRATION_PASSWORD: _owner, ...job } = JOB;
    expect(loadConfig({ ...app, AGENTX_DB_PASSWORD_FILE: appFile }).db.password).toBe(APP_LOGIN);
    expect(loadMigrationConfig({ ...job, AGENTX_DB_MIGRATION_PASSWORD_FILE: ownerFile }).db.password).toBe(OWNER_LOGIN);
  });

  it('refuses the variable and the file together', () => {
    expect(
      secretSetting({ AGENTX_DB_PASSWORD: 'x', AGENTX_DB_PASSWORD_FILE: file('both', 'y') }, 'AGENTX_DB_PASSWORD'),
    ).toEqual({
      ok: false,
      problem: 'set either AGENTX_DB_PASSWORD or AGENTX_DB_PASSWORD_FILE, not both',
    });
  });

  it('refuses neither', () => {
    expect(secretSetting({}, 'AGENTX_DB_MIGRATION_PASSWORD')).toEqual({
      ok: false,
      problem:
        'AGENTX_DB_MIGRATION_PASSWORD is required, or AGENTX_DB_MIGRATION_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
    });
  });

  it.each([
    ['an empty value', { AGENTX_DB_PASSWORD: '' }, 'AGENTX_DB_PASSWORD is empty'],
    ['an empty path', { AGENTX_DB_PASSWORD_FILE: '' }, 'AGENTX_DB_PASSWORD_FILE is empty'],
    ['an empty file', { AGENTX_DB_PASSWORD_FILE: file('empty', '') }, 'AGENTX_DB_PASSWORD_FILE names an empty file'],
    [
      'a file of one line break',
      { AGENTX_DB_PASSWORD_FILE: file('blank', '\n') },
      'AGENTX_DB_PASSWORD_FILE names an empty file',
    ],
    [
      'a missing file',
      { AGENTX_DB_PASSWORD_FILE: path.join(dir, 'missing') },
      "AGENTX_DB_PASSWORD_FILE names a file that can't be read",
    ],
    ['a directory', { AGENTX_DB_PASSWORD_FILE: dir }, "AGENTX_DB_PASSWORD_FILE names a file that can't be read"],
  ])('refuses %s, naming the variable and never the path', (_what, env, problem) => {
    expect(secretSetting(env, 'AGENTX_DB_PASSWORD')).toEqual({ ok: false, problem });
    expect(problem).not.toContain(dir);
  });
});

describe('SEC-TEN-06 a PG* variable refuses the start', () => {
  it.each([
    'PGHOST',
    'PGPORT',
    'PGUSER',
    'PGPASSWORD',
    'PGDATABASE',
    'PGOPTIONS',
    'PGSSLMODE',
    'PGSERVICE',
    'PGAPPNAME',
    'PG_COLOR',
  ])('refuses %s in the app', (name) => {
    expect(appProblems({ ...APP, [name]: 'x' })).toEqual([PG_PROBLEM(name)]);
  });

  it('refuses them in the migration job too', () => {
    expect(jobProblems({ ...JOB, PGOPTIONS: '-c app.org_id=x' })).toEqual([PG_PROBLEM('PGOPTIONS')]);
  });

  it('names every one, sorted, whatever their values', () => {
    expect(pgVariableProblems({ PGUSER: '', PGHOST: 'x', PG: 'y', OTHER: 'z' })).toEqual([
      PG_PROBLEM('PG'),
      PG_PROBLEM('PGHOST'),
      PG_PROBLEM('PGUSER'),
    ]);
  });

  it('refuses the name in any case: Windows reads the environment case-insensitively, so pghost is PGHOST there', () => {
    expect(pgVariableProblems({ pghost: 'x', Pgoptions: 'x', PGADMIN: 'x', PG2: 'x' })).toEqual([
      PG_PROBLEM('PG2'),
      PG_PROBLEM('PGADMIN'),
      PG_PROBLEM('Pgoptions'),
      PG_PROBLEM('pghost'),
    ]);
  });

  it('leaves names alone that only contain pg, or start with something else', () => {
    expect(pgVariableProblems({ APG: 'x', MYPGHOST: 'x', XPG_COLOR: 'x', P: 'x' })).toEqual([]);
  });
});

describe("SEC-AV-03 the other job's settings are refused by name", () => {
  it.each(['AGENTX_DB_MIGRATION_USER', 'AGENTX_DB_MIGRATION_PASSWORD', 'AGENTX_DB_MIGRATION_PASSWORD_FILE'])(
    'the app refuses %s: it never holds the migration login',
    (name) => {
      expect(appProblems({ ...APP, [name]: 'x' })).toEqual([
        `${name} belongs to the migration job (apps/migrate); the running app holds no login but its own role's (ADR-005 §3)`,
      ]);
    },
  );

  it.each([
    ['AGENTX_HTTP_PORT', 'the app (apps/api)'],
    ['AGENTX_PUBLIC_ORIGIN', 'the app (apps/api)'],
    ['AGENTX_DB_USER', "the app (apps/api) and the operator's command (apps/operator)"],
    ['AGENTX_DB_PASSWORD', "the app (apps/api) and the operator's command (apps/operator)"],
    ['AGENTX_DB_PASSWORD_FILE', "the app (apps/api) and the operator's command (apps/operator)"],
    ['AGENTX_DB_POOL_MAX', 'the app (apps/api)'],
  ])('the migration job refuses %s', (name, owners) => {
    expect(jobProblems({ ...JOB, [name]: 'x' })).toEqual([
      `${name} belongs to ${owners}; the migration job reads only the database and log settings`,
    ]);
  });

  it('still calls a misspelt name a misspelling, in either job', () => {
    const problem = 'AGENTX_DB_HSOT is not a setting the app knows; check the spelling and the capitals';
    expect(appProblems({ ...APP, AGENTX_DB_HSOT: 'x' })).toEqual([problem]);
    expect(jobProblems({ ...JOB, AGENTX_DB_HSOT: 'x' })).toEqual([problem]);
  });
});
