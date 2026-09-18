import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { ConfigError } from './common.ts';
import { loadConfig } from './config.ts';
import { loadMigrationConfig } from './migration.ts';
import { READERS } from './settings.ts';
import { loadSetupConfig } from './setup.ts';

type Env = Record<string, string | undefined>;

/** Plain words joined into logins long enough for the job's rule, so secret scanners ignore them. */
const loginOf = (role: string): string => [role, 'login', 'for', 'these', 'tests'].join('-');
const ADMIN_LOGIN = loginOf('admin');
const LOGINS = {
  AGENTX_DB_OWNER_PASSWORD: loginOf('owner'),
  AGENTX_DB_APP_PASSWORD: loginOf('app'),
  AGENTX_DB_BACKUP_PASSWORD: loginOf('backup'),
  AGENTX_DB_ZITADEL_PASSWORD: loginOf('zitadel'),
};
const LOCAL: Env = {
  AGENTX_ENV: 'development',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_ADMIN_USER: 'postgres',
  AGENTX_DB_ADMIN_PASSWORD: ADMIN_LOGIN,
  ...LOGINS,
};
const DEPLOYED: Env = {
  ...LOCAL,
  AGENTX_ENV: 'staging',
  AGENTX_RELEASE: 'r-1',
  AGENTX_DB_HOST: 'psql.internal.example',
  AGENTX_DB_ADMIN_USER: 'agentx_admin',
};

function problemsWith(env: Env): readonly string[] {
  try {
    loadSetupConfig(env);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
}

const folder = mkdtempSync(path.join(tmpdir(), 'agentx-setup-config-'));
afterAll(() => {
  rmSync(folder, { recursive: true, force: true });
});

describe('the set-up job config loads', () => {
  it('needs the environment, the host, the admin and every login, and fills in the defaults', () => {
    expect(loadSetupConfig(LOCAL)).toEqual({
      environment: 'development',
      release: 'local',
      log: { level: 'info', eventCapPerMinute: 600 },
      db: { host: 'db', port: 5432, tls: 'verify-full', database: 'agentx' },
      admin: { user: 'postgres', password: ADMIN_LOGIN, database: 'postgres' },
      logins: {
        owner: LOGINS.AGENTX_DB_OWNER_PASSWORD,
        app: LOGINS.AGENTX_DB_APP_PASSWORD,
        backup: LOGINS.AGENTX_DB_BACKUP_PASSWORD,
        zitadel: LOGINS.AGENTX_DB_ZITADEL_PASSWORD,
      },
    });
  });

  it('reads every setting, logins from mounted files included', () => {
    const file = path.join(folder, 'app');
    writeFileSync(file, `${LOGINS.AGENTX_DB_APP_PASSWORD}\n`);
    const { AGENTX_DB_APP_PASSWORD: _, ...others } = LOGINS;
    expect(
      loadSetupConfig({
        ...others,
        AGENTX_ENV: 'test',
        AGENTX_RELEASE: 'r-2',
        AGENTX_LOG_LEVEL: 'warn',
        AGENTX_LOG_EVENT_CAP_PER_MINUTE: '1200',
        AGENTX_DB_HOST: '10.0.0.5',
        AGENTX_DB_PORT: '6432',
        AGENTX_DB_NAME: 'agentx_uae',
        AGENTX_DB_TLS: 'disable',
        AGENTX_DB_ADMIN_USER: 'agentx_admin',
        AGENTX_DB_ADMIN_DATABASE: 'azure_maintenance',
        AGENTX_DB_ADMIN_PASSWORD: ADMIN_LOGIN,
        AGENTX_DB_APP_PASSWORD_FILE: file,
      }),
    ).toMatchObject({
      environment: 'test',
      release: 'r-2',
      log: { level: 'warn', eventCapPerMinute: 1200 },
      db: { host: '10.0.0.5', port: 6432, tls: 'disable', database: 'agentx_uae' },
      admin: { user: 'agentx_admin', database: 'azure_maintenance' },
      logins: { app: LOGINS.AGENTX_DB_APP_PASSWORD },
    });
  });

  it('returns a config nothing can change afterwards', () => {
    const config = loadSetupConfig(DEPLOYED);
    expect([config, config.log, config.db, config.admin, config.logins].map((part) => Object.isFrozen(part))).toEqual([
      true,
      true,
      true,
      true,
      true,
    ]);
  });
});

describe('SEC-AV-03 the set-up job refuses a bad config, naming each problem', () => {
  it('needs the admin and every login', () => {
    expect(problemsWith({ AGENTX_ENV: 'development', AGENTX_DB_HOST: 'db' })).toEqual([
      'AGENTX_DB_ADMIN_USER: is required',
      'AGENTX_DB_ADMIN_PASSWORD is required, or AGENTX_DB_ADMIN_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
      'AGENTX_DB_OWNER_PASSWORD is required, or AGENTX_DB_OWNER_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
      'AGENTX_DB_APP_PASSWORD is required, or AGENTX_DB_APP_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
      'AGENTX_DB_BACKUP_PASSWORD is required, or AGENTX_DB_BACKUP_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
      'AGENTX_DB_ZITADEL_PASSWORD is required, or AGENTX_DB_ZITADEL_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
    ]);
  });

  it.each([
    ['postgres', {}],
    ['template0', {}],
    ['template1', {}],
    ['zitadel', {}],
    ['azure_maintenance', { AGENTX_DB_ADMIN_DATABASE: 'azure_maintenance' }],
  ] as const)("refuses %s as the app's database: Postgres's own, the login service's or the admin's", (name, more) => {
    expect(problemsWith({ ...LOCAL, ...more, AGENTX_DB_NAME: name })).toEqual([
      "AGENTX_DB_NAME: must be the app's own database, not Postgres's own (postgres, template0, template1), the login service's (zitadel) or the admin's (AGENTX_DB_ADMIN_DATABASE)",
    ]);
  });

  it.each(['agentx_owner', 'agentx_app', 'agentx_backup', 'zitadel'])(
    'refuses %s as the admin: the admin creates the roles, it is none of them',
    (role) => {
      expect(problemsWith({ ...LOCAL, AGENTX_DB_ADMIN_USER: role })).toEqual([
        'AGENTX_DB_ADMIN_USER: must be the server admin, not one of the roles the set-up job creates',
      ]);
    },
  );

  it.each([
    ['shorter than 24 characters', 'x'.repeat(23)],
    ['with a space', `${'x'.repeat(24)} y`],
    ['outside ASCII', `${'x'.repeat(24)}${String.fromCharCode(0xe9)}`],
  ])("refuses a role's login %s", (_, login) => {
    expect(problemsWith({ ...LOCAL, AGENTX_DB_BACKUP_PASSWORD: login })).toEqual([
      'AGENTX_DB_BACKUP_PASSWORD must be at least 24 characters of printable ASCII with no spaces, so it is out of reach of guessing and can be stored as a SCRAM verifier',
    ]);
  });

  it("takes the admin's login as Azure gives it: any length, any characters", () => {
    expect(problemsWith({ ...LOCAL, AGENTX_DB_ADMIN_PASSWORD: 'short one' })).toEqual([]);
  });

  it('refuses one login given to two roles, the admin included', () => {
    expect(
      problemsWith({
        ...LOCAL,
        AGENTX_DB_ADMIN_PASSWORD: LOGINS.AGENTX_DB_ZITADEL_PASSWORD,
        AGENTX_DB_BACKUP_PASSWORD: LOGINS.AGENTX_DB_APP_PASSWORD,
      }),
    ).toEqual([
      'AGENTX_DB_ADMIN_PASSWORD and AGENTX_DB_ZITADEL_PASSWORD hold the same login; every role needs its own',
      'AGENTX_DB_APP_PASSWORD and AGENTX_DB_BACKUP_PASSWORD hold the same login; every role needs its own',
    ]);
  });

  it('verifies the server in every deployed environment: TLS off only locally, and a release named', () => {
    expect(problemsWith({ ...DEPLOYED, AGENTX_DB_TLS: 'disable', AGENTX_RELEASE: undefined })).toEqual([
      'AGENTX_RELEASE: is required in staging, so every log line and error names the build that ran',
      "AGENTX_DB_TLS: disable is allowed only in development and test; staging must verify the server's certificate (verify-full)",
    ]);
  });

  it('refuses PG* variables, TLS checks turned off, and Node debug output in production', () => {
    expect(
      problemsWith({
        ...DEPLOYED,
        AGENTX_ENV: 'production',
        PGHOST: 'elsewhere',
        NODE_TLS_REJECT_UNAUTHORIZED: '0',
        NODE_DEBUG: 'net',
      }),
    ).toEqual([
      'NODE_TLS_REJECT_UNAUTHORIZED: must be unset (or 1); 0 turns off TLS certificate checks for every connection',
      'PGHOST: must be unset; the database is reached only through the AGENTX_DB_* settings, and a PG* variable could redirect the connection or add session settings',
      'NODE_DEBUG: must be unset in production; Node would print its own debug output outside the logger',
    ]);
  });

  it.each([
    ['AGENTX_DB_PASSWORD', 'the app (apps/api)'],
    ['AGENTX_DB_USER', 'the app (apps/api)'],
    ['AGENTX_HTTP_PORT', 'the app (apps/api)'],
    ['AGENTX_DB_MIGRATION_PASSWORD', 'the migration job (apps/migrate)'],
  ])("refuses %s, another job's setting, by name", (name, job) => {
    expect(problemsWith({ ...LOCAL, [name]: 'x' })).toEqual([
      `${name} belongs to ${job}; the set-up job reads only the database, log and login settings it needs`,
    ]);
  });
});

describe("SEC-AV-03 the other jobs refuse the set-up job's settings", () => {
  it("lists each process's settings once, and gives the admin's and the roles' logins to the set-up job alone", () => {
    const readers = Object.values(READERS);
    for (const reader of readers) expect(new Set(reader.reads).size).toBe(reader.reads.length);
    const setupOnly = READERS.setup.reads.filter(
      (name) => !READERS.app.reads.includes(name) && !READERS.migrate.reads.includes(name),
    );
    expect(setupOnly).toEqual([
      'AGENTX_DB_ADMIN_USER',
      'AGENTX_DB_ADMIN_DATABASE',
      'AGENTX_DB_ADMIN_PASSWORD',
      'AGENTX_DB_ADMIN_PASSWORD_FILE',
      'AGENTX_DB_OWNER_PASSWORD',
      'AGENTX_DB_OWNER_PASSWORD_FILE',
      'AGENTX_DB_APP_PASSWORD',
      'AGENTX_DB_APP_PASSWORD_FILE',
      'AGENTX_DB_BACKUP_PASSWORD',
      'AGENTX_DB_BACKUP_PASSWORD_FILE',
      'AGENTX_DB_ZITADEL_PASSWORD',
      'AGENTX_DB_ZITADEL_PASSWORD_FILE',
    ]);
  });

  it.each(['AGENTX_DB_ADMIN_USER', 'AGENTX_DB_ADMIN_PASSWORD', 'AGENTX_DB_BACKUP_PASSWORD_FILE'])(
    'the app and the migration job refuse %s by name',
    (name) => {
      const refusal = (load: () => unknown): readonly string[] => {
        try {
          load();
          return [];
        } catch (error) {
          if (error instanceof ConfigError) return error.problems;
          throw error;
        }
      };
      const base = { AGENTX_ENV: 'development', AGENTX_DB_HOST: 'db', [name]: 'x' };
      expect(
        refusal(() => loadConfig({ ...base, AGENTX_DB_PASSWORD: 'app login', AGENTX_KEYS_DIR: '/mnt/secrets' })),
      ).toEqual([
        `${name} belongs to the database set-up job (apps/db-setup); the running app holds no login but its own role's (ADR-005 §3)`,
      ]);
      expect(refusal(() => loadMigrationConfig({ ...base, AGENTX_DB_MIGRATION_PASSWORD: 'owner login' }))).toEqual([
        `${name} belongs to the database set-up job (apps/db-setup); the migration job reads only the database and log settings`,
      ]);
    },
  );
});
