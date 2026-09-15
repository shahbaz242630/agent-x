// The database settings (ADR-002; ADR-005 §3; ADR-010 §4: secrets arrive as
// environment variables or mounted files, never through a cloud SDK). The app
// and the migration job share where the database is and how the connection is
// protected; each has its own role and password. Nothing reaches the driver
// from anywhere else: any PG* variable, which pg and libpq would read, refuses
// the start.
import { readFileSync } from 'node:fs';

import { type Env, type Environment, LOCAL_ONLY } from './common.ts';
import type { DatabaseTlsMode } from './primitives.ts';
import { type Checked, setting } from './settings.ts';

/** Where the database is, and how the connection is protected: the checks both loaders share. */
export interface LocationChecks {
  readonly host: Checked<string>;
  readonly port: Checked<number>;
  readonly database: Checked<string>;
  readonly tls: Checked<DatabaseTlsMode>;
}

export function checkLocation(env: Env): LocationChecks {
  return {
    host: setting(env, 'AGENTX_DB_HOST'),
    port: setting(env, 'AGENTX_DB_PORT'),
    database: setting(env, 'AGENTX_DB_NAME'),
    tls: setting(env, 'AGENTX_DB_TLS'),
  };
}

/** A password set directly, or the path of a file the platform mounted with it in. */
type SecretName = 'AGENTX_DB_PASSWORD' | 'AGENTX_DB_MIGRATION_PASSWORD';

const refused = (problem: string): Checked<never> => ({ ok: false, problem });

/**
 * Reads a secret from `name`, or from the file named by `name_FILE`. Exactly
 * one must be set. A file's one trailing line break is dropped, since tools
 * that write secret files usually add one. Problems name the variable, never
 * the value or the path. They are worded without a colon after the name: the
 * log scrubber redacts whatever follows `PASSWORD:`, which is right for a
 * value and would only hide the rest of these messages.
 */
export function secretSetting(env: Env, name: SecretName): Checked<string> {
  const fileName = `${name}_FILE`;
  const direct = env[name];
  const file = env[fileName];
  if (direct !== undefined && file !== undefined) return refused(`set either ${name} or ${fileName}, not both`);
  if (direct !== undefined) return direct === '' ? refused(`${name} is empty`) : { ok: true, value: direct };
  if (file === undefined) {
    return refused(`${name} is required, or ${fileName} with the path of a file that holds it (a mounted secret)`);
  }
  if (file === '') return refused(`${fileName} is empty`);
  let contents: string;
  try {
    contents = readFileSync(file, 'utf8');
  } catch {
    return refused(`${fileName} names a file that can't be read`);
  }
  const value = contents.replace(/\r?\n$/, '');
  return value === '' ? refused(`${fileName} names an empty file`) : { ok: true, value };
}

/** Anything pg or libpq would read on their own: PGHOST, PGOPTIONS, PGSSLMODE, PGPASSWORD and the rest. */
const PG_VARIABLE = /^PG[A-Z0-9_]*$/;

/**
 * SEC-TEN-06 (ADR-005 §4): the database is reached only through the settings
 * above. A PG* variable could point the driver at another server, add session
 * settings (PGOPTIONS can preset a tenant) or weaken TLS, so any one refuses
 * the start, in every environment.
 */
export function pgVariableProblems(env: Env): string[] {
  return Object.keys(env)
    .filter((name) => PG_VARIABLE.test(name))
    .sort()
    .map(
      (name) =>
        `${name}: must be unset; the database is reached only through the AGENTX_DB_* settings, and a PG* variable could redirect the connection or add session settings`,
    );
}

/** ADR-002: every deployed environment verifies the server's certificate and host name. */
export function tlsModeProblems(environment: Environment, mode: DatabaseTlsMode): string[] {
  return mode === 'disable' && !LOCAL_ONLY.includes(environment)
    ? [
        `AGENTX_DB_TLS: disable is allowed only in ${LOCAL_ONLY.join(' and ')}; ${environment} must verify the server's certificate (verify-full)`,
      ]
    : [];
}
