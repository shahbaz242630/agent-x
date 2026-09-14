// Schema migrations (ADR-001): plain SQL files in db/migrations, applied in
// order by the migration role (agentx_owner) at deploy time, never when the
// app starts. Migrations only go forward; a mistake is fixed by a new one.
//
// - Files are named NNNN_words.sql and numbered 0001 upward with no gaps, so a
//   misnamed or missing file stops the run instead of being skipped.
// - Each file runs in its own transaction with its row in the ledger
//   (migrations.applied), so it is applied completely or not at all.
// - The ledger keeps each file's SHA-256. A file changed after it was applied,
//   or a ledger row this build has no file for, stops the run.
// - A session-level advisory lock lets only one run work at a time. Closing
//   the connection releases it, even after a crash.
import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import pg from 'pg';

import type { Logger } from '../observability/index.ts';
import { type DatabaseConnectionOptions, poolConfig } from './database.ts';
import { refuseTenantPreset } from './tenant.ts';

const FILE_NAME = /^(\d{4})_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$/;

/** U+FEFF, which some editors put at the start of a file and Postgres can't parse. */
const BYTE_ORDER_MARK = String.fromCharCode(0xfe_ff);

/** An arbitrary advisory-lock key, used only by this runner. */
const LOCK_KEY = 7_402_531_119;

const LEDGER = `
  create schema if not exists migrations;
  create table if not exists migrations.applied (
    name text primary key,
    checksum text not null,
    applied_at timestamptz not null default pg_catalog.now()
  );
`;

/** Marks the open transaction as a migration's, to catch a file that ends it early. */
const MARK = "select pg_catalog.set_config('agentx.migration', $1, true)";
const READ_MARK = "select pg_catalog.current_setting('agentx.migration', true) as name";

export interface Migration {
  readonly name: string;
  readonly sql: string;
  /** SHA-256 of the file, with line endings written as LF, in hex. */
  readonly checksum: string;
}

/** The files or the ledger are wrong, so nothing was applied. */
export class MigrationRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`Migrations refused: ${problems.join('; ')}`);
    this.name = 'MigrationRefused';
    this.problems = problems;
  }
}

/** One migration failed and was rolled back; the ones before it stay applied. The cause says why. */
export class MigrationFailed extends Error {
  readonly migration: string;

  constructor(migration: string, cause: unknown) {
    super(`Migration ${migration} failed and was rolled back`, { cause });
    this.name = 'MigrationFailed';
    this.migration = migration;
  }
}

/** Reads and checks every migration file in the folder, in order. Throws MigrationRefused listing every problem. */
export async function loadMigrations(directory: string): Promise<Migration[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const problems: string[] = [];
  const migrations: Migration[] = [];

  // By UTF-16 code unit, so the order is the same on every machine and locale.
  for (const entry of entries.sort((a, b) => Number(a.name > b.name) - Number(a.name < b.name))) {
    if (!entry.isFile() || !FILE_NAME.test(entry.name)) {
      problems.push(`${entry.name} is not a migration file named like 0001_words.sql`);
      continue;
    }
    const expected = String(migrations.length + 1).padStart(4, '0');
    if (!entry.name.startsWith(`${expected}_`)) {
      problems.push(`${entry.name} is out of sequence: the next file must be numbered ${expected}`);
    }
    const raw = await readFile(path.join(directory, entry.name), 'utf8');
    if (raw.startsWith(BYTE_ORDER_MARK)) problems.push(`${entry.name} starts with a byte-order mark`);
    const sql = raw.replaceAll('\r\n', '\n');
    if (sql.trim() === '') problems.push(`${entry.name} is empty`);
    migrations.push({ name: entry.name, sql, checksum: createHash('sha256').update(sql).digest('hex') });
  }

  if (problems.length > 0) throw new MigrationRefused(problems);
  return migrations;
}

/** Problems with the ledger: every applied migration must be this build's file of the same place and content. */
function ledgerProblems(files: readonly Migration[], applied: readonly { name: string; checksum: string }[]): string[] {
  return applied.flatMap((row, index) => {
    const file = files[index];
    if (file?.name !== row.name) {
      return [`the database has ${row.name} applied where this build has ${file?.name ?? 'no file'}`];
    }
    return file.checksum === row.checksum ? [] : [`${row.name} was changed after it was applied`];
  });
}

export interface MigrationOptions {
  /** The migration role's connection (agentx_owner). */
  readonly connection: DatabaseConnectionOptions;
  /** The folder of migration files, db/migrations. */
  readonly directory: string;
  readonly logger: Logger;
}

/** Applies every migration not yet applied, in order, and returns their names. */
export async function runMigrations(options: MigrationOptions): Promise<string[]> {
  const files = await loadMigrations(options.directory);
  const client = new pg.Client(poolConfig(options.connection));
  // A lost connection is also reported as an event; with no listener, Node
  // would crash the process instead of letting the failing query report it.
  client.on('error', (error: unknown) => {
    options.logger.error('db.migration.connection_lost', { err: error });
  });
  await client.connect();
  try {
    await refuseTenantPreset(client);
    await client.query('select pg_catalog.pg_advisory_lock($1)', [LOCK_KEY]);
    await client.query(LEDGER);
    const { rows: applied } = await client.query<{ name: string; checksum: string }>(
      'select name, checksum from migrations.applied order by name',
    );
    const problems = ledgerProblems(files, applied);
    if (problems.length > 0) throw new MigrationRefused(problems);

    const pending = files.slice(applied.length);
    for (const migration of pending) {
      await applyOne(client, migration, options.logger);
      options.logger.info('db.migration.applied', { migration: migration.name, checksum: migration.checksum });
    }
    options.logger.info('db.migrations.done', { applied: pending.length, total: files.length });
    return pending.map((migration) => migration.name);
  } finally {
    await client.end();
  }
}

async function applyOne(client: pg.Client, migration: Migration, logger: Logger): Promise<void> {
  await client.query('begin');
  try {
    await client.query(MARK, [migration.name]);
    // eslint-disable-next-line agentx/no-string-built-sql -- Migration files are reviewed SQL from the repository, checksummed and run by the migration role; they are the one place SQL text comes from a file.
    await client.query(migration.sql);
    const { rows } = await client.query<{ name: string | null }>(READ_MARK);
    if (rows[0]?.name !== migration.name) {
      throw new Error(
        'the file ended its own transaction (a COMMIT or ROLLBACK in it), so part of it may be committed',
      );
    }
    await client.query('insert into migrations.applied (name, checksum) values ($1, $2)', [
      migration.name,
      migration.checksum,
    ]);
    await client.query('commit');
  } catch (error) {
    // If the rollback fails too, the connection is gone, and closing it rolls back anyway.
    await client.query('rollback').catch((rollbackError: unknown) => {
      logger.warn('db.migration.rollback_failed', { migration: migration.name, err: rollbackError });
    });
    throw new MigrationFailed(migration.name, error);
  }
}
