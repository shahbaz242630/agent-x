// Schema migrations (ADR-001): plain SQL files in db/migrations, applied in
// order by the migration role (agentx_owner) at deploy time, never when the
// app starts. Migrations only go forward; a mistake is fixed by a new one.
//
// - Files are named NNNN_words.sql and numbered 0001 upward with no gaps, so a
//   misnamed or missing file stops the run instead of being skipped.
// - Each file runs in its own transaction with its row in the ledger
//   (migrations.applied), so it is applied completely or not at all. A file
//   that would begin or end a transaction itself is refused before anything
//   runs, and a check after each file backs that up.
// - After each file, the session's settings, role and temporary tables are
//   reset, so a SET in one file can't change what the next one does. Every
//   file then behaves the same whether it runs alone or in a batch.
// - The ledger keeps each file's SHA-256. A file changed after it was applied,
//   or a ledger row this build has no file for, stops the run.
// - A session-level advisory lock lets only one run work at a time. Closing
//   the connection releases it, even after a crash.
// - A file waits at most LOCK_TIMEOUT_MS for each lock it takes. A file that
//   needs a table to itself would otherwise wait behind any open transaction
//   on it, and every new query on that table would queue behind the file, so
//   the app would stall until the job was stopped. A wait that runs out rolls
//   the file back, and it is tried again after a pause, LOCK_TRIES in all.
import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

import pg from 'pg';

import type { Logger } from '../observability/index.ts';
import { type DatabaseConnectionOptions, poolConfig } from './database.ts';
import { transactionControl } from './sql-statements.ts';
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

/**
 * The open transaction's ID. Read before and after a file runs: if it changed,
 * the file ended our transaction (the statement after a COMMIT runs in a new one).
 */
const TRANSACTION_ID = 'select pg_catalog.pg_current_xact_id()::text as id';

/**
 * What a file may have changed for the rest of the session. DISCARD ALL would
 * also drop the advisory lock, so the parts are reset one by one.
 */
const RESET_SESSION = 'reset all; reset role; discard temp';

/** How long a file waits for each lock before it is rolled back. */
export const LOCK_TIMEOUT_MS = 10_000;
/** Tries of one file whose lock wait ran out, the first included. */
export const LOCK_TRIES = 3;
/** The pause before trying such a file again. */
const LOCK_RETRY_PAUSE_MS = 5000;

/** Postgres's `lock_not_available`: a lock wait ran out. */
const LOCK_NOT_AVAILABLE = '55P03';

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

/**
 * A migration ended its own transaction, so part of it may be committed and it
 * has no ledger row. Running it again could apply that part twice: repair the
 * database by hand first.
 */
export class MigrationNotAtomic extends Error {
  readonly migration: string;

  constructor(migration: string) {
    super(
      `Migration ${migration} ended its own transaction, so part of it may be committed. Repair the database by hand; do not run it again as it is`,
    );
    this.name = 'MigrationNotAtomic';
    this.migration = migration;
  }
}

/** Whether a migration failed only because a lock wait ran out, so it may be tried again. */
export function isLockTimeout(error: unknown): error is MigrationFailed {
  const cause = error instanceof MigrationFailed ? error.cause : undefined;
  return typeof cause === 'object' && cause !== null && 'code' in cause && cause.code === LOCK_NOT_AVAILABLE;
}

/** Reads and checks every migration file in the folder, in order. Throws MigrationRefused listing every problem. */
export async function loadMigrations(directory: string): Promise<Migration[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const problems: string[] = [];
  const migrations: Migration[] = [];

  // By UTF-16 code unit, so the order is the same on every machine and locale.
  for (const entry of entries.toSorted((a, b) => Number(a.name > b.name) - Number(a.name < b.name))) {
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
    const control = transactionControl(sql);
    if (control.length > 0) {
      problems.push(
        `${entry.name} has ${control.join(', ')}: each file already runs in one transaction, so it must not begin or end one (write function bodies in $$ quotes, not BEGIN ATOMIC)`,
      );
    }
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
  /** Each lock's wait and the pause before a retry; LOCK_TIMEOUT_MS and 5 s when not given. Tests shorten them. */
  readonly lockWait?: { readonly timeoutMs: number; readonly pauseMs: number };
}

/** Applies every migration not yet applied, in order, and returns their names. */
export async function runMigrations(options: MigrationOptions): Promise<string[]> {
  const files = await loadMigrations(options.directory);
  // One connection for the whole run, opened as it starts: on Azure the
  // owner-login alert (postgres.bicep) takes any second login beside a start
  // of the migration job for someone else's.
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
    const lockWait = options.lockWait ?? { timeoutMs: LOCK_TIMEOUT_MS, pauseMs: LOCK_RETRY_PAUSE_MS };
    for (const migration of pending) {
      await applyWithLockRetries(client, migration, options.logger, lockWait);
      options.logger.info('db.migration.applied', { migration: migration.name, checksum: migration.checksum });
    }
    options.logger.info('db.migrations.done', { applied: pending.length, total: files.length });
    return pending.map((migration) => migration.name);
  } finally {
    await client.end();
  }
}

/** Applies one migration, trying it again after a pause when only a lock wait ran out, LOCK_TRIES in all. */
async function applyWithLockRetries(
  client: pg.Client,
  migration: Migration,
  logger: Logger,
  lockWait: { readonly timeoutMs: number; readonly pauseMs: number },
): Promise<void> {
  for (let tryNumber = 1; ; tryNumber += 1) {
    try {
      await applyMigration(client, migration, logger, lockWait.timeoutMs);
      return;
    } catch (error) {
      if (tryNumber >= LOCK_TRIES || !isLockTimeout(error)) throw error;
      logger.warn('db.migration.lock_wait_ran_out', { migration: migration.name, try: tryNumber });
      await sleep(lockWait.pauseMs);
    }
  }
}

/**
 * Applies one migration in its own transaction, with its ledger row, then
 * resets the session. Exported for its tests; runMigrations is the way in.
 */
export async function applyMigration(
  client: pg.Client,
  migration: Migration,
  logger: Logger,
  lockTimeoutMs = LOCK_TIMEOUT_MS,
): Promise<void> {
  await client.query('begin');
  let stillInOurTransaction: boolean;
  try {
    // LOCAL (the third argument), so it ends with the file's transaction. set_config takes the wait as a parameter.
    // eslint-disable-next-line agentx/tenant-setting-only-in-with-tenant -- Transaction-local lock_timeout on the runner's own unpooled client, not a tenant or session setting.
    await client.query("select pg_catalog.set_config('lock_timeout', $1, true)", [`${lockTimeoutMs}ms`]);
    const before = await client.query<{ id: string }>(TRANSACTION_ID);
    // eslint-disable-next-line agentx/no-string-built-sql -- Migration files are reviewed SQL from the repository, checksummed and run by the migration role; they are the one place SQL text comes from a file.
    await client.query(migration.sql);
    const after = await client.query<{ id: string }>(TRANSACTION_ID);
    stillInOurTransaction = after.rows[0]?.id === before.rows[0]?.id;
    if (stillInOurTransaction) {
      await client.query('insert into migrations.applied (name, checksum) values ($1, $2)', [
        migration.name,
        migration.checksum,
      ]);
      await client.query('commit');
    }
  } catch (error) {
    // If the rollback fails too, the connection is gone, and closing it rolls back anyway.
    await client.query('rollback').catch((rollbackError: unknown) => {
      logger.warn('db.migration.rollback_failed', { migration: migration.name, err: rollbackError });
    });
    throw new MigrationFailed(migration.name, error);
  }
  // loadMigrations refuses files that would do this; this check backs it up.
  if (!stillInOurTransaction) throw new MigrationNotAtomic(migration.name);
  await client.query(RESET_SESSION);
}
