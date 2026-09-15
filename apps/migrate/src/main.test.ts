import { MigrationFailed, MigrationNotAtomic, MigrationRefused } from '@agentx/platform/db';
import type { Output } from '@agentx/platform/observability';
import { findLeaks, LogCapture } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { failure, type MigrateProcess, runMigrate } from './main.ts';

describe('what a failed run reports: names, never file contents', () => {
  it('a refused set of files: its problems', () => {
    const refused = new MigrationRefused(['0002_x.sql is out of sequence', '0003_y.sql is empty']);
    expect(failure(refused)).toEqual({ problems: ['0002_x.sql is out of sequence', '0003_y.sql is empty'] });
  });

  it('a migration that failed and was rolled back: its name and the error', () => {
    const failed = new MigrationFailed('0004_z.sql', new Error('division by zero'));
    expect(failure(failed)).toEqual({ migration: '0004_z.sql', err: failed });
  });

  it('a migration that ended its own transaction: its name and the error', () => {
    const notAtomic = new MigrationNotAtomic('0005_w.sql');
    expect(failure(notAtomic)).toEqual({ migration: '0005_w.sql', err: notAtomic });
  });

  it('anything else: the error alone', () => {
    const other = new Error('connection refused');
    expect(failure(other)).toEqual({ err: other });
  });
});

/** Plain words standing in for a secret put in the wrong setting, so secret scanners ignore it. */
const MISPLACED = 'value that must never be printed';

class FakeProcess implements MigrateProcess {
  readonly written: string[] = [];
  readonly stdout: Output = { write: (chunk) => this.written.push(String(chunk)) > 0 };
  readonly stderr: Output = { write: (chunk) => this.written.push(String(chunk)) > 0 };
  exitCode: number | string | null | undefined = undefined;
}

describe('SEC-AV-03 the migration job refuses to run on a bad config', () => {
  it('says why, naming each setting and never its value, and exits with a failure', async () => {
    const host = new FakeProcess();
    const capture = new LogCapture();
    const code = await runMigrate(host, {
      env: { AGENTX_ENV: MISPLACED, AGENTX_DB_HOST: 'db', AGENTX_DB_MIGRATION_PASSWORD: 'x', AGENTX_DB_PORT: 'five' },
      destination: capture,
    });
    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        level: 'error',
        env: 'unconfigured',
        service: 'migrate',
        event: 'migrate.start_refused',
        problems: [
          'AGENTX_ENV: must be one of: development, test, staging, production',
          'AGENTX_DB_PORT: must be a whole number, written in digits only',
        ],
      }),
    ]);
    expect(findLeaks(capture.text, [MISPLACED])).toEqual([]);
  });

  it('logs an unexpected error while reading the config as a refusal too', async () => {
    const env = Object.defineProperty({}, 'AGENTX_ENV', {
      enumerable: true,
      get: () => {
        throw new Error('environment unreadable');
      },
    });
    const host = new FakeProcess();
    const capture = new LogCapture();
    expect(await runMigrate(host, { env, destination: capture })).toBe(1);
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        event: 'migrate.start_refused',
        err: expect.objectContaining({ type: 'Error', message: 'environment unreadable' }) as unknown,
      }),
    ]);
  });

  it('guards stdout and stderr before anything else', async () => {
    const host = new FakeProcess();
    await runMigrate(host, { env: { AGENTX_ENV: MISPLACED }, destination: new LogCapture() });
    host.stdout.write('stray text from someone@example.com\n');
    host.stderr.write('stray error from 192.0.2.44\n');
    expect(host.written).toEqual(['stray text from [email]\n', 'stray error from [ip]\n']);
  });
});
