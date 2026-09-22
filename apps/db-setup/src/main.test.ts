import { ServerSetupRefused } from '@agentx/platform/db';
import type { Output } from '@agentx/platform/observability';
import { findLeaks, LogCapture } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { failure, runDbSetup, type SetupProcess } from './main.ts';

describe('what a failed run reports: names, never logins', () => {
  it('a refused server: its problems', () => {
    const refused = new ServerSetupRefused(['agentx_app does not have the attributes db/bootstrap gives it']);
    expect(failure(refused)).toEqual({ problems: ['agentx_app does not have the attributes db/bootstrap gives it'] });
  });

  it('anything else: the error alone', () => {
    const other = new Error('connection refused');
    expect(failure(other)).toEqual({ err: other });
  });
});

/** Plain words standing in for a login put in the wrong setting, so secret scanners ignore it. */
const MISPLACED = 'value that must never be printed';

class FakeProcess implements SetupProcess {
  readonly written: string[] = [];
  readonly stdout: Output = { write: (chunk) => this.written.push(String(chunk)) > 0 };
  readonly stderr: Output = { write: (chunk) => this.written.push(String(chunk)) > 0 };
  exitCode: number | string | null | undefined = undefined;
}

describe('SEC-AV-03 the set-up job refuses to run on a bad config', () => {
  it('says why, naming each setting and never its value, and exits with a failure', async () => {
    const host = new FakeProcess();
    const capture = new LogCapture();
    const code = await runDbSetup(host, {
      env: {
        AGENTX_ENV: 'test',
        AGENTX_DB_HOST: 'db',
        AGENTX_DB_ADMIN_USER: 'postgres',
        AGENTX_DB_ADMIN_PASSWORD: MISPLACED,
        AGENTX_DB_OWNER_PASSWORD: MISPLACED,
        AGENTX_DB_PASSWORD: MISPLACED,
      },
      destination: capture,
    });
    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        level: 'error',
        env: 'unconfigured',
        service: 'db-setup',
        event: 'db_setup.start_refused',
        problems: [
          "AGENTX_DB_PASSWORD belongs to the app (apps/api) and the operator's command (apps/operator); the set-up job reads only the database, log and login settings it needs",
          'AGENTX_DB_APP_PASSWORD is required, or AGENTX_DB_APP_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
          'AGENTX_DB_BACKUP_PASSWORD is required, or AGENTX_DB_BACKUP_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
          'AGENTX_DB_ZITADEL_PASSWORD is required, or AGENTX_DB_ZITADEL_PASSWORD_FILE with the path of a file that holds it (a mounted secret)',
          'AGENTX_DB_OWNER_PASSWORD must be at least 24 characters of printable ASCII with no spaces, so it is out of reach of guessing and can be stored as a SCRAM verifier',
          'AGENTX_DB_ADMIN_PASSWORD and AGENTX_DB_OWNER_PASSWORD hold the same login; every role needs its own',
        ],
      }),
    ]);
    expect(findLeaks(capture.text, [MISPLACED])).toEqual([]);
    expect(host.written.join('')).toBe('');
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
    expect(await runDbSetup(host, { env, destination: capture })).toBe(1);
    expect(capture.lines()).toEqual([
      expect.objectContaining({
        event: 'db_setup.start_refused',
        err: expect.objectContaining({ type: 'Error', message: 'environment unreadable' }) as unknown,
      }),
    ]);
  });
});
