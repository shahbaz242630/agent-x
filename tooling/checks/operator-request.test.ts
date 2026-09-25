// B1c-2a: the operator's command never waits on its request file. Opened
// without waiting and checked as opened (apps/operator), a pipe with no writer
// is refused at once. Run as a process of its own, under a hard limit: an open
// that waited would block the whole thread, where no timer in the test's own
// could end it. Here rather than beside the command, since the product's code
// and its tests never start a process (the module boundaries). Windows has no
// such pipe; CI's runners are Linux.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { type TestKeys, writeTestKeys } from '../../packages/testing/src/keys.ts';

const COMMAND = path.resolve('apps/operator/src/main.ts');

describe.skipIf(process.platform === 'win32')("B1c-2a the operator's request file", () => {
  // Made and removed here, not as the file loads: where the tests are skipped, nothing is left behind.
  let keys: TestKeys;
  let folder: string;
  beforeAll(() => {
    keys = writeTestKeys(['audit-mac', 'field-encryption']);
    folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-pipe-'));
  });
  afterAll(() => {
    keys.remove();
    rmSync(folder, { recursive: true, force: true });
  });

  // The test's own limit sits above the child's, so a waiting open shows as the child stopped, not a timeout.
  it('refuses a pipe with no writer at once, never waiting on it', { timeout: 30_000 }, () => {
    const pipe = path.join(folder, 'a-pipe');
    expect(spawnSync('mkfifo', [pipe]).status).toBe(0);

    const ran = spawnSync(process.execPath, [COMMAND, '--request', pipe], {
      // A database that isn't there: the refusal comes before any connection.
      env: {
        AGENTX_ENV: 'test',
        AGENTX_RELEASE: 'r-operator',
        AGENTX_DB_HOST: '127.0.0.1',
        AGENTX_DB_PORT: '1',
        AGENTX_DB_PASSWORD: 'app login for these tests',
        AGENTX_DB_TLS: 'disable',
        AGENTX_KEYS_DIR: keys.directory,
      },
      encoding: 'utf8',
      timeout: 15_000,
    });

    expect({ status: ran.status, signal: ran.signal }).toEqual({ status: 1, signal: null });
    const refused = ran.stdout
      .split('\n')
      .filter((text) => text.includes('"operator.refused"'))
      .map((text) => (JSON.parse(text) as { problems: unknown }).problems);
    expect(refused).toEqual([["the request file isn't a plain file"]]);
  });
});
