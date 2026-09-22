// B1c: what the operator's command refuses before it connects to a database,
// and that it never repeats what was typed. Its settings point at a port
// nothing listens on, so a refusal that connected first would say the
// database was unavailable instead. What it does once connected is
// main.db.test.ts.
import { PURPOSES } from '@agentx/platform/keys';
import type { Output } from '@agentx/platform/observability';
import { LogCapture, writeTestKeys } from '@agentx/testing';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

import { type OperatorProcess, runOperator, USAGE } from './main.ts';

/** Failures no real input can cause (a bug, a broken disk), switched on by a test and off after it. */
const faults = vi.hoisted(() => ({ keys: undefined as Error | undefined, name: undefined as Error | undefined }));

vi.mock('@agentx/platform/keys', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/platform/keys')>();
  return {
    ...actual,
    loadKeys: (...args: Parameters<typeof actual.loadKeys>) => {
      if (faults.keys !== undefined) throw faults.keys;
      return actual.loadKeys(...args);
    },
  };
});

vi.mock('@agentx/core/modules/organizations', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/core/modules/organizations')>();
  return {
    ...actual,
    organizationName: (name: string) => {
      if (faults.name !== undefined) throw faults.name;
      return actual.organizationName(name);
    },
  };
});

afterEach(() => {
  faults.keys = undefined;
  faults.name = undefined;
});

/** The command's one key, as the platform mounts it. */
const keys = writeTestKeys(['audit-mac']);
/** Every key, mounted where the command holds only one. */
const everyKey = writeTestKeys(PURPOSES);

afterAll(() => {
  keys.remove();
  everyKey.remove();
});

/** Plain words, so secret scanners ignore it. */
const APP_LOGIN = 'app login for these tests';

/** Settings for a database that isn't there: 127.0.0.1, port 1. */
const ENV: Record<string, string> = {
  AGENTX_ENV: 'test',
  AGENTX_RELEASE: 'r-operator',
  AGENTX_DB_HOST: '127.0.0.1',
  AGENTX_DB_PORT: '1',
  AGENTX_DB_PASSWORD: APP_LOGIN,
  AGENTX_DB_TLS: 'disable',
  AGENTX_KEYS_DIR: keys.directory,
};

const NAME = 'Zephyrine Trading Test Co';

class FakeProcess implements OperatorProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  exitCode: number | string | null | undefined = undefined;
}

async function run(argv: readonly string[], env: Record<string, string> = ENV) {
  const host = new FakeProcess();
  const capture = new LogCapture();
  const code = await runOperator(host, { argv, env, destination: capture });
  const lines = capture.lines();
  return {
    code,
    host,
    text: capture.text,
    events: lines.map((line) => String(line.event)),
    line: (event: string) => lines.find((line) => line.event === event),
  };
}

describe("B1c what the operator's command refuses before it connects", () => {
  it.each([
    ['nothing', []],
    ['no name', ['create-organization']],
    ['no name after --name', ['create-organization', '--name']],
    ['another command', ['delete-organization', '--name', 'Quartzite Other Co']],
    ['the name another way', ['create-organization', '--name=Quartzite Other Co']],
    ['the name first', ['--name', 'Quartzite Other Co', 'create-organization']],
    ['a wrong option before the name', ['create-organization', '--title', 'Quartzite Other Co']],
    ['something more', ['create-organization', '--name', 'Quartzite Other Co', '--force']],
    ['the name as two arguments', ['create-organization', '--name', 'Quartzite', 'Other Co']],
  ])('refuses %s, repeating nothing that was typed', async (_what, argv) => {
    const { code, host, events, line, text } = await run(argv);

    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')).toMatchObject({
      level: 'error',
      service: 'operator',
      env: 'test',
      release: 'r-operator',
      problems: [`the command is ${USAGE}, with the name quoted as one argument, and nothing else`],
    });
    expect(text).not.toContain('Quartzite');
  });

  it.each([
    ['a space at the start', ' Leading Space Co', ['the name starts or ends with a space']],
    [
      'a character no one can see',
      'Hidden\u200bJoin Co',
      ['the name holds a control, format, invisible or unassigned character'],
    ],
    ['more than 200 characters', 'Q'.repeat(201), ['the name is 1 to 200 characters']],
  ])('refuses a name with %s, naming the rule, never the name', async (_what, name, problems) => {
    const { code, events, line, text } = await run(['create-organization', '--name', name]);

    expect(code).toBe(1);
    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')?.problems).toEqual(problems);
    expect(text).not.toContain(name);
  });

  it("refuses a key mounted with it that it doesn't hold, before anything else", async () => {
    const { code, host, events, line } = await run(['create-organization', '--name', NAME], {
      ...ENV,
      AGENTX_KEYS_DIR: everyKey.directory,
    });

    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(events).toEqual(['operator.start_refused']);
    expect(line('operator.start_refused')).toMatchObject({ service: 'operator', env: 'unconfigured' });
    expect(line('operator.start_refused')?.problems).toEqual(
      PURPOSES.filter((purpose) => purpose !== 'audit-mac')
        .toSorted()
        .map((purpose) => `key-${purpose}-v1 is a key this process doesn't hold: only audit-mac may be mounted for it`),
    );
  });

  it("refuses another job's setting, naming it, never its value", async () => {
    const { code, events, line, text } = await run(['create-organization', '--name', NAME], {
      ...ENV,
      AGENTX_DB_MIGRATION_PASSWORD: 'owner login for these tests',
    });

    expect(code).toBe(1);
    expect(events).toEqual(['operator.start_refused']);
    expect(line('operator.start_refused')?.problems).toEqual([
      "AGENTX_DB_MIGRATION_PASSWORD belongs to the migration job (apps/migrate); the operator's command reads only the database, log and key settings it needs, as the app's role",
    ]);
    expect(text).not.toContain('owner login');
  });

  it('logs an unexpected failure at start with its error, not as settings problems', async () => {
    faults.keys = new Error('the keys folder went away mid-read');

    const { code, host, events, line } = await run(['create-organization', '--name', NAME]);

    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(events).toEqual(['operator.start_refused']);
    expect(line('operator.start_refused')).toMatchObject({ err: { message: 'the keys folder went away mid-read' } });
    expect(line('operator.start_refused')).not.toHaveProperty('problems');
  });

  it('lets an unexpected error checking the name end the run, never taking it for a refusal', async () => {
    faults.name = new TypeError('a bug in the name check');

    await expect(run(['create-organization', '--name', NAME])).rejects.toThrow('a bug in the name check');
  });

  it("says so when the database can't be reached, once it has checked what it was asked", async () => {
    const { code, host, events, line, text } = await run(['create-organization', '--name', NAME]);

    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(events).toEqual(['operator.starting', 'operator.database_unavailable']);
    expect(line('operator.starting')).toMatchObject({
      command: 'create-organization',
      role: 'agentx_app',
      keys: [expect.objectContaining({ purpose: 'audit-mac', current: 1 })],
    });
    expect(text).not.toContain(NAME);
    expect(text).not.toContain(APP_LOGIN);
  });
});
