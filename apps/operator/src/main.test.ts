// B1c: what the operator's command refuses before it connects to a database,
// and that it never repeats what was typed or what its job's request file
// holds (B1c-2a). Its settings point at a port
// nothing listens on, so a refusal that connected first would say the
// database was unavailable instead. What it does once connected is
// main.db.test.ts.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { PURPOSES } from '@agentx/platform/keys';
import type { Output } from '@agentx/platform/observability';
import { LogCapture, writeTestKeys } from '@agentx/testing';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

import { type OperatorProcess, REQUEST_LIMIT_BYTES, REQUEST_USAGE, runOperator, USAGE } from './main.ts';

/** Failures no real input can cause (a bug, a broken disk), switched on by a test and off after it. */
const faults = vi.hoisted(() => ({
  keys: undefined as Error | undefined,
  name: undefined as Error | undefined,
  read: undefined as Error | undefined,
}));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    openSync: (...args: Parameters<typeof actual.openSync>) => {
      if (faults.read !== undefined) throw faults.read;
      return actual.openSync(...args);
    },
  };
});

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
  faults.read = undefined;
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

/** A new organisation's ID, as jobs.ts makes one for a request (a UUIDv7). */
const NEW_ID = '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b';

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
    ['an ID, which only a request file names', ['create-organization', '--name', 'Quartzite Other Co', '--id', NEW_ID]],
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

  it("refuses a run name Azure wouldn't give, naming the rule, never the name, before anything else", async () => {
    const { code, host, events, line, text } = await run(['create-organization', '--name', NAME], {
      ...ENV,
      CONTAINER_APP_JOB_EXECUTION_NAME: 'Quartzite Run',
    });

    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(events).toEqual(['operator.start_refused']);
    expect(line('operator.start_refused')?.problems).toEqual([
      "CONTAINER_APP_JOB_EXECUTION_NAME: must be a job run's name as Azure gives it, at most 64 characters: lower-case words of letters and digits joined by single hyphens, the first starting with a letter",
    ]);
    expect(text).not.toContain('Quartzite');
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

describe("B1c-2a the request the operator's job reads from its file", () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-request-'));
  afterAll(() => {
    rmSync(folder, { recursive: true, force: true });
  });
  let written = 0;
  /** A request file holding exactly these bytes. */
  const requestFile = (contents: string | Uint8Array): string => {
    written += 1;
    const file = path.join(folder, `request-${String(written)}`);
    writeFileSync(file, contents);
    return file;
  };
  /** A request as jobs.ts writes one: the words, then the new organisation's ID. */
  const request = (name: string, id: string = NEW_ID): string =>
    JSON.stringify(['create-organization', '--name', name, '--id', id]);
  const reached = ['operator.starting', 'operator.database_unavailable'];
  const shape = `the request file holds ${REQUEST_USAGE} as a JSON list, and nothing else`;
  const notList = "the request file must hold a JSON list of the command's words";
  const badId = "the organisation's ID must be a UUIDv7, in lower case";

  it('reads the words the file holds as if they were typed, repeating none of them', async () => {
    const { code, events, line, text } = await run(['--request', requestFile(request(NAME))]);

    expect(code).toBe(1);
    expect(events).toEqual(reached);
    expect(line('operator.starting')).toMatchObject({ command: 'create-organization' });
    expect(text).not.toContain(NAME);
  });

  it(`reads a file of exactly ${String(REQUEST_LIMIT_BYTES)} bytes, and refuses one byte more`, async () => {
    const full = `${request(NAME)}${' '.repeat(REQUEST_LIMIT_BYTES - request(NAME).length)}`;

    expect((await run(['--request', requestFile(full)])).events).toEqual(reached);
    const over = await run(['--request', requestFile(`${full} `)]);
    expect(over.events).toEqual(['operator.refused']);
    expect(over.line('operator.refused')?.problems).toEqual([
      `the request file holds more than ${String(REQUEST_LIMIT_BYTES)} bytes`,
    ]);
    expect(over.text).not.toContain(NAME);
  });

  it('reads a file that starts with a byte-order mark, and refuses one that is not UTF-8, never repairing it', async () => {
    const mark = String.fromCharCode(0xfeff);
    expect((await run(['--request', requestFile(`${mark}${request(NAME)}`)])).events).toEqual(reached);
    // An accented name in Latin-1: decoded loosely it would hold a replacement character, kept for good.
    const accented = `Caf${String.fromCharCode(0xe9)} Quartzite Co`;
    const { events, line } = await run(['--request', requestFile(Buffer.from(request(accented), 'latin1'))]);
    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')?.problems).toEqual(["the request file isn't UTF-8 text"]);
  });

  it.each([
    [
      'the job as deployed, which holds no request',
      '[]',
      'no request was written for this run: the job holds none until a person writes one',
    ],
    ['text that is not JSON', 'create-organization --name Quartzite Other Co', notList],
    ['an object', '{"create-organization":"Quartzite Other Co"}', notList],
    ['a word that is not text', '["create-organization","--name",["Quartzite Other Co"]]', notList],
    ['a command it does not know', '["delete-organization","--name","Quartzite Other Co"]', shape],
    ['a second request inside it', '["--request","Quartzite Other Co"]', shape],
    [
      'no ID, which would let it make a second organisation',
      '["create-organization","--name","Quartzite Other Co"]',
      shape,
    ],
    ['an ID with no value', '["create-organization","--name","Quartzite Other Co","--id"]', shape],
    [
      'another option in place of the ID',
      JSON.stringify(['create-organization', '--name', 'Quartzite Other Co', '--org', NEW_ID]),
      shape,
    ],
    [
      'something after the ID',
      JSON.stringify(['create-organization', '--name', 'Quartzite Other Co', '--id', NEW_ID, '--force']),
      shape,
    ],
    ['an ID in capitals', request('Quartzite Other Co', NEW_ID.toUpperCase()), badId],
    [
      'a random ID, not a time-ordered one',
      request('Quartzite Other Co', '6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f'),
      badId,
    ],
    ['an ID with its variant wrong', request('Quartzite Other Co', '0199a1b2-c3d4-7e5f-ca6b-7c8d9e0f1a2b'), badId],
    ['an ID with more after it', request('Quartzite Other Co', `${NEW_ID}0`), badId],
    ['an ID with more before it', request('Quartzite Other Co', `0${NEW_ID}`), badId],
  ])('refuses %s, repeating nothing it holds', async (_what, contents, problem) => {
    const { code, host, events, line, text } = await run(['--request', requestFile(contents)]);

    expect(code).toBe(1);
    expect(host.exitCode).toBe(1);
    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')?.problems).toEqual([problem]);
    expect(text).not.toContain('Quartzite');
  });

  it('refuses a name the file holds that breaks the rules, naming the rule', async () => {
    const { events, line, text } = await run(['--request', requestFile(request(' Leading Quartzite Co'))]);

    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')?.problems).toEqual(['the name starts or ends with a space']);
    expect(text).not.toContain('Quartzite');
  });

  it.each([
    ['no file', ['--request']],
    ['more than the file', ['--request', path.join(folder, 'request-0'), 'Quartzite Other Co']],
  ])('refuses %s after --request', async (_what, argv) => {
    const { events, line, text } = await run(argv);

    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')?.problems).toEqual([
      '--request takes the one file that holds the request, and nothing else',
    ]);
    expect(text).not.toContain('Quartzite');
  });

  it('lets an unexpected error reading the file end the run, never taking it for a refusal', async () => {
    faults.read = new TypeError('a bug reading the request');

    await expect(run(['--request', requestFile(request(NAME))])).rejects.toThrow('a bug reading the request');
  });

  it("says why a file can't be read by the system's reason alone, and refuses anything but a plain file", async () => {
    const missing = await run(['--request', path.join(folder, 'never-written')]);
    expect(missing.events).toEqual(['operator.refused']);
    expect(missing.line('operator.refused')?.problems).toEqual(["the request file can't be read (ENOENT)"]);
    // A folder, as a pipe or a device would be: refused by what was opened, before any read.
    const notAFile = await run(['--request', folder]);
    expect(notAFile.events).toEqual(['operator.refused']);
    expect(notAFile.line('operator.refused')?.problems).toEqual(["the request file isn't a plain file"]);
  });
  // A pipe with no writer is refused at once too: tooling/checks/operator-request.test.ts, as a process of its own.
});
