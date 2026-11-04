// 4D2e E10 (PL-29): the chain repair's command as its job runs it, against a
// real Postgres. The drill's copy is this same database by another host name,
// as for the restore check and the plan's command, so the chain here is whole
// and its plan writes nothing: the repair's rules themselves are proven in
// chain-restore.db.test.ts. Here: the request, the owner's role and nothing
// else, the settings, the evidence records, and every refusal before a write.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { type Output } from '@agentx/platform/observability';
import {
  createTestDatabase,
  LogCapture,
  type TestDatabase,
  testLogger,
  type TestRole,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { planChainRecovery, planDigest, planFile } from './chain-recovery.ts';
import { OWNER_LOGIN_NOTE, runChainRestore } from './chain-restore-main.ts';
import { createOrganizationAsOperator, type OperatorTables } from './create-organization.ts';
import type { OperatorProcess } from './main.ts';
import { chainRestoreRequest } from './request.ts';

/** Each answer pushed overrides one read-only proof, in the order the command asks. */
const faults = vi.hoisted(() => ({ readOnly: [] as boolean[], roles: [] as string[][] }));

// Each answer pushed overrides one role check, in the order the command asks: the copy's, then the live server's.
vi.mock('@agentx/core/modules/audit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/core/modules/audit')>();
  return {
    ...actual,
    repairRoleProblems: async (...args: Parameters<typeof actual.repairRoleProblems>) => {
      // Taken as it is called, not as it answers: the two checks run together.
      const forced = faults.roles.shift();
      const said = await actual.repairRoleProblems(...args);
      return forced ?? said;
    },
  };
});

vi.mock('@agentx/platform/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/platform/db')>();
  return {
    ...actual,
    transactionsReadOnly: async (...args: Parameters<typeof actual.transactionsReadOnly>) => {
      const said = await actual.transactionsReadOnly(...args);
      return faults.readOnly.shift() ?? said;
    },
  };
});

afterEach(() => {
  faults.readOnly = [];
  faults.roles = [];
});

const server = inject('postgres');
/** The operator's keys, which made the organisation; the repair is given the MAC key and the public half alone. */
const operatorKeyFiles = writeTestKeys(['audit-mac', 'field-encryption', 'operator-signing']);
const operatorKeys = loadKeys({ directory: operatorKeyFiles.directory, current: {} }, [
  'audit-mac',
  'field-encryption',
  'operator-signing',
]);
/** writeTestKeys gives each purpose its place's value: audit-mac first, so the same key as the operator's. */
const restoreKeyFiles = writeTestKeys(['audit-mac']);
const operatorHalf = String(
  operatorKeys.describe().find((key) => key.purpose === 'operator-signing')?.versions[0]?.publicKey,
);
writeFileSync(path.join(restoreKeyFiles.directory, 'public-operator-signing-v1'), `${operatorHalf}\n`);

const folder = mkdtempSync(path.join(tmpdir(), 'agentx-chain-restore-'));
const evidence = path.join(folder, 'evidence');
const anchorsFolder = path.join(folder, 'anchors');
const anchorKeyFiles = writeTestKeys(['audit-anchor']);
const anchorHalf = String(
  loadKeys({ directory: anchorKeyFiles.directory, current: {} }, ['audit-anchor']).describe()[0]?.versions[0]
    ?.publicKey,
);

let database: TestDatabase;
let operator: Database<OperatorTables>;
let orgId: string;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  operator = createDatabase<OperatorTables>({ ...database.connection('operator'), maxConnections: 1 }, testLogger());
  orgId = uuidV7Ids.next();
  await createOrganizationAsOperator(
    operator,
    { keys: operatorKeys, ids: uuidV7Ids, logger: testLogger() },
    { orgId, name: `Chain Restore Command ${orgId.slice(-6)}`, release: 'r-1', run: null },
  );
});

afterAll(async () => {
  await operator.destroy();
  await database.drop();
  for (const files of [operatorKeyFiles, restoreKeyFiles, anchorKeyFiles]) files.remove();
  rmSync(folder, { recursive: true, force: true });
});

class FakeProcess implements OperatorProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  exitCode: number | string | null | undefined = undefined;
}

/** A repair's environment against this database: the owner's login, the copy by another host name. */
function envFor(role: TestRole = 'owner', overrides: Record<string, string> = {}): Record<string, string> {
  const connection = database.connection(role);
  return {
    AGENTX_ENV: 'test',
    AGENTX_RELEASE: 'r-restore',
    AGENTX_DB_HOST: connection.host,
    AGENTX_DB_PORT: String(connection.port),
    AGENTX_DB_NAME: connection.database,
    AGENTX_DB_USER: connection.user,
    AGENTX_DB_PASSWORD: connection.password,
    AGENTX_DB_TLS: 'disable',
    AGENTX_KEYS_DIR: restoreKeyFiles.directory,
    AGENTX_DB_DRILL_HOST: connection.host === 'localhost' ? '127.0.0.1' : 'localhost',
    AGENTX_EVIDENCE_DIR: evidence,
    AGENTX_AUDIT_ANCHORS_DIR: anchorsFolder,
    AGENTX_AUDIT_ANCHOR_PUBLIC_KEYS: `1:${anchorHalf}`,
    ...overrides,
  };
}

async function run(argv: readonly string[], env: Record<string, string> = envFor()) {
  const host = new FakeProcess();
  const capture = new LogCapture();
  const code = await runChainRestore(host, { argv, env, destination: capture });
  const lines = capture.lines();
  return {
    code,
    host,
    events: lines.map((line) => String(line.event)),
    line: (event: string) => lines.find((line) => line.event === event),
  };
}

/** The plan the operator reads now, kept in the evidence store as the plan's command keeps it: its ID and digest. */
async function planned(): Promise<{ planId: string; digest: string }> {
  const reader = createDatabase<OperatorTables>(
    { ...database.connection('operator'), maxConnections: 1, readOnly: true },
    testLogger(),
  );
  try {
    const plan = await planChainRecovery({ copy: reader, live: reader, keys: operatorKeys, orgId, anchor: undefined });
    const planId = uuidV7Ids.next();
    const facts = { planId, orgId, release: 'r-1', run: null, anchor: undefined };
    mkdirSync(path.join(evidence, orgId), { recursive: true });
    writeFileSync(path.join(evidence, orgId, `chain-recovery-${planId}.ndjson`), planFile(plan, facts));
    return { planId, digest: planDigest(plan, orgId, undefined) };
  } finally {
    await reader.destroy();
  }
}

/** A plan's file whose first line says what a test needs, and its ID: by default this organisation's, made, with `digest`. */
function stored(digest: string, summary: Readonly<Record<string, unknown>> = {}, text?: string): string {
  const planId = uuidV7Ids.next();
  mkdirSync(path.join(evidence, orgId), { recursive: true });
  writeFileSync(
    path.join(evidence, orgId, `chain-recovery-${planId}.ndjson`),
    text ?? `${JSON.stringify({ k: 'plan', planId, orgId, ok: true, digest, ...summary })}\n`,
  );
  return planId;
}

/** A request file asking for a repair, and the repair's ID. */
function requested(words: string | readonly string[]): string {
  const file = path.join(folder, `request-${uuidV7Ids.next()}`);
  writeFileSync(file, typeof words === 'string' ? words : JSON.stringify(words));
  return file;
}

const records = (restoreId: string, which: 'start' | 'outcome') =>
  JSON.parse(readFileSync(path.join(evidence, orgId, `chain-restore-${restoreId}-${which}.ndjson`), 'utf8')) as Record<
    string,
    unknown
  >;

describe('4D2e E10 the chain repair, run as its job runs it', () => {
  it('repairs as the owner, says the owner-login alert fires by design, keeps both records, never twice', async () => {
    const { planId, digest } = await planned();
    const restoreId = uuidV7Ids.next();
    const asked = requested(chainRestoreRequest({ orgId, planId, digest, id: restoreId }));

    const { code, events, line, host } = await run(['--request', asked]);

    expect(events).toEqual([
      'operator.starting',
      'operator.chain_restore_owner_login',
      'audit.anchors_read',
      'db.schema_checked',
      'operator.chain_restored',
    ]);
    expect(code).toBe(0);
    expect(host.exitCode).toBe(0);
    expect(line('operator.starting')).toMatchObject({ command: 'chain-restore', role: 'agentx_owner' });
    expect(line('operator.chain_restore_owner_login')).toMatchObject({ restoreId, note: OWNER_LOGIN_NOTE });
    expect(line('operator.chain_restored')).toMatchObject({
      orgId,
      restoreId,
      planId,
      ok: true,
      putBack: 0,
      replaced: 0,
      removed: 0,
      holdKept: true,
    });
    const facts = { restoreId, planId, orgId, digest, discardFork: false, release: 'r-restore', run: null };
    expect(records(restoreId, 'start')).toEqual({ k: 'restore_start', ...facts });
    expect(records(restoreId, 'outcome')).toMatchObject({ k: 'restore', ...facts, ok: true });

    const again = await run(['--request', asked]);
    expect(again.code).toBe(1);
    expect(again.line('operator.done_before')).toMatchObject({ command: 'chain-restore', restoreId });
    expect(again.events).not.toContain('operator.chain_restored');
  });

  it('refuses a stale digest, and keeps that as its outcome', async () => {
    const restoreId = uuidV7Ids.next();
    const asked = requested(
      chainRestoreRequest({ orgId, planId: stored('a'.repeat(64)), digest: 'a'.repeat(64), id: restoreId }, true),
    );
    const { code, line } = await run(['--request', asked]);
    expect(code).toBe(1);
    expect(line('operator.chain_restore_refused')).toMatchObject({ restoreId, ok: false, reason: 'stale' });
    expect(records(restoreId, 'outcome')).toMatchObject({ ok: false, reason: 'stale', discardFork: true });
  });

  it("an outcome's record already there: said, and the run fails", async () => {
    const restoreId = uuidV7Ids.next();
    const asked = requested(
      chainRestoreRequest({ orgId, planId: stored('b'.repeat(64)), digest: 'b'.repeat(64), id: restoreId }),
    );
    writeFileSync(path.join(evidence, orgId, `chain-restore-${restoreId}-outcome.ndjson`), 'there\n');
    const { code, events } = await run(['--request', asked]);
    expect(code).toBe(1);
    expect(events.slice(-2)).toEqual(['operator.chain_restore_refused', 'operator.done_before']);
  });

  it('refuses any role but the owner, and settings without the stores or a copy, before it connects', async () => {
    const asked = requested(
      chainRestoreRequest({ orgId, planId: stored('c'.repeat(64)), digest: 'c'.repeat(64), id: uuidV7Ids.next() }),
    );
    const leftOut = new Set(['AGENTX_EVIDENCE_DIR', 'AGENTX_AUDIT_ANCHORS_DIR', 'AGENTX_DB_DRILL_HOST']);
    const env = Object.fromEntries(Object.entries(envFor('operator')).filter(([name]) => !leftOut.has(name)));
    const bare = await run(['--request', asked], env);
    expect(bare.code).toBe(1);
    expect(bare.line('operator.refused')).toMatchObject({
      problems: [
        'AGENTX_DB_USER must be agentx_owner: only the owner may repair a chain',
        expect.stringMatching(/^no store for an audit export/),
        expect.stringMatching(/^no store of the chains' anchors/),
        expect.stringMatching(/^AGENTX_DB_DRILL_HOST must name the drill's copy/),
      ],
    });
  });

  it('refuses a copy that is not read-only', async () => {
    const asked = () =>
      requested(
        chainRestoreRequest({ orgId, planId: stored('d'.repeat(64)), digest: 'd'.repeat(64), id: uuidV7Ids.next() }),
      );
    faults.readOnly.push(false);
    const writable = await run(['--request', asked()]);
    expect(writable.code).toBe(1);
    expect(writable.line('operator.refused')).toMatchObject({
      problems: ["the drill's copy is not read-only, so nothing was read"],
    });
  });

  it('refuses a connection whose role could get round the walls, naming the side', async () => {
    faults.roles.push(['it can bypass row-level security'], ['the session has switched to another role (SET ROLE)']);
    const asked = requested(
      chainRestoreRequest({ orgId, planId: stored('9'.repeat(64)), digest: '9'.repeat(64), id: uuidV7Ids.next() }),
    );
    const { code, line } = await run(['--request', asked]);
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({
      problems: [
        "the drill's copy: it can bypass row-level security",
        'the live server: the session has switched to another role (SET ROLE)',
      ],
    });
  });

  it("refuses when the anchors' store can't be read whole", async () => {
    const unreadable = path.join(folder, 'not-a-folder');
    writeFileSync(unreadable, 'a file, not a folder\n');
    const asked = requested(
      chainRestoreRequest({ orgId, planId: stored('e'.repeat(64)), digest: 'e'.repeat(64), id: uuidV7Ids.next() }),
    );
    const { code, line } = await run(['--request', asked], envFor('owner', { AGENTX_AUDIT_ANCHORS_DIR: unreadable }));
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({
      problems: [expect.stringMatching(/^the chains' anchors' store couldn't be read whole/)],
    });
  });

  it('a failure part-way is said, the run fails', async () => {
    const asked = requested(
      chainRestoreRequest({ orgId, planId: stored('f'.repeat(64)), digest: 'f'.repeat(64), id: uuidV7Ids.next() }),
    );
    // The drill's copy named but not there: its connection fails after the plan is read.
    const { code, line } = await run(
      ['--request', asked],
      envFor('owner', { AGENTX_DB_DRILL_HOST: 'no-copy.invalid' }),
    );
    expect(code).toBe(1);
    expect(line('operator.failed')).toMatchObject({ command: 'chain-restore' });
  });

  it("refuses, before connecting, a plan that isn't in the evidence store, isn't this one, was refused, or has another digest", async () => {
    const digest = '7'.repeat(64);
    const cases: readonly (readonly [string, RegExp])[] = [
      [
        uuidV7Ids.next(),
        /^the plan \S+ has no readable file in the evidence store \(.+\): make the plan first, or check its ID$/,
      ],
      [stored(digest, {}, 'not json\n'), /^the plan \S+ has no readable file in the evidence store/],
      [stored(digest, { orgId: uuidV7Ids.next() }), /^the file \S+ is not this organisation's plan \S+$/],
      [stored(digest, { k: 'row' }), /^the file \S+ is not this organisation's plan/],
      [stored(digest, { planId: uuidV7Ids.next() }), /^the file \S+ is not this organisation's plan/],
      [stored(digest, { ok: false, reason: 'fork' }), /^the plan \S+ was refused \(fork\): there is nothing to apply$/],
      [stored('8'.repeat(64)), /^the digest asked is not the plan \S+'s: copy it again from the plan's line$/],
      [stored(digest, {}, '[1]\n'), /^the file \S+ is not this organisation's plan/],
    ];
    for (const [planId, problem] of cases) {
      const restoreId = uuidV7Ids.next();
      const asked = requested(chainRestoreRequest({ orgId, planId, digest, id: restoreId }));
      const { code, events, line } = await run(['--request', asked]);
      expect({ planId, code, events }).toEqual({
        planId,
        code: 1,
        events: ['operator.starting', 'operator.chain_restore_owner_login', 'operator.refused'],
      });
      expect(line('operator.refused')).toMatchObject({ restoreId, problems: [expect.stringMatching(problem)] });
    }
  });
});

describe('4D2e E10 the repair refuses a request it cannot read, before it connects', () => {
  const id = () => uuidV7Ids.next();
  it.each([
    ['typed, not from a file', ['chain-restore', '--org', id()], /^chain-restore runs only from a request file/],
    ['a file that is not a list', ['--request', 'FILE:{}'], /^the request file must hold a JSON list/],
    [
      'another shape',
      ['--request', `FILE:${JSON.stringify(['chain-restore', '--org', id(), '--id', id()])}`],
      /^the request file holds chain-restore --org/,
    ],
    [
      'a flag other than the named one',
      [
        '--request',
        `FILE:${JSON.stringify(['chain-restore', '--org', id(), '--plan', id(), '--digest', 'a'.repeat(64), '--id', id(), '--force'])}`,
      ],
      /^the request file holds chain-restore --org/,
    ],
  ])('%s', async (_case, argv, problem) => {
    const words = argv.map((word) => (word.startsWith('FILE:') ? requested(word.slice(5)) : word));
    const { code, line, events } = await run(words);
    expect(code).toBe(1);
    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')).toMatchObject({ problems: [expect.stringMatching(problem)] });
  });

  it('names every ID and the digest that are not as they must be', async () => {
    const asked = requested(['chain-restore', '--org', 'X', '--plan', 'Y', '--digest', 'Z', '--id', 'W']);
    const { line } = await run(['--request', asked]);
    expect(line('operator.refused')).toMatchObject({
      problems: [
        "the organisation's ID must be a UUIDv7, in lower case",
        "the plan's ID must be a UUIDv7, in lower case",
        "the plan's digest must be 64 lower-case hex digits",
        "the repair's ID must be a UUIDv7, in lower case",
      ],
    });
  });

  it("refuses its settings or its keys: the operator's own signing key is never mounted here", async () => {
    const missing = await run(['--request', 'x'], {});
    expect(missing.code).toBe(1);
    expect(missing.events).toEqual(['operator.start_refused']);
    const signing = await run(['--request', 'x'], envFor('owner', { AGENTX_KEYS_DIR: operatorKeyFiles.directory }));
    expect(signing.events).toEqual(['operator.start_refused']);
    const crashed = await run(['--request', 'x'], envFor('owner', { AGENTX_KEYS_DIR: path.join(folder, 'none') }));
    expect(crashed.events).toEqual(['operator.start_refused']);
  });
});
