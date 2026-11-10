// PL-29 follow-up (Carry-Forward S175): the authority rows' plan and repair
// as the chain repair's job runs them, against a real Postgres. The drill's
// copy is this same database by another host name, as for the chain's repair
// command, so an organisation untouched plans nothing and its repair writes
// nothing: the rules themselves are proven in state-restore.db.test.ts. Here:
// the requests, the owner's role, the evidence records, and every refusal.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { type Output } from '@agentx/platform/observability';
import {
  createTestDatabase,
  LogCapture,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  type TestRole,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import { runChainRestore } from './chain-restore-main.ts';
import { createOrganizationAsOperator, type OperatorTables } from './create-organization.ts';
import type { OperatorProcess } from './main.ts';
import { stateRecoveryRequest, stateRestoreRequest } from './request.ts';
import { OWNER_LOGIN_NOTE } from './restore-job.ts';

/** Each answer pushed overrides one read-only proof, in the order the command asks: the copy's, then the live server's. */
const faults = vi.hoisted(() => ({ readOnly: [] as boolean[] }));

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
});

const server = inject('postgres');
/** The operator's keys, which made the organisation; the job is given the MAC key and the public halves alone. */
const operatorKeyFiles = writeTestKeys(['audit-mac', 'field-encryption', 'operator-signing', 'audit-rebase']);
const operatorKeys = loadKeys({ directory: operatorKeyFiles.directory, current: {} }, [
  'audit-mac',
  'field-encryption',
  'operator-signing',
  'audit-rebase',
]);
/** writeTestKeys gives each purpose its place's value: audit-mac first, so the same key as the operator's. */
const jobKeyFiles = writeTestKeys(['audit-mac']);
for (const purpose of ['operator-signing', 'audit-rebase'] as const) {
  const half = String(operatorKeys.describe().find((key) => key.purpose === purpose)?.versions[0]?.publicKey);
  writeFileSync(path.join(jobKeyFiles.directory, `public-${purpose}-v1`), `${half}\n`);
}

const folder = mkdtempSync(path.join(tmpdir(), 'agentx-state-restore-'));
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

/** A new organisation, made by the operator as the product makes one. */
async function newOrganization(): Promise<string> {
  const id = uuidV7Ids.next();
  await createOrganizationAsOperator(
    operator,
    { keys: operatorKeys, ids: uuidV7Ids, logger: testLogger() },
    { orgId: id, name: `State Restore Command ${id.slice(-6)}`, release: 'r-1', run: null },
  );
  return id;
}

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  operator = createDatabase<OperatorTables>({ ...database.connection('operator'), maxConnections: 1 }, testLogger());
  orgId = await newOrganization();
});

afterAll(async () => {
  await operator.destroy();
  await database.drop();
  for (const files of [operatorKeyFiles, jobKeyFiles, anchorKeyFiles]) files.remove();
  rmSync(folder, { recursive: true, force: true });
});

class FakeProcess implements OperatorProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  exitCode: number | string | null | undefined = undefined;
}

/** The job's environment against this database: the owner's login, the copy by another host name. */
function envFor(role: TestRole = 'owner', overrides: Record<string, string> = {}): Record<string, string> {
  const connection = database.connection(role);
  return {
    AGENTX_ENV: 'test',
    AGENTX_RELEASE: 'r-state',
    AGENTX_DB_HOST: connection.host,
    AGENTX_DB_PORT: String(connection.port),
    AGENTX_DB_NAME: connection.database,
    AGENTX_DB_USER: connection.user,
    AGENTX_DB_PASSWORD: connection.password,
    AGENTX_DB_TLS: 'disable',
    AGENTX_KEYS_DIR: jobKeyFiles.directory,
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

/** A request file holding these words, by its path. */
function requested(words: string | readonly string[]): string {
  const file = path.join(folder, `request-${uuidV7Ids.next()}`);
  writeFileSync(file, typeof words === 'string' ? words : JSON.stringify(words));
  return file;
}

const recordOf = (org: string, name: string) =>
  JSON.parse(readFileSync(path.join(evidence, org, name), 'utf8').split('\n')[0] ?? '') as Record<string, unknown>;

/** A plan's file whose first line says what a test needs, and its ID: by default this organisation's, made, with `digest`. */
function stored(digest: string, summary: Readonly<Record<string, unknown>> = {}): string {
  const planId = uuidV7Ids.next();
  mkdirSync(path.join(evidence, orgId), { recursive: true });
  writeFileSync(
    path.join(evidence, orgId, `state-recovery-${planId}.ndjson`),
    `${JSON.stringify({ k: 'state_plan', planId, orgId, ok: true, digest, ...summary })}\n`,
  );
  return planId;
}

describe('PL-29 follow-up: the authority rows’ plan and repair, run as the job runs them', () => {
  it('plans read-only as the owner, keeps the plan, then repairs from it by its digest, never twice', async () => {
    const planId = uuidV7Ids.next();
    const plan = await run(['--request', requested(stateRecoveryRequest(orgId, planId))]);
    expect(plan.code).toBe(0);
    expect(plan.events).toEqual([
      'operator.starting',
      'operator.state_owner_login',
      'audit.anchors_read',
      'db.schema_checked',
      'operator.state_recovery_planned',
    ]);
    expect(plan.line('operator.starting')).toMatchObject({ command: 'state-recovery-plan', role: 'agentx_owner' });
    expect(plan.line('operator.state_owner_login')).toMatchObject({ planId, note: OWNER_LOGIN_NOTE });
    const planned = plan.line('operator.state_recovery_planned');
    expect(planned).toMatchObject({ orgId, planId, putBack: 0, removed: 0, anchorSeq: null });
    const digest = String(planned?.digest);
    expect(recordOf(orgId, `state-recovery-${planId}.ndjson`)).toMatchObject({
      k: 'state_plan',
      planId,
      orgId,
      ok: true,
      digest,
      release: 'r-state',
    });
    const twice = await run(['--request', requested(stateRecoveryRequest(orgId, planId))]);
    expect(twice.code).toBe(1);
    expect(twice.line('operator.done_before')).toMatchObject({ command: 'state-recovery-plan', planId });

    const restoreId = uuidV7Ids.next();
    const asked = requested(stateRestoreRequest({ orgId, planId, digest, id: restoreId }));
    const repair = await run(['--request', asked]);
    expect(repair.events).toEqual([
      'operator.starting',
      'operator.state_owner_login',
      'audit.anchors_read',
      'db.schema_checked',
      'operator.states_restored',
    ]);
    expect(repair.code).toBe(0);
    expect(repair.host.exitCode).toBe(0);
    expect(repair.line('operator.states_restored')).toMatchObject({
      restoreId,
      planId,
      ok: true,
      putBack: 0,
      removed: 0,
      holdKept: true,
    });
    const facts = { restoreId, planId, orgId, digest, release: 'r-state', run: null };
    expect(recordOf(orgId, `state-restore-${restoreId}-start.ndjson`)).toEqual({ k: 'state_restore_start', ...facts });
    expect(recordOf(orgId, `state-restore-${restoreId}-outcome.ndjson`)).toMatchObject({
      k: 'state_restore',
      ...facts,
      ok: true,
    });
    const again = await run(['--request', asked]);
    expect(again.code).toBe(1);
    expect(again.line('operator.done_before')).toMatchObject({ command: 'state-restore', restoreId });
    expect(again.events).not.toContain('operator.states_restored');
  });

  it('keeps a refused plan, naming why, and fails', async () => {
    const held = await newOrganization();
    // Changed past the app on the live server, which is the copy too here: the copy can't vouch for it.
    const tamper = await tamperAsOwner(database, ORGANIZATIONS, held);
    await tamper.setColumn(held, 'status', 'FROZEN');
    await tamper.end();
    const planId = uuidV7Ids.next();
    const { code, line } = await run(['--request', requested(stateRecoveryRequest(held, planId))]);
    expect(code).toBe(1);
    expect(line('operator.state_recovery_refused')).toMatchObject({
      planId,
      reason: 'copy_differs',
      subjectType: 'organization',
      objectId: held,
      sign: 'seal',
      problem: null,
    });
    expect(recordOf(held, `state-recovery-${planId}.ndjson`)).toMatchObject({ ok: false, reason: 'copy_differs' });
  });

  it('refuses a stale digest, keeping that as its outcome; an outcome already there is said too', async () => {
    const restoreId = uuidV7Ids.next();
    const asked = requested(
      stateRestoreRequest({ orgId, planId: stored('a'.repeat(64)), digest: 'a'.repeat(64), id: restoreId }),
    );
    const { code, line } = await run(['--request', asked]);
    expect(code).toBe(1);
    expect(line('operator.state_restore_refused')).toMatchObject({ restoreId, ok: false, reason: 'stale' });
    expect(recordOf(orgId, `state-restore-${restoreId}-outcome.ndjson`)).toMatchObject({ reason: 'stale' });

    const second = uuidV7Ids.next();
    writeFileSync(path.join(evidence, orgId, `state-restore-${second}-outcome.ndjson`), 'there\n');
    const there = await run([
      '--request',
      requested(stateRestoreRequest({ orgId, planId: stored('b'.repeat(64)), digest: 'b'.repeat(64), id: second })),
    ]);
    expect(there.code).toBe(1);
    expect(there.events.slice(-2)).toEqual(['operator.state_restore_refused', 'operator.done_before']);
  });

  it('refuses, before connecting, a plan of another kind: a chain plan’s file is not an authority rows’ plan', async () => {
    const planId = uuidV7Ids.next();
    writeFileSync(
      path.join(evidence, orgId, `state-recovery-${planId}.ndjson`),
      `${JSON.stringify({ k: 'plan', planId, orgId, ok: true, digest: 'c'.repeat(64) })}\n`,
    );
    const restoreId = uuidV7Ids.next();
    const { code, events, line } = await run([
      '--request',
      requested(stateRestoreRequest({ orgId, planId, digest: 'c'.repeat(64), id: restoreId })),
    ]);
    expect(code).toBe(1);
    expect(events).toEqual(['operator.starting', 'operator.state_owner_login', 'operator.refused']);
    expect(line('operator.refused')).toMatchObject({
      restoreId,
      problems: [expect.stringMatching(/^the file \S+ is not this organisation's plan/)],
    });
  });

  it('refuses a plan whose live connection is not read-only', async () => {
    faults.readOnly.push(true, false);
    const { code, line } = await run(['--request', requested(stateRecoveryRequest(orgId, uuidV7Ids.next()))]);
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({
      problems: ['the live server is not read-only for a plan, so nothing was read'],
    });
  });

  it('refuses any role but the owner before it connects, and says a failure part-way', async () => {
    const asked = requested(stateRecoveryRequest(orgId, uuidV7Ids.next()));
    const operatorRun = await run(['--request', asked], envFor('operator'));
    expect(operatorRun.code).toBe(1);
    expect(operatorRun.line('operator.refused')).toMatchObject({
      problems: ['AGENTX_DB_USER must be agentx_owner: only the owner may repair a chain'],
    });
    const planId = uuidV7Ids.next();
    const noCopy = await run(
      ['--request', requested(stateRecoveryRequest(orgId, planId))],
      envFor('owner', { AGENTX_DB_DRILL_HOST: 'no-copy.invalid' }),
    );
    expect(noCopy.code).toBe(1);
    expect(noCopy.line('operator.failed')).toMatchObject({ command: 'state-recovery-plan', planId });
  });
});

describe('PL-29 follow-up: a request the job cannot read is refused before it connects', () => {
  const id = () => uuidV7Ids.next();
  it.each([
    [
      "a plan's other shape",
      ['state-recovery-plan', '--org', id(), '--id', id(), '--discard-fork'],
      /^the request file holds state-recovery-plan --org/,
    ],
    [
      "a repair's other shape",
      ['state-restore', '--org', id(), '--id', id()],
      /^the request file holds state-restore --org/,
    ],
  ])('%s', async (_case, words, problem) => {
    const { code, line, events } = await run(['--request', requested(words)]);
    expect(code).toBe(1);
    expect(events).toEqual(['operator.refused']);
    expect(line('operator.refused')).toMatchObject({ problems: [expect.stringMatching(problem)] });
  });

  it('names every ID and the digest that are not as they must be', async () => {
    const plan = await run(['--request', requested(['state-recovery-plan', '--org', 'X', '--id', 'Y'])]);
    expect(plan.line('operator.refused')).toMatchObject({
      problems: [
        "the organisation's ID must be a UUIDv7, in lower case",
        "the plan's ID must be a UUIDv7, in lower case",
      ],
    });
    const repair = await run([
      '--request',
      requested(['state-restore', '--org', 'X', '--plan', 'Y', '--digest', 'Z', '--id', 'W']),
    ]);
    expect(repair.line('operator.refused')).toMatchObject({
      problems: [
        "the organisation's ID must be a UUIDv7, in lower case",
        "the repair's ID must be a UUIDv7, in lower case",
        "the plan's ID must be a UUIDv7, in lower case",
        "the plan's digest must be 64 lower-case hex digits",
      ],
    });
  });
});
