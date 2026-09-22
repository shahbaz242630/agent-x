// B1c: the operator's command against a real Postgres (Rule Book §6): it
// creates an organisation as the app's role, on its own audit chain and the
// platform's, in one transaction; it refuses the owner's role and rewritten
// walls, and a failure anywhere leaves nothing behind. What it refuses before
// it connects is main.test.ts.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { createLogger, type Output } from '@agentx/platform/observability';
import {
  createTestDatabase,
  LogCapture,
  type TestDatabase,
  type TestRole,
  within,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import type { OperatorTables } from './create-organization.ts';
import { type OperatorProcess, runOperator } from './main.ts';

const server = inject('postgres');
/** The command's one key, as the platform mounts it. */
const keys = writeTestKeys(['audit-mac']);
/** The same key the command holds, to check what it wrote. */
const auditKeys = loadKeys({ directory: keys.directory, current: {} }, ['audit-mac']);
let database: TestDatabase;
let app: Database<OperatorTables>;

/** Plain words a test can look for in every log line; never a real business. */
const NAME = 'Zephyrine Trading Test Co';

const quiet = () =>
  createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: new LogCapture(),
  });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<OperatorTables>({ ...database.connection('app'), maxConnections: 2 }, quiet());
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
  keys.remove();
});

class FakeProcess implements OperatorProcess {
  readonly stdout: Output = { write: () => true };
  readonly stderr: Output = { write: () => true };
  exitCode: number | string | null | undefined = undefined;
}

/** The environment of a run against this test database, as one of its roles. */
function envFor(role: TestRole, overrides: Record<string, string> = {}): Record<string, string> {
  const connection = database.connection(role);
  return {
    AGENTX_ENV: 'test',
    AGENTX_RELEASE: 'r-operator',
    AGENTX_DB_HOST: connection.host,
    AGENTX_DB_PORT: String(connection.port),
    AGENTX_DB_NAME: connection.database,
    AGENTX_DB_USER: connection.user,
    AGENTX_DB_PASSWORD: connection.password,
    AGENTX_DB_TLS: 'disable',
    AGENTX_KEYS_DIR: keys.directory,
    ...overrides,
  };
}

async function run(argv: readonly string[], env: Record<string, string> = envFor('app')) {
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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Holds the platform chain's head from a session of its own, as a stuck operator action would, until `release`. */
async function holdPlatformHead(): Promise<{ release(): Promise<void> }> {
  const holder = await database.connect('admin');
  await holder.query('begin');
  await holder.query('select * from platform_controls.audit_head for update');
  return {
    async release() {
      await holder.query('rollback');
      await holder.end();
    },
  };
}

/** The relation locks the command's connection holds while it waits on another's lock, as `schema.table mode`. */
async function locksWhileWaiting(): Promise<string[]> {
  const rows = await database.as('admin').query<{ lock: string }>(
    `select c.relnamespace::regnamespace::text || '.' || c.relname || ' ' || l.mode as lock
       from pg_catalog.pg_stat_activity a
       join pg_catalog.pg_locks l on l.pid = a.pid and l.granted
       join pg_catalog.pg_class c on c.oid = l.relation
      where a.datname = $1 and a.application_name = 'agentx-operator' and a.wait_event_type = 'Lock'`,
    [database.name],
  );
  return rows.map((row) => row.lock);
}

/** How many organisations the directory lists, and how long the platform chain is: what a refused run must leave alone. */
async function counts(): Promise<{ orgs: number; platform: number }> {
  const [row] = await database.as('owner').query<{ orgs: number; platform: number }>(
    `select (select pg_catalog.count(*)::integer from directory.orgs) as orgs,
            (select pg_catalog.count(*)::integer from platform_controls.audit_events) as platform`,
  );
  return row ?? { orgs: -1, platform: -1 };
}

describe(`B1c the operator creates an organisation (Postgres ${server.version})`, () => {
  it("creates it ACTIVE as the app's role, its own chain first, then the platform's, and never logs its name", async () => {
    const before = await counts();

    const { code, host, text, events, line } = await run(['create-organization', '--name', NAME]);

    expect(code).toBe(0);
    expect(host.exitCode).toBe(0);
    expect(events).toEqual(['operator.starting', 'db.schema_checked', 'operator.organization_created']);
    expect(line('operator.starting')).toMatchObject({
      command: 'create-organization',
      role: 'agentx_app',
      keys: [expect.objectContaining({ purpose: 'audit-mac', current: 1 })],
    });
    const created = line('operator.organization_created');
    const orgId = String(created?.orgId);
    expect(created).toMatchObject({ release: 'r-operator', orgSeq: '1', platformSeq: String(before.platform + 1) });
    expect(text).not.toContain(NAME);
    expect(await counts()).toEqual({ orgs: before.orgs + 1, platform: before.platform + 1 });

    const services = { keys: auditKeys, ids: uuidV7Ids, logger: quiet() };
    const state = await withSignedStates(app, orgId, services, (tx, states) =>
      states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share'),
    );
    expect(state).toMatchObject({ outcome: 'verified', version: 1, fields: new Map([['status', 'ACTIVE']]) });
    const hold = await withSignedStates(app, orgId, services, (tx, states) => states.integrityHold(tx, orgId, 'none'));
    expect(hold).toMatchObject({ outcome: 'clear' });
    const own = await withTenant(app, orgId, async (tx) => ({
      name: (await tx.selectFrom('organizations.organizations').select('name').executeTakeFirstOrThrow()).name,
      events: await tx
        .selectFrom('audit.events')
        .select(['seq', 'actor_type', 'actor_id', 'action'])
        .orderBy('seq')
        .execute(),
      chain: await createAuditTrail({ keys: auditKeys, ids: uuidV7Ids }).verify(tx, orgId, undefined),
    }));
    expect(own).toMatchObject({
      name: NAME,
      events: [
        { seq: 1n, actor_type: 'system', actor_id: 'operator', action: 'organization.created' },
        { seq: 2n, actor_type: 'system', actor_id: 'operator', action: 'integrity_hold.created' },
      ],
      chain: { ok: true, seq: 2n },
    });

    const platform = await app
      .selectFrom('platform_controls.audit_events')
      .select(['seq', 'actor_type', 'actor_id', 'action', 'details'])
      .orderBy('seq', 'desc')
      .limit(1)
      .executeTakeFirstOrThrow();
    expect(platform).toEqual({
      seq: BigInt(before.platform + 1),
      actor_type: 'system',
      actor_id: 'operator',
      action: 'organization.created',
      details: JSON.stringify({ orgId, release: 'r-operator' }),
    });
    const platformChain = createPlatformChain({ keys: auditKeys, ids: uuidV7Ids });
    await expect(app.transaction().execute((tx) => platformChain.verify(tx, undefined))).resolves.toMatchObject({
      ok: true,
      seq: BigInt(before.platform + 1),
    });
  });

  it('keeps the name composed (NFC), as the organisation keeps every name', async () => {
    const { code, line } = await run(['create-organization', '--name', 'Cafe\u0301 Test Co']);
    const orgId = String(line('operator.organization_created')?.orgId);

    expect(code).toBe(0);
    const { name } = await withTenant(app, orgId, (tx) =>
      tx.selectFrom('organizations.organizations').select('name').executeTakeFirstOrThrow(),
    );
    expect(name).toBe('Caf\u00e9 Test Co');
  });

  it('creates a new organisation every run, each with its own ID', async () => {
    const first = await run(['create-organization', '--name', NAME]);
    const second = await run(['create-organization', '--name', NAME]);

    expect([first.code, second.code]).toEqual([0, 0]);
    expect(first.line('operator.organization_created')?.orgId).not.toBe(
      second.line('operator.organization_created')?.orgId,
    );
  });

  it('makes one organisation of a request file however often it runs, with the ID it names (B1c-2a)', async () => {
    const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-request-'));
    try {
      const file = path.join(folder, 'operator-request');
      const id = uuidV7Ids.next();
      writeFileSync(file, JSON.stringify(['create-organization', '--name', NAME, '--id', id]));
      const before = await counts();

      const first = await run(['--request', file]);
      expect(first.code).toBe(0);
      expect(first.line('operator.organization_created')).toMatchObject({ orgId: id });
      const made = await counts();
      expect(made).toEqual({ orgs: before.orgs + 1, platform: before.platform + 1 });

      // Left on the job and run again: the directory refuses the second, and nothing changes.
      const again = await run(['--request', file]);
      expect(again.code).toBe(1);
      expect(again.host.exitCode).toBe(1);
      expect(again.line('operator.done_before')).toMatchObject({
        level: 'error',
        orgId: id,
        command: 'create-organization',
      });
      expect(again.events).not.toContain('operator.organization_created');
      expect(again.events).not.toContain('operator.failed');
      expect(again.events).not.toContain('audit.integrity_failed');
      expect(await counts()).toEqual(made);
      expect(`${first.text}${again.text}`).not.toContain(NAME);
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
  });
});

describe(`B1c the lock order and the platform head's wait (ADR-006 §6; Postgres ${server.version})`, () => {
  it("writes the organisation's rows and starts its chain before it waits on the platform's head", async () => {
    // A run first, so the platform chain has a head to hold.
    expect((await run(['create-organization', '--name', NAME])).code).toBe(0);
    const head = await holdPlatformHead();
    try {
      const running = run(['create-organization', '--name', NAME]);
      const held = await vi.waitFor(
        async () => {
          const locks = await locksWhileWaiting();
          expect(locks).not.toEqual([]);
          return locks;
        },
        // Counted from the command's start: it connects and checks the schema first.
        { timeout: 20_000, interval: 100 },
      );

      expect(held).toEqual(
        expect.arrayContaining([
          'directory.orgs RowExclusiveLock',
          'organizations.organizations RowExclusiveLock',
          'audit.heads RowExclusiveLock',
        ]),
      );
      await head.release();
      expect((await within(20_000, running, 'the command')).code).toBe(0);
    } finally {
      await head.release().catch(() => undefined);
    }
  });

  it("gives up after 10 seconds while the platform's head stays held, naming the organisation it didn't create", async () => {
    expect((await run(['create-organization', '--name', NAME])).code).toBe(0);
    const before = await counts();
    const head = await holdPlatformHead();
    try {
      const began = performance.now();
      const { code, events, line } = await within(20_000, run(['create-organization', '--name', NAME]), 'the command');

      expect(performance.now() - began).toBeGreaterThanOrEqual(9_000);
      expect(code).toBe(1);
      expect(events).toEqual(['operator.starting', 'db.schema_checked', 'operator.failed']);
      const failed = line('operator.failed');
      expect(failed).toMatchObject({ command: 'create-organization' });
      expect(JSON.stringify(failed?.err)).toMatch(/lock timeout/);
      expect(failed?.orgId).toMatch(UUID);
      expect(await counts()).toEqual(before);
      expect(
        await database.as('owner').query('select 1 from directory.orgs where org_id = $1', [failed?.orgId]),
      ).toEqual([]);
    } finally {
      await head.release();
    }
  });
});

describe("B1c what the operator's command refuses, with nothing changed", () => {
  it("refuses to run as the owner's role, which could switch the walls off", async () => {
    const before = await counts();

    const { code, events, line } = await run(['create-organization', '--name', NAME], envFor('owner'));

    expect(code).toBe(1);
    expect(events).toEqual(['operator.starting', 'operator.start_refused']);
    expect(line('operator.start_refused')?.problems).toEqual(expect.arrayContaining([expect.any(String)]));
    expect(await counts()).toEqual(before);
  });

  it('refuses to write through walls that have been rewritten, and raises the alarm (A3e-1b)', async () => {
    const before = await counts();
    await database.as('owner').query('grant truncate on audit.events to agentx_app');
    try {
      const { code, events, line } = await run(['create-organization', '--name', NAME]);

      expect(code).toBe(1);
      expect(events).toEqual(['operator.starting', 'audit.integrity_failed']);
      expect(line('audit.integrity_failed')).toMatchObject({ check: 'schema', when: 'start' });
      expect(await counts()).toEqual(before);
    } finally {
      await database.as('owner').query('revoke truncate on audit.events from agentx_app');
    }
  });

  it("changes nothing when the platform chain refuses the event: no organisation, and the platform's alarm", async () => {
    // A run first, so the platform chain has a head to break.
    expect((await run(['create-organization', '--name', NAME])).code).toBe(0);
    const before = await counts();
    const owner = database.as('owner');
    const [kept] = await owner.query<{ mac: Buffer }>('select mac from platform_controls.audit_head');
    await owner.query(
      "update platform_controls.audit_head set mac = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')",
    );
    try {
      const { code, events, line } = await run(['create-organization', '--name', NAME]);

      expect(code).toBe(1);
      expect(events).toEqual(['operator.starting', 'db.schema_checked', 'audit.integrity_failed', 'operator.failed']);
      expect(line('audit.integrity_failed')).toMatchObject({ chain: 'platform', check: 'record' });
      expect(line('audit.integrity_failed')).not.toHaveProperty('orgId');
      expect(line('operator.failed')).toMatchObject({ command: 'create-organization', err: { type: 'ChainBroken' } });
      expect(line('operator.failed')?.orgId).toMatch(UUID);
      expect(await counts()).toEqual(before);
    } finally {
      await owner.query('update platform_controls.audit_head set mac = $1', [kept?.mac]);
    }
    expect((await run(['create-organization', '--name', NAME])).code).toBe(0);
  });
});
