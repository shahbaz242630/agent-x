// B1c: the operator's command against a real Postgres (Rule Book §6): it
// creates an organisation as the app's role, on its own audit chain and the
// platform's, in one transaction; it refuses the owner's role and rewritten
// walls, and a failure anywhere leaves nothing behind. What it refuses before
// it connects is main.test.ts.
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { createAuditTrail, withSignedStates } from '@agentx/core/modules/audit';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createPlatformChain, HEAD_WAIT_SECONDS } from '@agentx/core/modules/platform-controls';
import { uuidV7Ids } from '@agentx/core/shared-kernel';
import {
  type Chain,
  type CheckedPoint,
  createAnchorLog,
  readRebaseFile,
  rebaseFile,
  signAnchor,
  signRebase,
} from '@agentx/platform/audit-chain';
import { createDatabase, type Database, databaseNow, lockName, withTenant } from '@agentx/platform/db';
import { loadKeys } from '@agentx/platform/keys';
import { type Output } from '@agentx/platform/observability';
import { folderWriteOnceStore, OverwriteRefused } from '@agentx/platform/storage';
import {
  createTestDatabase,
  holdNamedLock,
  LogCapture,
  tamperAsOwner,
  type TestDatabase,
  testLogger,
  type TestRole,
  within,
  waitUntilQueued,
  writeTestKeys,
} from '@agentx/testing';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it, vi } from 'vitest';

import type { OperatorTables } from './create-organization.ts';
import { REBASE_LOCK } from './chain-rebase.ts';
import { type OperatorProcess, runOperator } from './main.ts';
import {
  auditExportRequest,
  chainRebaseRequest,
  chainRecoveryRequest,
  factorResetNoticeRequest,
  firstAdminRequest,
  handoffRequest,
  restoreCheckRequest,
} from './request.ts';

/** A failure no real run can cause yet, switched on by a test and off after it. */
const faults = vi.hoisted(() => ({
  create: undefined as Error | undefined,
  readOnly: [] as boolean[],
  /** Fails the next work through the signed states once (a rebase's event, E11). */
  signedStates: undefined as Error | undefined,
  /** Fails the next platform event recorded on its own once (a rebase's event, E11). */
  platformRecord: undefined as Error | undefined,
  /** Fails the next file written to a folder store once (a rebase's file, E11). */
  storePut: undefined as Error | undefined,
}));

vi.mock('@agentx/core/modules/platform-controls', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/core/modules/platform-controls')>();
  return {
    ...actual,
    createPlatformChain: (...args: Parameters<typeof actual.createPlatformChain>) => {
      const chain = actual.createPlatformChain(...args);
      return {
        ...chain,
        recordAlone: (...more: Parameters<typeof chain.recordAlone>) => {
          const fault = faults.platformRecord;
          faults.platformRecord = undefined;
          return fault === undefined ? chain.recordAlone(...more) : Promise.reject(fault);
        },
      };
    },
  };
});

vi.mock('@agentx/platform/storage', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/platform/storage')>();
  return {
    ...actual,
    folderWriteOnceStore: (...args: Parameters<typeof actual.folderWriteOnceStore>) => {
      const store = actual.folderWriteOnceStore(...args);
      return {
        ...store,
        put: (...more: Parameters<typeof store.put>) => {
          const fault = faults.storePut;
          faults.storePut = undefined;
          return fault === undefined ? store.put(...more) : Promise.reject(fault);
        },
      };
    },
  };
});

vi.mock('@agentx/core/modules/audit', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/core/modules/audit')>();
  return {
    ...actual,
    withSignedStates: (...args: Parameters<typeof actual.withSignedStates>) => {
      const fault = faults.signedStates;
      faults.signedStates = undefined;
      return fault === undefined ? actual.withSignedStates(...args) : Promise.reject(fault);
    },
  };
});

vi.mock('./create-organization.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./create-organization.ts')>();
  return {
    ...actual,
    createOrganizationAsOperator: (...args: Parameters<typeof actual.createOrganizationAsOperator>) => {
      if (faults.create !== undefined) return Promise.reject(faults.create);
      return actual.createOrganizationAsOperator(...args);
    },
  };
});

// Each answer pushed overrides one read-only proof, in the order the command asks.
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
  faults.create = undefined;
  faults.readOnly = [];
  faults.signedStates = undefined;
  faults.platformRecord = undefined;
  faults.storePut = undefined;
});

const server = inject('postgres');
/** The command's one key, as the platform mounts it. */
const keys = writeTestKeys(['audit-mac', 'field-encryption', 'operator-signing', 'audit-rebase']);
/** The same key the command holds, to check what it wrote. */
const auditKeys = loadKeys({ directory: keys.directory, current: {} }, [
  'audit-mac',
  'field-encryption',
  'operator-signing',
  'audit-rebase',
]);
let database: TestDatabase;
let app: Database<OperatorTables>;

/** Plain words a test can look for in every log line; never a real business. */
const NAME = 'Zephyrine Trading Test Co';

const quiet = () => testLogger();

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

async function run(argv: readonly string[], env: Record<string, string> = envFor('operator')) {
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
  it("creates it ACTIVE as its own role (PL-57), its own chain first, then the platform's, and never logs its name", async () => {
    const before = await counts();

    const { code, host, text, events, line } = await run(['create-organization', '--name', NAME]);

    expect(code).toBe(0);
    expect(host.exitCode).toBe(0);
    expect(events).toEqual(['operator.starting', 'db.schema_checked', 'operator.organization_created']);
    expect(line('operator.starting')).toMatchObject({
      command: 'create-organization',
      role: 'agentx_operator',
      keys: [
        expect.objectContaining({ purpose: 'audit-mac', current: 1 }),
        expect.objectContaining({ purpose: 'field-encryption', current: 1 }),
        expect.objectContaining({ purpose: 'operator-signing', current: 1 }),
        expect.objectContaining({ purpose: 'audit-rebase', current: 1 }),
      ],
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
      // A run by hand, as a test's is: no job's run to name.
      details: JSON.stringify({ orgId, release: 'r-operator', run: null }),
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

  it("names the job's run in the platform's event, as Azure names it, so the event leads to who started it (B1c-2b)", async () => {
    const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-request-'));
    try {
      const file = path.join(folder, 'operator-request');
      const id = uuidV7Ids.next();
      writeFileSync(file, JSON.stringify(['create-organization', '--name', NAME, '--id', id]));
      const jobRun = 'job-agentx-stg-operator-7x2kq9m';

      const { code } = await run(['--request', file], envFor('operator', { CONTAINER_APP_JOB_EXECUTION_NAME: jobRun }));

      expect(code).toBe(0);
      const event = await app
        .selectFrom('platform_controls.audit_events')
        .select(['action', 'details'])
        .orderBy('seq', 'desc')
        .limit(1)
        .executeTakeFirstOrThrow();
      expect(event).toEqual({
        action: 'organization.created',
        details: JSON.stringify({ orgId: id, release: 'r-operator', run: jobRun }),
      });
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
  });

  it("reports any other key's refusal as a failure, never as a request done before", async () => {
    faults.create = Object.assign(new Error('duplicate key value violates unique constraint'), {
      code: '23505',
      constraint: 'one_row_per_organization',
    });

    const { code, events, line } = await run(['create-organization', '--name', NAME]);

    expect(code).toBe(1);
    expect(events).toContain('operator.failed');
    expect(events).not.toContain('operator.done_before');
    expect(line('operator.failed')).toMatchObject({ command: 'create-organization' });
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

  it("gives up after HEAD_WAIT_SECONDS while the platform's head stays held, naming the organisation it didn't create", async () => {
    expect((await run(['create-organization', '--name', NAME])).code).toBe(0);
    const before = await counts();
    const head = await holdPlatformHead();
    try {
      const began = performance.now();
      const { code, events, line } = await within(20_000, run(['create-organization', '--name', NAME]), 'the command');

      expect(performance.now() - began).toBeGreaterThanOrEqual((HEAD_WAIT_SECONDS - 1) * 1000);
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

describe(`B4-6b the operator invites an organisation's first admin (Postgres ${server.version})`, () => {
  /** An address a test can look for in every log line. */
  const ADDRESS = 'quartzine.first@example.test';

  /** Runs one request file, as the job does. */
  async function runRequest(contents: string) {
    const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-request-'));
    try {
      const file = path.join(folder, 'operator-request');
      writeFileSync(file, contents);
      return await run(['--request', file]);
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
  }

  /** A new organisation, made by the command itself. */
  async function organization(): Promise<string> {
    const id = uuidV7Ids.next();
    const made = await runRequest(JSON.stringify(['create-organization', '--name', NAME, '--id', id]));
    expect(made.code).toBe(0);
    return id;
  }

  /** The request deploy/azure/operator.ts writes: the token made there, only its hash sent. */
  const invitation = (orgId: string, id = uuidV7Ids.next()) => {
    const token = randomBytes(32).toString('base64url');
    const hash = createHash('sha256').update(token, 'ascii').digest('hex');
    return { id, hash, request: firstAdminRequest(orgId, ADDRESS, id, hash) };
  };

  it('opens an admin’s invitation listed by the hash, on both chains, never logging the address', async () => {
    const orgId = await organization();
    const before = await counts();
    const asked = invitation(orgId);

    const done = await runRequest(asked.request);

    expect(done.code).toBe(0);
    expect(done.events).toEqual([
      'operator.starting',
      'db.schema_checked',
      'status.changed',
      'operator.first_admin_invited',
    ]);
    expect(done.line('operator.first_admin_invited')).toMatchObject({ orgId, invitationId: asked.id });
    expect(done.text).not.toContain(ADDRESS);
    expect(done.text).not.toContain(asked.hash);
    const [row] = await database
      .as('backup')
      .query<{ role: string; status: string; invited_by: string | null }>(
        'select role, status, invited_by from identity.invitations where id = $1',
        [asked.id],
      );
    expect(row).toEqual({ role: 'admin', status: 'OPEN', invited_by: null });
    const listed = await database
      .as('backup')
      .query('select 1 from directory.invites where token_hash = $1', [Buffer.from(asked.hash, 'hex')]);
    expect(listed).toHaveLength(1);
    expect(await counts()).toEqual({ orgs: before.orgs, platform: before.platform + 1 });
    const [event] = await database
      .as('backup')
      .query<{ action: string; details: string }>(
        'select action, details from platform_controls.audit_events order by seq desc limit 1',
      );
    expect(event?.action).toBe('invitation.first_admin');
    expect(JSON.parse(event?.details ?? '{}')).toMatchObject({ orgId, invitationId: asked.id, release: 'r-operator' });
  });

  it('changes nothing when the same request runs again', async () => {
    const orgId = await organization();
    const asked = invitation(orgId);
    expect((await runRequest(asked.request)).code).toBe(0);
    const after = await counts();

    const again = await runRequest(asked.request);

    expect(again.code).toBe(1);
    expect(again.line('operator.done_before')).toMatchObject({ command: 'invite-first-admin', invitationId: asked.id });
    expect(await counts()).toEqual(after);
  });

  it('refuses an organisation that isn’t there, or one someone belongs to already, changing nothing', async () => {
    const orgId = await organization();
    const member = await runRequest(invitation(orgId).request);
    expect(member.code).toBe(0);
    // Someone listed there: the organisation is in use, and its admins invite.
    const userId = uuidV7Ids.next();
    await database
      .as('admin')
      .query(
        "insert into identity.users (id, issuer, subject, created_at) values ($1, 'https://auth.example.test', $2, now())",
        [userId, userId],
      );
    await database
      .as('admin')
      .query('insert into directory.members (user_id, org_id, membership_id) values ($1, $2, $3)', [
        userId,
        orgId,
        uuidV7Ids.next(),
      ]);
    const before = await counts();

    const inUse = await runRequest(invitation(orgId).request);
    const missing = await runRequest(invitation(uuidV7Ids.next()).request);

    expect(inUse.code).toBe(1);
    expect(inUse.line('operator.refused')).toMatchObject({
      problems: ['the organisation has members: its admins invite, not the operator'],
    });
    expect(missing.line('operator.refused')).toMatchObject({ problems: ['no organisation has this ID'] });
    expect(await counts()).toEqual(before);
    expect(`${inUse.text}${missing.text}`).not.toContain(ADDRESS);
  });

  it('refuses an address that isn’t one, never repeating it, changing nothing', async () => {
    const orgId = await organization();
    const before = await counts();
    const id = uuidV7Ids.next();

    const done = await runRequest(firstAdminRequest(orgId, 'not an address', id, 'ab'.repeat(32)));

    expect(done.code).toBe(1);
    expect(done.line('operator.refused')).toMatchObject({
      invitationId: id,
      problems: ["the invited address, or the token's hash, isn't one"],
    });
    expect(done.text).not.toContain('not an address');
    expect(await counts()).toEqual(before);
  });

  it('refuses an organisation whose records can’t be verified, changing nothing', async () => {
    const orgId = await organization();
    const owner = await tamperAsOwner(database, ORGANIZATIONS, orgId);
    try {
      await owner.setColumn(orgId, 'status', 'FROZEN');
    } finally {
      await owner.end();
    }
    const asked = invitation(orgId);

    const done = await runRequest(asked.request);

    expect(done.code).toBe(1);
    expect(done.line('operator.refused')).toMatchObject({ problems: ["the organisation's records can't be verified"] });
    const rows = await database.as('backup').query('select 1 from identity.invitations where id = $1', [asked.id]);
    expect(rows).toEqual([]);
  });
});

describe(`E10c the operator exports an organisation's audit log for a case, as the job runs it (Postgres ${server.version})`, () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-export-'));
  afterAll(() => {
    rmSync(folder, { recursive: true, force: true });
  });
  const store = path.join(folder, 'evidence');
  const CASE = 'DSP-2026/0417';
  /** A day either side of now: a range is 366 days at most. */
  const around = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

  /** A new organisation, made by the command. */
  async function organization(): Promise<string> {
    const orgId = uuidV7Ids.next();
    const created = path.join(folder, `create-${orgId}`);
    writeFileSync(created, JSON.stringify(['create-organization', '--name', NAME, '--id', orgId]));
    expect((await run(['--request', created])).code).toBe(0);
    return orgId;
  }

  /** The run of a request to export the organisation's log, as the job runs one. */
  function exportRun(orgId: string): { exportId: string; running: ReturnType<typeof run> } {
    const exportId = uuidV7Ids.next();
    const asked = path.join(folder, `export-${exportId}`);
    writeFileSync(asked, auditExportRequest(orgId, around(-1), around(1), CASE, exportId));
    return { exportId, running: run(['--request', asked], envFor('operator', { AGENTX_EVIDENCE_DIR: store })) };
  }

  it('writes the file to the evidence store from a request file, checking the schema first, never logging the case', async () => {
    const orgId = await organization();
    const { exportId, running } = exportRun(orgId);

    const { code, events, line, text } = await running;

    expect(events).toEqual(['operator.starting', 'db.schema_checked', 'operator.audit_exported']);
    expect(code).toBe(0);
    expect(line('operator.audit_exported')).toMatchObject({ orgId, exportId, events: 2, release: 'r-operator' });
    const file = readFileSync(path.join(store, orgId, `${exportId}.ndjson`), 'utf8');
    expect(file.trimEnd().split(String.fromCharCode(10))).toHaveLength(2);
    expect(text).not.toContain(CASE);
  });

  it("records on the organisation's chain and writes the notice before it waits on the platform's head (ADR-006 §6)", async () => {
    // Made first, which also gives the platform chain a head to hold.
    const orgId = await organization();
    const head = await holdPlatformHead();
    try {
      const { running } = exportRun(orgId);
      const held = await vi.waitFor(
        async () => {
          const locks = await locksWhileWaiting();
          expect(locks).not.toEqual([]);
          return locks;
        },
        { timeout: 20_000, interval: 100 },
      );

      expect(held).toEqual(
        expect.arrayContaining(['audit.heads RowExclusiveLock', 'notifications.outbox RowExclusiveLock']),
      );
      await head.release();
      expect((await within(20_000, running, 'the command')).code).toBe(0);
    } finally {
      await head.release().catch(() => undefined);
    }
  });
});

describe(`Phase 4 B1 the operator resumes every hand-off, as the job runs it (Postgres ${server.version})`, () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-handoff-'));
  afterAll(() => {
    rmSync(folder, { recursive: true, force: true });
  });
  const REASON = 'INC-2026/0042';

  it('resumes from a request file, checking the schema first, then tells every organisation, never logging the reason', async () => {
    const id = uuidV7Ids.next();
    const asked = path.join(folder, `resume-${id}`);
    writeFileSync(asked, handoffRequest('handoff-resume', REASON, id));

    const { code, events, line, text } = await run(['--request', asked]);

    expect(events).toEqual([
      'operator.starting',
      'db.schema_checked',
      'operator.handoff_resumed',
      'operator.handoff_told',
    ]);
    expect(code).toBe(0);
    expect(line('operator.starting')).toMatchObject({ command: 'handoff-resume' });
    expect(line('operator.handoff_resumed')).toMatchObject({ platformEventId: id });
    expect(line('operator.handoff_told')).toMatchObject({ platformEventId: id, failed: 0 });
    const [event] = await database
      .as('owner')
      .query<{ details: string }>('select details from platform_controls.audit_events where id = $1', [id]);
    expect(JSON.parse(String(event?.details))).toEqual({ reason: REASON, release: 'r-operator', run: null });
    expect(text).not.toContain(REASON);
  });
});

describe(`OR2 our team's reset notice, as the job runs it (Postgres ${server.version})`, () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-reset-notice-'));
  afterAll(() => {
    rmSync(folder, { recursive: true, force: true });
  });
  const REASON = 'INC-2026/0099';

  it('checks the schema first, then refuses an organisation it cannot find, recording nothing, never logging the reference', async () => {
    const id = uuidV7Ids.next();
    const asked = path.join(folder, `notice-${id}`);
    const request = { orgId: uuidV7Ids.next(), userId: '6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f', reason: REASON, id };
    writeFileSync(asked, factorResetNoticeRequest(request));

    const { code, events, line, text } = await run(['--request', asked]);

    expect(events).toEqual(['operator.starting', 'db.schema_checked', 'operator.refused']);
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({ noticeId: id, problems: ['no organisation has this ID'] });
    expect(text).not.toContain(REASON);
  });
});

describe("S78 the restore drill's check, run as the job runs it", () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-restore-'));
  afterAll(() => {
    rmSync(folder, { recursive: true, force: true });
  });
  const file = path.join(folder, 'request');
  writeFileSync(file, restoreCheckRequest());
  // The copy is this same database under another name for the same server
  // (the test server listens on 127.0.0.1, which localhost names too): a copy the live server is.
  const drill = () => run(['--request', file], envFor('operator', { AGENTX_DB_DRILL_HOST: 'localhost' }));

  it('reads the copy and the live server, read-only, says the copy holds, and writes nothing', async () => {
    const head = async () => database.as('owner').query('select seq from platform_controls.audit_head');
    const before = await head();

    const { code, events, line } = await drill();

    expect(events).toEqual(['operator.starting', 'operator.restore_check_done']);
    expect(code).toBe(0);
    expect(line('operator.restore_check_done')).toMatchObject({ problems: [], newSinceCopy: 0 });
    expect(await head()).toEqual(before);
    // Both pools closed: no connection of the command's is left on the server.
    await vi.waitFor(
      async () => {
        const open = await database
          .as('admin')
          .query(
            "select 1 from pg_catalog.pg_stat_activity where datname = $1 and application_name = 'agentx-operator'",
            [database.name],
          );
        expect(open).toEqual([]);
      },
      { timeout: 5000, interval: 100 },
    );
  });

  it('fails a copy with a single problem, naming it', async () => {
    // The directory's list unreadable: one problem, on both sides at once.
    await database.as('owner').query('revoke select on directory.orgs from agentx_operator');
    try {
      const { code, events, line } = await drill();

      expect(code).toBe(1);
      expect(events).toEqual(['operator.starting', 'operator.restore_check_failed']);
      expect(line('operator.restore_check_failed')).toMatchObject({
        problems: ["the organisations' lists: unreadable (42501)"],
        problemCount: 1,
      });
    } finally {
      await database.as('owner').query('grant select on directory.orgs to agentx_operator');
    }
  });

  it('reads nothing when the live server does not prove itself read-only', async () => {
    // The copy is asked first, then the live server.
    faults.readOnly.push(true, false);

    const { code, events, line } = await drill();

    expect(code).toBe(1);
    expect(events).toEqual(['operator.starting', 'operator.refused']);
    expect(line('operator.refused')).toMatchObject({
      problems: ['a connection is not read-only, so nothing was read'],
    });
    expect(faults.readOnly).toEqual([]);
  });
});

describe('4D2e E9 the chain recovery plan, run as the job runs it', () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-recovery-'));
  const signingFiles = writeTestKeys(['audit-anchor']);
  afterAll(() => {
    rmSync(folder, { recursive: true, force: true });
    signingFiles.remove();
  });
  const evidence = path.join(folder, 'evidence');
  const anchorsFolder = path.join(folder, 'anchors');
  /** The API's anchor key, which signs what the store holds; the command gets its public half alone. */
  const signing = loadKeys({ directory: signingFiles.directory, current: {} }, ['audit-anchor']);
  const publicKey = String(signing.describe()[0]?.versions[0]?.publicKey);
  const recoveryEnv = (overrides: Record<string, string> = {}) =>
    envFor('operator', {
      // The copy is this same database by another name, as for the restore check: a copy the live server is.
      AGENTX_DB_DRILL_HOST: 'localhost',
      AGENTX_EVIDENCE_DIR: evidence,
      AGENTX_AUDIT_ANCHORS_DIR: anchorsFolder,
      AGENTX_AUDIT_ANCHOR_PUBLIC_KEYS: `1:${publicKey}`,
      ...overrides,
    });

  /** A new organisation, made by the command, and its chain's head. */
  async function organisation(): Promise<{ orgId: string; head: CheckedPoint }> {
    const orgId = uuidV7Ids.next();
    const created = path.join(folder, `create-${orgId}`);
    writeFileSync(created, JSON.stringify(['create-organization', '--name', NAME, '--id', orgId]));
    expect((await run(['--request', created])).code).toBe(0);
    const report = await createAuditTrail({ keys: auditKeys, ids: uuidV7Ids }).verifyAlone(app, orgId, undefined);
    if (!report.ok) throw new Error('A new chain should check out');
    return { orgId, head: report };
  }

  /** Keeps an anchor in the store as the API does, signed with its key. */
  async function anchored(orgId: string, point: CheckedPoint): Promise<void> {
    const log = createAnchorLog({
      store: folderWriteOnceStore(anchorsFolder),
      keys: signing,
      logger: quiet(),
      now: () => new Date(),
      epoch: 1,
      alertAfterMs: 60_000,
    });
    await log.read();
    log.keep(signAnchor(signing, { kind: 'organisation', orgId }, point, new Date(), 1));
    await log.flush();
  }

  function plan(orgId: string, env = recoveryEnv()) {
    const planId = uuidV7Ids.next();
    const asked = path.join(folder, `plan-${planId}`);
    writeFileSync(asked, chainRecoveryRequest(orgId, planId));
    return { planId, asked, running: run(['--request', asked], env) };
  }

  const planLines = (orgId: string, planId: string) =>
    readFileSync(path.join(evidence, orgId, `chain-recovery-${planId}.ndjson`), 'utf8')
      .trimEnd()
      .split('\n')
      .map((text) => JSON.parse(text) as Record<string, unknown>);

  it("plans from the copy against the store's anchor, keeps the plan as evidence, and never makes it twice", async () => {
    const { orgId, head } = await organisation();
    await anchored(orgId, head);
    const { planId, asked, running } = plan(orgId);

    const { code, events, line } = await running;

    expect(events).toEqual(['operator.starting', 'audit.anchors_read', 'operator.chain_recovery_planned']);
    expect(code).toBe(0);
    expect(line('operator.chain_recovery_planned')).toMatchObject({
      orgId,
      planId,
      putBack: 0,
      replaced: 0,
      removed: 0,
      headReplaced: false,
      anchorSeq: String(head.seq),
    });
    expect(planLines(orgId, planId)).toEqual([
      expect.objectContaining({ k: 'plan', ok: true, planId, orgId, rows: 0, release: 'r-operator' }),
    ]);

    const again = await run(['--request', asked], recoveryEnv());
    expect(again.code).toBe(1);
    expect(again.line('operator.done_before')).toMatchObject({ command: 'chain-recovery-plan', planId });
  });

  it('keeps a refused plan too, and says why', async () => {
    const { orgId, head } = await organisation();
    await anchored(orgId, { ...head, seq: head.seq + 3n });
    const { planId, running } = plan(orgId);

    const { code, events, line } = await running;

    expect(code).toBe(1);
    expect(events).toEqual(['operator.starting', 'audit.anchors_read', 'operator.chain_recovery_refused']);
    expect(line('operator.chain_recovery_refused')).toMatchObject({
      planId,
      reason: 'behind_anchor',
      seq: String(head.seq + 3n),
      problem: null,
    });
    expect(planLines(orgId, planId)).toEqual([
      expect.objectContaining({ k: 'plan', ok: false, reason: 'behind_anchor' }),
    ]);
  });

  it("refuses without the evidence store, the anchors' store or their public keys, before it connects", async () => {
    const bare = await plan(uuidV7Ids.next(), envFor('operator', { AGENTX_DB_DRILL_HOST: 'localhost' })).running;
    expect(bare.code).toBe(1);
    expect(bare.line('operator.refused')).toMatchObject({
      problems: [
        expect.stringMatching(/^no store for an audit export/),
        expect.stringMatching(/^no store of the chains' anchors/),
      ],
    });
    const keyless = await plan(
      uuidV7Ids.next(),
      envFor('operator', { AGENTX_EVIDENCE_DIR: evidence, AGENTX_AUDIT_ANCHORS_DIR: anchorsFolder }),
    ).running;
    expect(keyless.line('operator.refused')).toMatchObject({
      problems: [expect.stringMatching(/^no store of the chains' anchors/)],
    });
    const storeless = await plan(
      uuidV7Ids.next(),
      envFor('operator', { AGENTX_EVIDENCE_DIR: evidence, AGENTX_AUDIT_ANCHOR_PUBLIC_KEYS: `1:${publicKey}` }),
    ).running;
    expect(storeless.line('operator.refused')).toMatchObject({
      problems: [expect.stringMatching(/^no store of the chains' anchors/)],
    });
  });

  it("refuses when the anchors' store can't be read whole", async () => {
    // A file where the store's folder should be: no listing of it can be made.
    const notAFolder = path.join(folder, 'not-a-folder');
    writeFileSync(notAFolder, '');
    const { code, line } = await plan(uuidV7Ids.next(), recoveryEnv({ AGENTX_AUDIT_ANCHORS_DIR: notAFolder })).running;
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({
      problems: ["the chains' anchors' store couldn't be read whole, so no plan can be checked against it"],
    });
  });

  it('runs only from a request file, naming the organisation and the plan by UUIDv7', async () => {
    const typed = await run(['chain-recovery-plan', '--org', uuidV7Ids.next(), '--id', uuidV7Ids.next()]);
    expect(typed.line('operator.refused')).toMatchObject({
      problems: [
        'chain-recovery-plan runs only from a request file: chain-recovery-plan --org <organisation ID> --id <new plan ID> [--discard-fork]',
      ],
    });
    const asked = path.join(folder, 'badly-asked');
    writeFileSync(asked, JSON.stringify(['chain-recovery-plan', '--org', 'ORG', '--id', 'ID']));
    expect((await run(['--request', asked])).line('operator.refused')).toMatchObject({
      problems: [
        "the organisation's ID must be a UUIDv7, in lower case",
        "the plan's ID must be a UUIDv7, in lower case",
      ],
    });
    writeFileSync(asked, JSON.stringify(['chain-recovery-plan', '--org', uuidV7Ids.next()]));
    expect((await run(['--request', asked])).line('operator.refused')).toMatchObject({
      problems: [
        'the request file holds chain-recovery-plan --org <organisation ID> --id <new plan ID> [--discard-fork] as a JSON list, and nothing else',
      ],
    });
    // A flag after its words: the named one alone.
    writeFileSync(
      asked,
      JSON.stringify(['chain-recovery-plan', '--org', uuidV7Ids.next(), '--id', uuidV7Ids.next(), '--force']),
    );
    expect((await run(['--request', asked])).line('operator.refused')).toMatchObject({
      problems: [expect.stringMatching(/^the request file holds chain-recovery-plan/)],
    });
  });

  it("plans with the named fork flag when asked, and logs the digest its file names (E10's request)", async () => {
    const { orgId } = await organisation();
    const planId = uuidV7Ids.next();
    const asked = path.join(folder, `plan-${planId}`);
    writeFileSync(asked, chainRecoveryRequest(orgId, planId, true));
    const { code, line } = await run(['--request', asked], recoveryEnv());
    expect(code).toBe(0);
    const [summary] = planLines(orgId, planId);
    expect(line('operator.chain_recovery_planned')).toMatchObject({
      planId,
      discardFork: true,
      forkDiscarded: false,
      digest: summary?.digest,
    });
    expect(summary?.digest).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("4D2e E11 a chain's rebase, run as the job runs it", () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-rebase-'));
  const anchorKeyFiles = writeTestKeys(['audit-anchor']);
  afterAll(() => {
    rmSync(folder, { recursive: true, force: true });
    anchorKeyFiles.remove();
  });
  const anchors = path.join(folder, 'anchors');
  const rebases = path.join(anchors, 'e1', 'rebases');
  const apiAnchorKey = loadKeys({ directory: anchorKeyFiles.directory, current: {} }, ['audit-anchor']);
  const env = (store = anchors) =>
    envFor('operator', {
      AGENTX_AUDIT_ANCHORS_DIR: store,
      AGENTX_AUDIT_ANCHOR_PUBLIC_KEYS: `1:${String(apiAnchorKey.describe()[0]?.versions[0]?.publicKey)}`,
    });
  const EVIDENCE = 'INC-2026/0042';

  /** The chains' anchors as the API holds them: its own anchor key, and the rebase key's public half alone. */
  const apiLog = () =>
    createAnchorLog({
      store: folderWriteOnceStore(anchors),
      keys: {
        ...apiAnchorKey,
        verifySignature: (purpose, version, message, signature) =>
          (purpose === 'audit-rebase' ? auditKeys : apiAnchorKey).verifySignature(purpose, version, message, signature),
      },
      logger: quiet(),
      now: () => new Date(),
      epoch: 1,
      alertAfterMs: 60_000,
    });

  /** The chain's head, checked whole. */
  async function headOf(chain: Chain): Promise<CheckedPoint> {
    const report =
      chain.kind === 'platform'
        ? await createPlatformChain({ keys: auditKeys, ids: uuidV7Ids }).verifyAlone(app, undefined)
        : await createAuditTrail({ keys: auditKeys, ids: uuidV7Ids }).verifyAlone(app, chain.orgId, undefined);
    if (!report.ok) throw new Error('The chain should check out');
    return report;
  }

  /** The chain anchored `ahead` events past its head, as a chain wound back, or cut short by a repair, reads: its head. */
  async function anchoredAhead(chain: Chain, ahead: bigint): Promise<CheckedPoint> {
    const head = await headOf(chain);
    const log = apiLog();
    await log.read();
    const at = new Date();
    log.keep(signAnchor(apiAnchorKey, chain, { ...head, seq: head.seq + ahead }, at, 1));
    await log.flush();
    // The anchor is dated by this process's clock, the rebase by the database's, and a
    // rebase moves only anchors dated before it: Docker's clock can trail the host's by
    // ~0.2 s (the laptop-only flake, S183), so wait until the database's has passed it.
    // Backdating instead lets the platform chain's own newer anchors win (4D2e).
    await vi.waitUntil(async () => (await databaseNow(app)).getTime() > at.getTime(), { timeout: 5000, interval: 20 });
    return head;
  }

  async function madeOrganisation(): Promise<string> {
    const orgId = uuidV7Ids.next();
    const asked = path.join(folder, `create-${orgId}`);
    writeFileSync(asked, JSON.stringify(['create-organization', '--name', NAME, '--id', orgId]));
    expect((await run(['--request', asked])).code).toBe(0);
    return orgId;
  }

  function rebase(chain: string, head: CheckedPoint, { id = uuidV7Ids.next(), store = anchors } = {}) {
    const asked = path.join(folder, `rebase-${id}`);
    writeFileSync(
      asked,
      chainRebaseRequest({
        chain,
        seq: head.seq.toString(),
        hash: head.hash.toString('hex'),
        reason: 'repaired',
        evidence: EVIDENCE,
        id,
      }),
    );
    return { id, asked, running: run(['--request', asked], env(store)) };
  }

  /** The newest event of an organisation's chain, as stored. */
  async function newestEvent(orgId: string): Promise<Record<string, unknown> | undefined> {
    const rows = await database
      .as('admin')
      .query(
        'select seq, actor_id, action, subject_type, subject_id, details from audit.events where org_id = $1 order by seq desc limit 1',
        [orgId],
      );
    return rows[0];
  }

  it("SEC-DB-11 moves an organisation's chain on to the head named, says it is shorter, records it on the chain, and the API takes it in", async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 3n);
    const before = await databaseNow(app);
    const { id, asked, running } = rebase(orgId, head);

    const { code, events, line, text } = await running;

    expect(code).toBe(0);
    expect(events).toEqual([
      'operator.starting',
      'audit.anchors_read',
      'operator.chain_rebase_shorter',
      'operator.chain_rebased',
    ]);
    expect(line('operator.chain_rebase_shorter')).toMatchObject({
      orgId,
      rebaseId: id,
      seq: String(head.seq),
      anchorSeq: String(head.seq + 3n),
      shorterBy: '3',
    });
    expect(line('operator.chain_rebased')).toMatchObject({
      orgId,
      rebaseId: id,
      chain: 'organisation',
      seq: String(head.seq),
      headHash: head.hash.toString('hex'),
      anchorSeq: String(head.seq + 3n),
      shorterBy: '3',
      reason: 'repaired',
      recorded: 'recorded',
    });
    expect(text).not.toContain(EVIDENCE);
    const read = await readRebaseFile(auditKeys, {
      bytes: readFileSync(path.join(rebases, id)),
      name: `e1/rebases/${id}`,
      epoch: 1,
    });
    expect(read).toMatchObject({
      rebase: { chain: `organisation:${orgId}`, seq: head.seq, from: head.seq + 3n, evidence: EVIDENCE },
    });
    // Dated by the database's clock.
    const at = 'rebase' in read ? read.rebase.at.getTime() : 0;
    expect(at).toBeGreaterThanOrEqual(before.getTime());
    expect(at).toBeLessThanOrEqual((await databaseNow(app)).getTime());
    // The organisation can read of it on its own chain: the operator's signed event, just past the rebase's place.
    expect(await newestEvent(orgId)).toMatchObject({
      seq: String(head.seq + 1n),
      actor_id: 'operator',
      action: 'audit_chain.rebased',
      subject_type: 'audit_chain',
      subject_id: id,
    });
    expect(JSON.parse(String((await newestEvent(orgId))?.details))).toMatchObject({
      rebaseId: id,
      seq: String(head.seq),
      fromSeq: String(head.seq + 3n),
      evidence: EVIDENCE,
      reason: 'repaired',
    });
    expect((await headOf({ kind: 'organisation', orgId })).seq).toBe(head.seq + 1n);

    const api = apiLog();
    await api.read();
    expect(api.latest({ kind: 'organisation', orgId })).toMatchObject({ seq: head.seq, hash: head.hash });

    // The same request again: done, its event there already.
    const again = await run(['--request', asked], env());
    expect(again.code).toBe(1);
    expect(again.line('operator.done_before')).toMatchObject({ rebaseId: id, recorded: 'already' });
    // Its ID reused for another head is no rebase of that head: never said done (E11b review).
    for (const named of [
      { ...head, seq: head.seq + 1n },
      { ...head, hash: Buffer.alloc(32, 7) },
    ]) {
      const reused = await rebase(orgId, named, { id }).running;
      expect(reused.code).toBe(1);
      expect(reused.line('operator.done_before')).toMatchObject({ rebaseId: id, recorded: null });
    }
    // Another: the chain holds its point and has grown whole from it.
    const another = await rebase(orgId, head).running;
    expect(another.line('operator.chain_rebase_refused')).toMatchObject({
      reason: 'not_needed',
      seq: String(head.seq),
    });
  });

  it('SEC-DB-11 refuses a head other than the one named, writing nothing: a chain cut short since is never blessed', async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 3n);
    for (const named of [
      { ...head, seq: head.seq + 1n },
      { ...head, seq: head.seq - 1n },
      { ...head, hash: Buffer.alloc(32, 7) },
    ]) {
      const { id, running } = rebase(orgId, named);
      const { code, line } = await running;
      expect(code).toBe(1);
      expect(line('operator.chain_rebase_refused')).toMatchObject({
        rebaseId: id,
        reason: 'head_differs',
        seq: String(head.seq),
      });
      expect(readdirOrNone(rebases)).not.toContain(id);
    }
    expect((await headOf({ kind: 'organisation', orgId })).seq).toBe(head.seq);
  });

  it('moves the platform chain on, as after it was begun again, and records it there', async () => {
    const head = await anchoredAhead({ kind: 'platform' }, 5n);
    const { id, asked, running } = rebase('platform', head);
    const { code, line } = await running;
    expect(code).toBe(0);
    expect(line('operator.chain_rebased')).toMatchObject({
      chain: 'platform',
      anchorSeq: String(head.seq + 5n),
      shorterBy: '5',
      recorded: 'recorded',
    });
    expect(line('operator.chain_rebased')).not.toHaveProperty('orgId');
    const rows = await database
      .as('admin')
      .query('select seq, actor_id, action from platform_controls.audit_events where id = $1', [id]);
    expect(rows).toEqual([{ seq: String(head.seq + 1n), actor_id: 'operator', action: 'audit_chain.rebased' }]);

    // Its rebase found again: the platform chain holds its event under the rebase's ID already, and refuses a second.
    const again = await run(['--request', asked], env());
    expect(again.code).toBe(1);
    expect(again.line('operator.done_before')).toMatchObject({ rebaseId: id, recorded: 'already' });
  });

  it('a run whose event was not written says so; the same request run again writes only the event', async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 2n);
    faults.signedStates = new Error('the database went away');
    const { id, asked, running } = rebase(orgId, head);

    const first = await running;
    expect(first.code).toBe(1);
    expect(first.line('operator.rebase_not_recorded')).toMatchObject({ orgId, rebaseId: id });
    expect(first.line('operator.chain_rebased')).toMatchObject({ recorded: 'failed' });
    expect(readdirOrNone(rebases)).toContain(id);
    expect((await headOf({ kind: 'organisation', orgId })).seq).toBe(head.seq);

    const again = await run(['--request', asked], env());
    expect(again.code).toBe(0);
    // Every rebase in the store is said as it is read (audit.rebased), this one's among them.
    expect(again.events.filter((event) => event !== 'audit.rebased')).toEqual([
      'operator.starting',
      'audit.anchors_read',
      'operator.rebase_recorded',
    ]);
    expect(again.line('operator.rebase_recorded')).toMatchObject({
      rebaseId: id,
      note: "The rebase was already written; its record on the chain's audit log is now written too.",
    });
    expect(await newestEvent(orgId)).toMatchObject({ action: 'audit_chain.rebased', subject_id: id });
  });

  it("two runs finishing one rebase's record at once write it once: each waits for the rebase's lock before it looks", async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 2n);
    faults.signedStates = new Error('the database went away');
    const { id, asked, running } = rebase(orgId, head);
    expect((await running).line('operator.rebase_not_recorded')).toMatchObject({ rebaseId: id });

    // A third party part-way through, holding the rebase's lock: both runs queue behind it, then go one after the other.
    const holder = await database.connect('admin');
    await holder.query('begin');
    try {
      await holdNamedLock(holder, lockName(REBASE_LOCK, id));
      const both = within(
        30_000,
        Promise.all([run(['--request', asked], env()), run(['--request', asked], env())]),
        'the two runs',
      );
      await waitUntilQueued(database.as('admin'), 2);
      await holder.query('commit');
      const outcomes = (await both).map((done) => [done.code, done.events.at(-1)]);
      expect(outcomes.toSorted()).toEqual([
        [0, 'operator.rebase_recorded'],
        [1, 'operator.done_before'],
      ]);
    } finally {
      await holder.query('rollback');
      await holder.end();
    }
    const written = await database
      .as('admin')
      .query("select count(*)::int as n from audit.events where org_id = $1 and action = 'audit_chain.rebased'", [
        orgId,
      ]);
    expect(written).toEqual([{ n: 1 }]);
  });

  it("dates the rebase by the database's clock, whatever the job's own says", async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 1n);
    const before = await databaseNow(app);
    // The job's clock a year ahead: only Date is faked, so the database and its timers go on as they are.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(Date.now() + 365 * 86_400_000));
    let done: Awaited<ReturnType<typeof run>>;
    try {
      done = await rebase(orgId, head).running;
    } finally {
      vi.useRealTimers();
    }
    expect(done.code).toBe(0);
    const at = Date.parse(String(done.line('operator.chain_rebased')?.at));
    expect(at).toBeGreaterThanOrEqual(before.getTime());
    expect(at).toBeLessThanOrEqual((await databaseNow(app)).getTime());
  });

  /** An organisation whose chain holds two events, its first anchored with another hash: wound back and grown again. */
  async function grownAgainOnAWoundBackHead(): Promise<{ orgId: string; head: CheckedPoint }> {
    const orgId = await madeOrganisation();
    await withTenant(app, orgId, (tx) =>
      createAuditTrail({ keys: auditKeys, ids: uuidV7Ids }).record(tx, orgId, {
        actor: { type: 'system', id: 'api' },
        action: 'probe.noted',
        subject: { type: 'probe', id: orgId, version: 1 },
        details: { n: 1 },
      }),
    );
    const head = await headOf({ kind: 'organisation', orgId });
    const log = apiLog();
    await log.read();
    const first = { seq: 1n, hash: Buffer.alloc(32, 9), macKeyVersion: head.macKeyVersion };
    log.keep(signAnchor(apiAnchorKey, { kind: 'organisation', orgId }, first, new Date(), 1));
    await log.flush();
    return { orgId, head };
  }

  it('moves a chain grown again past a wound-back anchor on to its head, giving up nothing', async () => {
    const { orgId, head } = await grownAgainOnAWoundBackHead();
    const { code, events, line } = await rebase(orgId, head).running;
    expect(code).toBe(0);
    expect(events).not.toContain('operator.chain_rebase_shorter');
    expect(line('operator.chain_rebased')).toMatchObject({ seq: String(head.seq), anchorSeq: '1', shorterBy: '0' });
  });

  it('SEC-DB-11 refuses a chain that fails its own check past where it fails its anchor', async () => {
    const { orgId, head } = await grownAgainOnAWoundBackHead();
    await database
      .as('admin')
      .query(`update audit.events set details = '{"forged":1}' where org_id = $1 and seq = 2`, [orgId]);
    const { code, line } = await rebase(orgId, head).running;
    expect(code).toBe(1);
    expect(line('operator.chain_rebase_refused')).toMatchObject({ reason: 'broken', seq: '2' });
  });

  it('finishes a rebase found in the store for a chain that had no anchor before, its record naming none', async () => {
    const orgId = await madeOrganisation();
    const head = await headOf({ kind: 'organisation', orgId });
    const id = uuidV7Ids.next();
    const fresh = signRebase(auditKeys, 1, {
      id,
      chain: `organisation:${orgId}`,
      seq: head.seq,
      hash: head.hash,
      macKeyVersion: head.macKeyVersion,
      at: await databaseNow(app),
      reason: 'recovered',
      evidence: EVIDENCE,
      from: null,
    });
    await folderWriteOnceStore(anchors).put(`e1/rebases/${id}`, rebaseFile(fresh));
    const { code, line } = await rebase(orgId, head, { id }).running;
    expect(code).toBe(0);
    expect(line('operator.rebase_recorded')).toMatchObject({ rebaseId: id });
    expect(JSON.parse(String((await newestEvent(orgId))?.details))).toMatchObject({ rebaseId: id, fromSeq: null });
  });

  it("says the record failed when the organisation's audit log about the rebase can't be verified", async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 1n);
    const { id, asked, running } = rebase(orgId, head);
    expect((await running).code).toBe(0);
    await database
      .as('admin')
      .query(`update audit.events set details = '{"forged":1}' where org_id = $1 and subject_id = $2`, [orgId, id]);
    const again = await run(['--request', asked], env());
    expect(again.code).toBe(1);
    expect(again.line('operator.rebase_not_recorded')).toMatchObject({ rebaseId: id });
    expect(again.line('operator.done_before')).toMatchObject({ rebaseId: id, recorded: 'failed' });
  });

  it("says the platform chain's record failed, for any refusal but its own event there already", async () => {
    const head = await anchoredAhead({ kind: 'platform' }, 2n);
    faults.platformRecord = new Error('the database went away');
    const { id, running } = rebase('platform', head);
    const { code, line } = await running;
    expect(code).toBe(1);
    expect(line('operator.rebase_not_recorded')).toMatchObject({ rebaseId: id });
    expect(line('operator.chain_rebased')).toMatchObject({ recorded: 'failed' });
  });

  it("refuses a rebase whose file another run wrote first, and fails on any other failure of the store's write", async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 1n);
    faults.storePut = new OverwriteRefused();
    const raced = await rebase(orgId, head).running;
    expect(raced.code).toBe(1);
    expect(raced.line('operator.done_before')).toMatchObject({ command: 'chain-rebase', recorded: null });

    faults.storePut = new Error('the store went away');
    const failed = await rebase(orgId, head).running;
    expect(failed.code).toBe(1);
    expect(failed.line('operator.failed')).toMatchObject({ command: 'chain-rebase' });
    expect((await headOf({ kind: 'organisation', orgId })).seq).toBe(head.seq);
  });

  it('refuses a chain that holds its anchor, or has none: nothing to move', async () => {
    const orgId = await madeOrganisation();
    const { id, running } = rebase(orgId, await headOf({ kind: 'organisation', orgId }));
    const { code, line } = await running;
    expect(code).toBe(1);
    expect(line('operator.chain_rebase_refused')).toMatchObject({ orgId, reason: 'not_needed', seq: null });
    expect(readdirOrNone(rebases)).not.toContain(id);
  });

  it('SEC-DB-11 refuses a chain that fails its own check: a rebase never blesses what the app did not write', async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 3n);
    await database
      .as('admin')
      .query(`update audit.events set details = '{"forged":1}' where org_id = $1 and seq = 1`, [orgId]);

    const { id, running } = rebase(orgId, head);
    const { code, line } = await running;

    expect(code).toBe(1);
    expect(line('operator.chain_rebase_refused')).toMatchObject({ rebaseId: id, reason: 'broken', seq: '1' });
    expect(readdirOrNone(rebases)).not.toContain(id);
  });

  it('refuses a rebase whose ID is taken in the store by something else, and one the store cannot be read for', async () => {
    const orgId = await madeOrganisation();
    const head = await anchoredAhead({ kind: 'organisation', orgId }, 3n);
    const id = uuidV7Ids.next();
    await folderWriteOnceStore(anchors).put(`e1/rebases/${id}`, Buffer.from('taken'));
    const taken = await rebase(orgId, head, { id }).running;
    expect(taken.code).toBe(1);
    expect(taken.line('operator.done_before')).toMatchObject({ command: 'chain-rebase', rebaseId: id, recorded: null });
    expect((await headOf({ kind: 'organisation', orgId })).seq).toBe(head.seq);

    const notAFolder = path.join(folder, 'not-a-folder');
    writeFileSync(notAFolder, '');
    const unread = await rebase(orgId, head, { store: notAFolder }).running;
    expect(unread.code).toBe(1);
    expect(unread.line('operator.chain_rebase_refused')).toMatchObject({ reason: 'store' });
  });

  it('reads nothing when the live server does not prove itself read-only', async () => {
    faults.readOnly.push(false);
    const { code, line } = await rebase('platform', await headOf({ kind: 'platform' })).running;
    expect(code).toBe(1);
    expect(line('operator.refused')).toMatchObject({
      problems: ['the connection is not read-only, so nothing was read'],
    });
  });
});

/** A folder's names, or none where it isn't there yet. */
function readdirOrNone(folder: string): string[] {
  return existsSync(folder) ? readdirSync(folder) : [];
}
