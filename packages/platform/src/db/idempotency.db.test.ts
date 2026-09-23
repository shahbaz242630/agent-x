// API idempotency (idempotency.ts, db/migrations/0006_idempotency.sql): each
// write that carries an idempotency key is done once, on the real table, with
// a stand-in tenant table (probe.items) for the write itself, as a module's
// write would be.
import { createHash } from 'node:crypto';

import {
  createTenantProbe,
  createTestDatabase,
  failures,
  LogCapture,
  SENSITIVE_SAMPLES,
  successes,
  type TestDatabase,
  type TestSession,
  waitUntilQueued,
} from '@agentx/testing';
import { sql, type Transaction } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createKeyProvider, type KeyMaterial, type KeyProvider, type PurposeKeys } from '../keys/key-provider.ts';
import { type KeyPurpose, PURPOSES } from '../keys/purposes.ts';
import { createLogger } from '../observability/index.ts';
import { createDatabase, type Database } from './database.ts';
import {
  createIdempotentWrites,
  IDEMPOTENCY_RETENTION_DAYS,
  type IdempotencyClient,
  IdempotencyFailed,
  type IdempotentRequest,
  type IdempotentResult,
  type IdempotentWrite,
  sweepIdempotencyKeys,
} from './idempotency.ts';
import { TenantContextError, withTenant } from './tenant.ts';

interface ProbeTables {
  'probe.items': { org_id: string; id: string; label: string };
}

/** A key's row as the server's superuser reads it, past row security. */
interface StoredKey {
  org_id: string;
  client_kind: string;
  client_id: string;
  operation: string;
  key: string;
  request_hash: Buffer;
  request_hash_key_version: number;
  created_at: Date;
  result_status: number | null;
  result_id: string | null;
}

const server = inject('postgres');
let database: TestDatabase;
let app: Database<ProbeTables>;
/** The server's superuser: past every wall, for setting up and for playing the attacker. */
let admin: TestSession;
let capture: LogCapture;

const ORG = '0199a0f1-0000-7000-8000-00000000000a';
const OTHER_ORG = '0199a0f1-0000-7000-8000-00000000000b';
const AGENT = '0199a0f1-0000-7000-8000-0000000000a1';
const OTHER_AGENT = '0199a0f1-0000-7000-8000-0000000000a2';

const fill = (byte: number): Buffer => Buffer.alloc(32, byte);
/** The request-hash key most tests use, and the same key rotated to a version 2 beside it. */
const REQUEST_HASH_V1: PurposeKeys = { current: 1, versions: new Map([[1, fill(0x02)]]) };
const ROTATED: PurposeKeys = {
  current: 2,
  versions: new Map([
    [1, fill(0x02)],
    [2, fill(0x03)],
  ]),
};

/** Every purpose's stand-in key, each its own, with the request-hash key given, and any other purpose's. */
function keysWith(requestHash: PurposeKeys, others: Partial<Record<KeyPurpose, PurposeKeys>> = {}): KeyProvider {
  const material = Object.fromEntries(
    PURPOSES.map((purpose, index) => [
      purpose,
      purpose === 'request-hash'
        ? requestHash
        : (others[purpose] ?? { current: 1, versions: new Map([[1, fill(0x10 + index)]]) }),
    ]),
  ) as KeyMaterial;
  return createKeyProvider(material);
}

const KEYS = keysWith(REQUEST_HASH_V1);

function loggerFor(destination: LogCapture) {
  return createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination,
  });
}

const writes = (keys = KEYS) => createIdempotentWrites({ keys, logger: loggerFor(capture) });
/** How long a race waits for its parties to queue: longer than the default, for a slow CI runner opening connections. */
const QUEUE_WAIT = { timeoutMs: 20_000 };

/** The promise's value, or a failure once `ms` have passed without one. */
async function within<T>(ms: number, promise: Promise<T> | undefined, what: string): Promise<T> {
  if (promise === undefined) throw new Error(`Nothing to wait for: ${what}`);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Waited ${ms.toString()} ms for ${what}`));
    }, ms);
  });
  try {
    return await Promise.race([promise, late]);
  } finally {
    clearTimeout(timer);
  }
}
const linesNamed = (event: string) => capture.lines().filter((line) => line.event === event);

let serial = 0;
/** A number no other test uses, so no two tests share a key or an item. */
const next = (): number => {
  serial += 1;
  return serial;
};
const newId = (): string => `0199a0f1-0000-7000-8000-${(0x1000 + next()).toString(16).padStart(12, '0')}`;
const newKey = (): string => `key-${next().toString()}`;

function requestFor(key: string, changes: Partial<IdempotentRequest> = {}): IdempotentRequest {
  return {
    orgId: ORG,
    client: { kind: 'agent', id: AGENT },
    operation: 'items.create',
    key,
    payload: '{"label":"first"}',
    ...changes,
  };
}

/** How many times a write itself has run, across every test. */
let writesDone = 0;

/** A write as a module does one: a new item in the organisation, whose ID is the result. */
async function createItem(tx: Transaction<ProbeTables>, orgId: string): Promise<IdempotentResult> {
  writesDone += 1;
  const id = newId();
  await tx.insertInto('probe.items').values({ org_id: orgId, id, label: 'made' }).execute();
  return { status: 201, resourceId: id };
}

type Work = (tx: Transaction<ProbeTables>, orgId: string) => Promise<IdempotentResult>;

/** One idempotent write in its own transaction, as a route would run it. */
function write(
  request: IdempotentRequest,
  { keys = KEYS, work = createItem }: { readonly keys?: KeyProvider; readonly work?: Work } = {},
): Promise<IdempotentWrite> {
  return withTenant(app, request.orgId, (tx) => writes(keys).run(tx, request, () => work(tx, request.orgId)));
}

/** The first write with a key: its result, or a failed test. */
async function firstWrite(
  request: IdempotentRequest,
  options?: Parameters<typeof write>[1],
): Promise<IdempotentResult> {
  const outcome = await write(request, options);
  if (outcome.outcome !== 'done') throw new Error(`Expected the write to be done, but it was ${outcome.outcome}`);
  return outcome.result;
}

const storedKeys = (key: string) =>
  admin.query<StoredKey>('select * from idempotency.keys where key = $1 order by org_id, client_id, operation', [key]);
const items = (orgId = ORG) =>
  admin.query<{ id: string }>('select id from probe.items where org_id = $1 order by id', [orgId]);

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  await createTenantProbe(database);
  app = createDatabase<ProbeTables>({ ...database.connection('app'), maxConnections: 12 }, loggerFor(new LogCapture()));
  admin = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe('ADR-007 §4 a write with an idempotency key is done once', () => {
  it('does the write, records its result against the key, and answers it', async () => {
    const key = newKey();
    const before = await items();

    const outcome = await write(requestFor(key));

    const after = await items();
    expect(after).toHaveLength(before.length + 1);
    const made = after.find((item) => !before.some((earlier) => earlier.id === item.id));
    expect(outcome).toEqual({ outcome: 'done', result: { status: 201, resourceId: made?.id } });
    const [row, ...others] = await storedKeys(key);
    expect(others).toEqual([]);
    expect(row).toMatchObject({
      org_id: ORG,
      client_kind: 'agent',
      client_id: AGENT,
      operation: 'items.create',
      key,
      request_hash_key_version: 1,
      result_status: 201,
      result_id: made?.id,
    });
    expect(row?.request_hash).toHaveLength(32);
    // The database's own clock: the container's may differ from this machine's.
    expect(
      await admin.query(
        "select 1 from idempotency.keys where key = $1 and created_at between pg_catalog.now() - interval '1 minute' and pg_catalog.now()",
        [key],
      ),
    ).toHaveLength(1);
  });

  it('SEC-DP-07 answers a retry of the same request with the stored result, without doing the write again', async () => {
    const key = newKey();
    const result = await firstWrite(requestFor(key));
    const done = writesDone;
    const before = await items();

    expect(await write(requestFor(key))).toEqual({ outcome: 'replayed', result });
    expect(await write(requestFor(key))).toEqual({ outcome: 'replayed', result });

    expect(writesDone).toBe(done);
    expect(await items()).toEqual(before);
    expect(await storedKeys(key)).toHaveLength(1);
    expect(linesNamed('idempotency.replayed')).toEqual([
      expect.objectContaining({
        level: 'info',
        orgId: ORG,
        operation: 'items.create',
        clientKind: 'agent',
        clientId: AGENT,
        idempotencyKey: key,
        resultStatus: 201,
      }),
      expect.objectContaining({ level: 'info', idempotencyKey: key }),
    ]);
  });

  it('SEC-DP-08 answers a request asking for something else with a conflict, and changes nothing', async () => {
    const key = newKey();
    await firstWrite(requestFor(key));
    const stored = await storedKeys(key);
    const done = writesDone;

    expect(await write(requestFor(key, { payload: '{"label":"second"}' }))).toEqual({ outcome: 'conflict' });

    expect(writesDone).toBe(done);
    expect(await storedKeys(key)).toEqual(stored);
    expect(linesNamed('idempotency.conflict')).toEqual([
      expect.objectContaining({
        level: 'warn',
        orgId: ORG,
        operation: 'items.create',
        clientKind: 'agent',
        clientId: AGENT,
        idempotencyKey: key,
      }),
    ]);
  });

  it('keeps each organisation, client and operation to its own keys, and answers each retry from its own row', async () => {
    const key = newKey();
    const neighbours = [
      requestFor(key),
      requestFor(key, { orgId: OTHER_ORG }),
      requestFor(key, { client: { kind: 'agent', id: OTHER_AGENT } }),
      requestFor(key, { client: { kind: 'user', id: AGENT } }),
      requestFor(key, { operation: 'items.rename' }),
      requestFor(`${key}-next`),
    ];

    const results: IdempotentResult[] = [];
    for (const request of neighbours) results.push(await firstWrite(request));

    for (const [index, request] of neighbours.entries()) {
      expect(await write(request)).toEqual({ outcome: 'replayed', result: results[index] });
    }
    expect(new Set(results.map((result) => result.resourceId)).size).toBe(neighbours.length);
    expect(await storedKeys(key)).toHaveLength(neighbours.length - 1);
  });

  it('takes IDs in any case, as Postgres reads a uuid', async () => {
    const key = newKey();
    const result = await firstWrite(requestFor(key));

    const shouted = requestFor(key, {
      orgId: ORG.toUpperCase(),
      client: { kind: 'agent', id: AGENT.toUpperCase() },
    });
    expect(await write(shouted)).toEqual({ outcome: 'replayed', result });
    // Logged in lower case too, so one search finds every line about the client.
    expect(linesNamed('idempotency.replayed')).toEqual([expect.objectContaining({ orgId: ORG, clientId: AGENT })]);
  });

  it("answers the resource's ID as Postgres prints it, whatever case the write gave it in", async () => {
    const key = newKey();
    const id = newId();

    const outcome = await write(requestFor(key), {
      work: async (tx, orgId) => {
        await tx.insertInto('probe.items').values({ org_id: orgId, id, label: 'made' }).execute();
        return { status: 200, resourceId: id.toUpperCase() };
      },
    });

    expect(outcome).toEqual({ outcome: 'done', result: { status: 200, resourceId: id } });
    expect(await write(requestFor(key))).toEqual({ outcome: 'replayed', result: { status: 200, resourceId: id } });
  });

  it('leaves the key unused when the write is refused along the way, so it works once the refusal is lifted', async () => {
    const key = newKey();
    const refusal = new Error('ORG_FROZEN, say');
    const before = await items();

    await expect(
      write(requestFor(key), {
        work: async (tx, orgId) => {
          await createItem(tx, orgId);
          throw refusal;
        },
      }),
    ).rejects.toBe(refusal);

    expect(await storedKeys(key)).toEqual([]);
    expect(await items()).toEqual(before);
    expect(await write(requestFor(key, { payload: 'changed after the refusal' }))).toMatchObject({ outcome: 'done' });
  });

  it('is undone with the transaction it runs in', async () => {
    const key = newKey();
    const undone = new Error('undone');

    await expect(
      withTenant(app, ORG, async (tx) => {
        await writes().run(tx, requestFor(key), () => createItem(tx, ORG));
        throw undone;
      }),
    ).rejects.toBe(undone);

    expect(await storedKeys(key)).toEqual([]);
    expect(await write(requestFor(key))).toMatchObject({ outcome: 'done' });
  });

  it('leaves the key unused when the caller catches the refusal and commits the rest of its transaction', async () => {
    const key = newKey();
    const refusal = new Error('ORG_FROZEN, say');
    const before = await items();
    const noted = newId();

    // As a route answering a temporary refusal would: its audit event (here an item) in the same transaction.
    await withTenant(app, ORG, async (tx) => {
      await expect(
        writes().run(tx, requestFor(key), async () => {
          await createItem(tx, ORG);
          throw refusal;
        }),
      ).rejects.toBe(refusal);
      await tx.insertInto('probe.items').values({ org_id: ORG, id: noted, label: 'refusal noted' }).execute();
    });

    expect(await storedKeys(key)).toEqual([]);
    const after = await items();
    expect(after).toHaveLength(before.length + 1);
    expect(after).toContainEqual({ id: noted });
    expect(await write(requestFor(key))).toMatchObject({ outcome: 'done' });
  });

  it('lets a request waiting on the key go ahead as soon as a refused claim is rolled back, while its transaction goes on', async () => {
    const key = newKey();
    const refusal = new Error('refused along the way');
    let claimed = (): void => undefined;
    const hasClaimed = new Promise<void>((resolve) => {
      claimed = resolve;
    });
    // Filled in once the first has claimed; an object, since the first's transaction reads it later.
    const waiting: { second?: Promise<IdempotentWrite> } = {};

    const first = withTenant(app, ORG, async (tx) => {
      await writes()
        .run(tx, requestFor(key), async () => {
          claimed();
          await waitUntilQueued(admin, 1, QUEUE_WAIT);
          throw refusal;
        })
        .catch((error: unknown) => {
          if (error !== refusal) throw error;
        });
      // Still open: the waiting request must finish before this transaction
      // ends. Bounded, so a claim still held fails the test rather than hanging
      // it; this transaction then rolls back, and the waiter goes on.
      return within(QUEUE_WAIT.timeoutMs, waiting.second, 'the waiting request to finish');
    });
    await hasClaimed;
    waiting.second = write(requestFor(key, { payload: '{"label":"second"}' }));

    expect(await first).toMatchObject({ outcome: 'done' });
    expect(await storedKeys(key)).toHaveLength(1);
  });

  it("leaves no claim behind when the write rolls back past the claim's savepoint before it fails", async () => {
    const key = newKey();
    const refusal = new Error('refused after rolling back to an earlier savepoint');

    await withTenant(app, ORG, async (tx) => {
      await sql`savepoint before_the_claim`.execute(tx);
      await expect(
        writes().run(tx, requestFor(key), async () => {
          // Undoes the claim and ends its savepoint, which then can't be rolled back to.
          await sql`rollback to savepoint before_the_claim`.execute(tx);
          throw refusal;
        }),
      ).rejects.toBe(refusal);
    });

    expect(linesNamed('idempotency.rollback_failed')).toEqual([
      expect.objectContaining({ level: 'error', idempotencyKey: key }),
    ]);
    expect(await storedKeys(key)).toEqual([]);
  });

  it("keeps a savepoint the write opens of its own from standing in for the claim's", async () => {
    const key = newKey();
    const refusal = new Error('refused inside a savepoint of its own');

    await withTenant(app, ORG, async (tx) => {
      await expect(
        writes().run(tx, requestFor(key), async () => {
          await sql`savepoint idempotency_claim`.execute(tx);
          await createItem(tx, ORG);
          throw refusal;
        }),
      ).rejects.toBe(refusal);
    });

    expect(await storedKeys(key)).toEqual([]);
    expect(linesNamed('idempotency.rollback_failed')).toEqual([]);
  });

  it('leaves its transaction usable when the claim itself fails', async () => {
    const key = newKey();
    const noted = newId();
    const owner = database.as('owner');
    // The claim's insert fails: the app's right to add keys taken away, as the table's owner could.
    await owner.query('revoke insert on idempotency.keys from agentx_app');
    try {
      await withTenant(app, ORG, async (tx) => {
        await expect(writes().run(tx, requestFor(key), () => createItem(tx, ORG))).rejects.toMatchObject({
          code: '42501',
        });
        // Rolled back to before the claim, so the transaction goes on and commits.
        await tx.insertInto('probe.items').values({ org_id: ORG, id: noted, label: 'after a failed claim' }).execute();
      });
    } finally {
      await owner.query('grant insert on idempotency.keys to agentx_app');
    }

    expect(await items()).toContainEqual({ id: noted });
    expect(await storedKeys(key)).toEqual([]);
  });
});

describe('the tenant walls (ADR-005)', () => {
  it("refuses to run outside the request's organisation's transaction, where its keys can't be seen", async () => {
    const key = newKey();

    await expect(
      withTenant(app, OTHER_ORG, (tx) => writes().run(tx, requestFor(key), () => createItem(tx, ORG))),
    ).rejects.toBeInstanceOf(TenantContextError);
    await expect(
      app.transaction().execute((tx) => writes().run(tx, requestFor(key), () => createItem(tx, ORG))),
    ).rejects.toBeInstanceOf(TenantContextError);
    expect(await storedKeys(key)).toEqual([]);
  });

  it("can't read another organisation's key (SEC-TEN-01), and its own claim of the same key is its own", async () => {
    const key = newKey();
    await firstWrite(requestFor(key, { orgId: OTHER_ORG }));

    const seen = await withTenant(app, ORG, (tx) =>
      sql<{ key: string }>`select key from idempotency.keys where key = ${key}`.execute(tx),
    );

    expect(seen.rows).toEqual([]);
    expect(await write(requestFor(key))).toMatchObject({ outcome: 'done' });
  });
});

describe('ADR-006 §6 the key is claimed first in its transaction', () => {
  const notFirst = async (running: Promise<unknown>, key: string) => {
    await expect(running).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(running).rejects.toMatchObject({ reason: 'not_first' });
    expect(await storedKeys(key)).toEqual([]);
  };

  it('refuses a claim once its transaction has written', async () => {
    const key = newKey();
    const before = await items();

    await notFirst(
      withTenant(app, ORG, async (tx) => {
        await createItem(tx, ORG);
        return writes().run(tx, requestFor(key), () => createItem(tx, ORG));
      }),
      key,
    );
    expect(await items()).toEqual(before);
  });

  it('refuses a claim once its transaction has locked a row', async () => {
    const key = newKey();
    const id = newId();
    await admin.query("insert into probe.items (org_id, id, label) values ($1, $2, 'there')", [ORG, id]);

    await notFirst(
      withTenant(app, ORG, async (tx) => {
        await sql`select 1 from probe.items where org_id = ${ORG} and id = ${id} for share`.execute(tx);
        return writes().run(tx, requestFor(key), () => createItem(tx, ORG));
      }),
      key,
    );
  });

  it('refuses a second claim in the same transaction', async () => {
    const [outer, inner] = [newKey(), newKey()];

    await notFirst(
      withTenant(app, ORG, (tx) =>
        writes().run(tx, requestFor(outer), async () => {
          await writes().run(tx, requestFor(inner), () => createItem(tx, ORG));
          return createItem(tx, ORG);
        }),
      ),
      inner,
    );
    expect(await storedKeys(outer)).toEqual([]);
  });

  it.each<[string, (key: string) => IdempotentRequest]>([
    ['a stored result', (key) => requestFor(key)],
    ['a conflict', (key) => requestFor(key, { payload: '{"label":"other"}' })],
  ])('refuses a second claim in a transaction whose first was answered with %s', async (_answer, retry) => {
    const [first, second] = [newKey(), newKey()];
    await firstWrite(requestFor(first));

    await notFirst(
      withTenant(app, ORG, async (tx) => {
        // Answered from the row: the transaction has written nothing, yet it has claimed.
        await writes().run(tx, retry(first), () => createItem(tx, ORG));
        return writes().run(tx, requestFor(second), () => createItem(tx, ORG));
      }),
      second,
    );
  });

  it('lets a transaction read before it claims', async () => {
    const key = newKey();

    const outcome = await withTenant(app, ORG, async (tx) => {
      await sql`select count(*) from probe.items`.execute(tx);
      return writes().run(tx, requestFor(key), () => createItem(tx, ORG));
    });

    expect(outcome).toMatchObject({ outcome: 'done' });
  });
});

describe('the request hash (ADR-014 §3)', () => {
  it('SEC-PAY-05 keeps a request carrying bank details only as a keyed hash: never the request, never its plain hash', async () => {
    const key = newKey();
    const iban = SENSITIVE_SAMPLES.uaeIban;
    const payload = JSON.stringify({ iban });

    await firstWrite(requestFor(key, { payload }));

    const [row] = await admin.query<{ text: string; request_hash: Buffer }>(
      'select pg_catalog.row_to_json(k)::text as text, request_hash from idempotency.keys k where key = $1',
      [key],
    );
    expect(row?.text).not.toContain(iban);
    for (const plain of [payload, iban]) {
      const plainHash = createHash('sha256').update(plain).digest();
      expect(row?.request_hash.equals(plainHash)).toBe(false);
    }
    // Keyed: the same request, checked with another request-hash key, doesn't match.
    const otherKey = keysWith({ current: 1, versions: new Map([[1, fill(0x04)]]) });
    expect(await write(requestFor(key, { payload }), { keys: otherKey })).toEqual({ outcome: 'conflict' });
    expect(await write(requestFor(key, { payload }))).toMatchObject({ outcome: 'replayed' });
    // Nor does it reach the logs: the lines name the key, never the request.
    expect(linesNamed('idempotency.conflict')).toHaveLength(1);
    expect(linesNamed('idempotency.replayed')).toHaveLength(1);
    expect(capture.text).not.toContain(iban);
    expect(capture.text).not.toContain('iban');
  });

  it('SEC-DATA-07 matches a retry during a key rotation, checked with the version its row was made with', async () => {
    const key = newKey();
    const result = await firstWrite(requestFor(key));
    const rotated = keysWith(ROTATED);

    expect(await write(requestFor(key), { keys: rotated })).toEqual({ outcome: 'replayed', result });
    expect(await write(requestFor(key, { payload: 'changed' }), { keys: rotated })).toEqual({ outcome: 'conflict' });

    // New keys are hashed with the current version, and checked with it.
    const fresh = newKey();
    const freshResult = await firstWrite(requestFor(fresh), { keys: rotated });
    expect(await storedKeys(fresh)).toEqual([expect.objectContaining({ request_hash_key_version: 2 })]);
    expect(await write(requestFor(fresh), { keys: rotated })).toEqual({ outcome: 'replayed', result: freshResult });
  });

  it("refuses a row made with a key version this process doesn't hold, rather than call it a conflict", async () => {
    const key = newKey();
    await firstWrite(requestFor(key), { keys: keysWith(ROTATED) });

    const refused = write(requestFor(key));

    await expect(refused).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(refused).rejects.toMatchObject({ reason: 'key_not_held' });
    expect(linesNamed('idempotency.key_not_held')).toEqual([
      expect.objectContaining({ level: 'error', keyVersion: 2, idempotencyKey: key }),
    ]);
  });

  it("looks for the version among the request-hash key's own, not another key's", async () => {
    const key = newKey();
    await firstWrite(requestFor(key), { keys: keysWith(ROTATED) });
    // Another key has a version 2; the request-hash key still has only its first.
    const auditMacRotated = keysWith(REQUEST_HASH_V1, {
      'audit-mac': {
        current: 2,
        versions: new Map([
          [1, fill(0x05)],
          [2, fill(0x06)],
        ]),
      },
    });

    const refused = write(requestFor(key), { keys: auditMacRotated });

    await expect(refused).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(refused).rejects.toMatchObject({ reason: 'key_not_held' });
  });

  /** A key row's primary key, as query values. */
  const primaryKey = ({ orgId, client, operation, key }: IdempotentRequest) => [
    orgId,
    client.kind,
    client.id,
    operation,
    key,
  ];

  it.each<[string, (request: IdempotentRequest) => IdempotentRequest]>([
    ['organisation', (request) => ({ ...request, orgId: OTHER_ORG })],
    ["client's kind", (request) => ({ ...request, client: { kind: 'user', id: AGENT } })],
    ["client's ID", (request) => ({ ...request, client: { kind: 'agent', id: OTHER_AGENT } })],
    ['operation', (request) => ({ ...request, operation: 'items.rename' })],
    ['key', (request) => ({ ...request, key: `${request.key}-other` })],
  ])('seals the %s into the hash: a hash copied from a row without it does not match', async (_part, change) => {
    const original = requestFor(newKey());
    const other = change(original);
    await firstWrite(original);
    await firstWrite(other);
    // The other row given the original's hash, as someone with the table could:
    // the same payload, so only the part changed tells the two apart.
    await admin.query(
      `update idempotency.keys set request_hash = (
         select request_hash from idempotency.keys
         where org_id = $1 and client_kind = $2 and client_id = $3 and operation = $4 and key = $5)
       where org_id = $6 and client_kind = $7 and client_id = $8 and operation = $9 and key = $10`,
      [...primaryKey(original), ...primaryKey(other)],
    );

    expect(await write(other)).toEqual({ outcome: 'conflict' });
  });
});

describe('FX-RACE SEC-DP-09 concurrent requests with one key: one record', () => {
  /** A write that holds its claim until `waiting` others are queued behind it, so they meet it uncommitted. */
  const holdingUntilQueued =
    (waiting: number): Work =>
    async (tx, orgId) => {
      await waitUntilQueued(admin, waiting, QUEUE_WAIT);
      return createItem(tx, orgId);
    };

  it('does the write once for six identical requests at once, and answers the other five with its result', async () => {
    const key = newKey();
    const done = writesDone;
    const before = await items();

    const outcomes = await Promise.allSettled(
      Array.from({ length: 6 }, () => write(requestFor(key), { work: holdingUntilQueued(5) })),
    );

    expect(failures(outcomes)).toEqual([]);
    const settled = successes(outcomes);
    const [first, ...alsoDone] = settled.filter((outcome) => outcome.outcome === 'done');
    expect(alsoDone).toEqual([]);
    expect(first).toBeDefined();
    expect(settled.filter((outcome) => outcome.outcome === 'replayed')).toEqual(
      Array.from({ length: 5 }, () => ({ outcome: 'replayed', result: first?.result })),
    );
    expect(writesDone).toBe(done + 1);
    expect(await items()).toHaveLength(before.length + 1);
    expect(await storedKeys(key)).toHaveLength(1);
  });

  it('does one write for six different requests at once with one key, and answers the rest with conflicts', async () => {
    const key = newKey();
    const done = writesDone;

    const outcomes = await Promise.allSettled(
      Array.from({ length: 6 }, (_, party) =>
        write(requestFor(key, { payload: `{"party":${party.toString()}}` }), { work: holdingUntilQueued(5) }),
      ),
    );

    expect(failures(outcomes)).toEqual([]);
    const settled = successes(outcomes);
    expect(settled.filter((outcome) => outcome.outcome === 'done')).toHaveLength(1);
    expect(settled.filter((outcome) => outcome.outcome === 'conflict')).toHaveLength(5);
    expect(writesDone).toBe(done + 1);
    expect(await storedKeys(key)).toHaveLength(1);
  });

  it('lets a request waiting on the key go ahead as the first when the first rolls back', async () => {
    const key = newKey();
    const refusal = new Error('refused along the way');
    let claimed = (): void => undefined;
    const hasClaimed = new Promise<void>((resolve) => {
      claimed = resolve;
    });

    const first = write(requestFor(key), {
      work: async () => {
        claimed();
        await waitUntilQueued(admin, 1, QUEUE_WAIT);
        throw refusal;
      },
    });
    await hasClaimed;
    // A different payload: the first left nothing behind for it to conflict with.
    const second = write(requestFor(key, { payload: '{"label":"second"}' }));

    await expect(first).rejects.toBe(refusal);
    const outcome = await second;
    expect(outcome).toMatchObject({ outcome: 'done' });
    expect(await storedKeys(key)).toEqual([
      expect.objectContaining({ result_id: outcome.outcome === 'done' ? outcome.result.resourceId : 'none' }),
    ]);
  });
});

describe('what it refuses to take', () => {
  it.each<[string, Partial<IdempotentRequest>]>([
    ['an organisation ID that is not a UUID', { orgId: 'org-1' }],
    [
      'a client that is neither a user nor an agent',
      { client: { kind: 'operator', id: AGENT } as unknown as IdempotencyClient },
    ],
    ["a client's ID that is not a UUID", { client: { kind: 'agent', id: 'agent-1' } }],
    ['an empty operation', { operation: '' }],
    ['an operation in capitals', { operation: 'Items.Create' }],
    ['an operation with an empty word', { operation: 'items..create' }],
    ['an operation ending in a dot', { operation: 'items.' }],
    ['an operation with a space', { operation: 'items create' }],
    ['an operation longer than 64 characters', { operation: `items.${'a'.repeat(59)}` }],
    ['an empty key', { key: '' }],
    ['a key longer than 255 characters', { key: 'k'.repeat(256) }],
    ['a key with a space', { key: 'two words' }],
    ['a key with a letter outside ASCII', { key: 'clé' }],
    ['a key with a line break', { key: 'line\nbreak' }],
    ['a payload that is not text', { payload: Buffer.from('bytes') as unknown as string }],
    // A lone surrogate, which UTF-8 would write as U+FFFD, so it would hash as that.
    ['a payload that is not well-formed text', { payload: String.fromCharCode(0x7b, 0xd800, 0x7d) }],
    // Text in a list would pass a pattern once turned into text.
    ['an organisation ID that is not text', { orgId: [ORG] as unknown as string }],
    ["a client's ID that is not text", { client: { kind: 'agent', id: [AGENT] as unknown as string } }],
    ['an operation that is not text', { operation: ['items.create'] as unknown as string }],
    ['a key that is not text', { key: ['key-listed'] as unknown as string }],
  ])('refuses %s, before asking the database', async (_what, changes) => {
    const key = changes.key ?? newKey();

    const refused = withTenant(app, ORG, (tx) => writes().run(tx, requestFor(key, changes), () => createItem(tx, ORG)));

    await expect(refused).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(refused).rejects.toMatchObject({ reason: 'bad_request' });
    expect(await storedKeys(key)).toEqual([]);
  });

  it('takes a key of 255 visible characters and an operation of 64', async () => {
    const key = `${newKey()}-${'!~'.repeat(200)}`.slice(0, 255);
    const operation = `items.${'a'.repeat(58)}`;

    expect(await write(requestFor(key, { operation }))).toMatchObject({ outcome: 'done' });
    expect(await storedKeys(key)).toEqual([expect.objectContaining({ key, operation })]);
  });

  it.each<[string, IdempotentResult]>([
    ['a status below 200', { status: 199, resourceId: AGENT }],
    ['a status of 300', { status: 300, resourceId: AGENT }],
    ['a refusal status', { status: 409, resourceId: AGENT }],
    ['a status that is not a whole number', { status: 200.5, resourceId: AGENT }],
    ['a resource ID that is not a UUID', { status: 201, resourceId: 'item-1' }],
  ])('refuses a write answering %s, and undoes it', async (_what, answer) => {
    const key = newKey();
    const before = await items();

    const refused = write(requestFor(key), {
      work: async (tx, orgId) => {
        await createItem(tx, orgId);
        return answer;
      },
    });

    await expect(refused).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(refused).rejects.toMatchObject({ reason: 'bad_result' });
    expect(await storedKeys(key)).toEqual([]);
    expect(await items()).toEqual(before);
  });
});

describe('a key row changed past this step', () => {
  const unreadable = async (running: Promise<unknown>) => {
    await expect(running).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(running).rejects.toMatchObject({ reason: 'unreadable' });
  };

  it('refuses a row whose claim committed without a result', async () => {
    const key = newKey();
    await firstWrite(requestFor(key));
    await admin.query('update idempotency.keys set result_status = null, result_id = null where key = $1', [key]);

    await unreadable(write(requestFor(key)));
    expect(linesNamed('idempotency.unreadable')).toEqual([
      expect.objectContaining({ level: 'error', problem: 'no_result', idempotencyKey: key }),
    ]);
  });

  it("records the result on the claimed row alone, though the client's other rows lie without one", async () => {
    const key = newKey();
    const claim = requestFor(key);
    // Rows left without a result by someone past this step, each differing from the claim in one part.
    const neighbours = [
      { ...claim, client: { kind: 'user', id: AGENT } },
      { ...claim, client: { kind: 'agent', id: OTHER_AGENT } },
      { ...claim, operation: 'items.rename' },
      { ...claim, key: `${key}-next` },
    ] satisfies IdempotentRequest[];
    for (const { client, operation, key: theirKey } of neighbours) {
      await admin.query(
        `insert into idempotency.keys
           (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at)
         values ($1, $2, $3, $4, $5, $6, 1, pg_catalog.now())`,
        [ORG, client.kind, client.id, operation, theirKey, fill(1)],
      );
    }

    expect(await write(claim)).toMatchObject({ outcome: 'done' });

    const untouched = await admin.query<{ result_status: number | null }>(
      'select result_status from idempotency.keys where org_id = $1 and key in ($2, $3) and result_status is null',
      [ORG, key, `${key}-next`],
    );
    expect(untouched).toHaveLength(neighbours.length);
  });

  it('refuses a claim whose result was written by something else first, and undoes the write', async () => {
    const key = newKey();
    const before = await items();

    const refused = write(requestFor(key), {
      work: async (tx, orgId) => {
        await sql`update idempotency.keys set result_status = 200, result_id = ${AGENT} where key = ${key}`.execute(tx);
        return createItem(tx, orgId);
      },
    });

    await expect(refused).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(refused).rejects.toMatchObject({ reason: 'not_applied' });
    expect(linesNamed('idempotency.not_applied')).toEqual([
      expect.objectContaining({ level: 'error', idempotencyKey: key }),
    ]);
    expect(await storedKeys(key)).toEqual([]);
    expect(await items()).toEqual(before);
  });

  it("refuses a row row security hides from the read, though it stands in the claim's way", async () => {
    const key = newKey();
    await firstWrite(requestFor(key));
    const owner = database.as('owner');
    // A rewritten policy that still passes a new claim's row but hides every
    // row with a result, as the table's owner could write it.
    await owner.query('alter policy tenant_isolation on idempotency.keys using (result_status is null)');
    try {
      await unreadable(write(requestFor(key)));
    } finally {
      await owner.query(
        "alter policy tenant_isolation on idempotency.keys using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)",
      );
    }
    expect(linesNamed('idempotency.unreadable')).toEqual([
      expect.objectContaining({ level: 'error', problem: 'row_hidden' }),
    ]);
    // Taken first for a key swept since (B1e-2): claimed again once, and hidden still.
    expect(linesNamed('idempotency.claimed_again')).toEqual([expect.objectContaining({ idempotencyKey: key })]);
    expect(await write(requestFor(key))).toMatchObject({ outcome: 'replayed' });
  });
});

describe('the retention sweep (B1e, db/migrations/0009)', () => {
  /** A claimed key in the organisation, its claim moved back `age` (a Postgres interval) past the app. */
  async function keyAged(orgId: string, age: string, key = newKey()): Promise<string> {
    await firstWrite(requestFor(key, { orgId }));
    await admin.query(
      'update idempotency.keys set created_at = pg_catalog.now() - $3::interval where org_id = $1 and key = $2',
      [orgId, key, age],
    );
    return key;
  }
  const kept = async (orgId: string): Promise<string[]> =>
    (
      await admin.query<{ key: string }>('select key from idempotency.keys where org_id = $1 order by key', [orgId])
    ).map((row) => row.key);
  const sweep = (orgId: string, most = 100) => withTenant(app, orgId, (tx) => sweepIdempotencyKeys(tx, orgId, most));

  it('deletes only the keys past their 30 days, of this organisation alone, and says how many', async () => {
    const [org, other] = [newId(), newId()];
    await keyAged(org, '30 days 1 minute');
    const young = await keyAged(org, '29 days 23 hours');
    const fresh = await keyAged(org, '0 seconds');
    const othersOld = await keyAged(other, '90 days');

    expect(IDEMPOTENCY_RETENTION_DAYS).toBe(30);
    expect(await sweep(org)).toBe(1);
    expect(await kept(org)).toEqual([fresh, young].sort());
    expect(await kept(other)).toEqual([othersOld]);
    expect(await sweep(org)).toBe(0);
  });

  it('deletes at most as many as asked, oldest first, so a caller sweeps again while it gets that many', async () => {
    const org = newId();
    // Claimed youngest first, so the table's own order isn't oldest first.
    const old = await keyAged(org, '40 days');
    await keyAged(org, '50 days');
    await keyAged(org, '60 days');

    expect(await sweep(org, 2)).toBe(2);
    expect(await kept(org)).toEqual([old]);
    expect(await sweep(org, 2)).toBe(1);
    expect(await kept(org)).toEqual([]);
  });

  it('lets a swept key be claimed again, as a new request', async () => {
    const org = newId();
    const key = await keyAged(org, '31 days');
    await sweep(org);

    expect(await write(requestFor(key, { orgId: org, payload: '{"label":"again"}' }))).toMatchObject({
      outcome: 'done',
    });
  });

  it("is held by the database too: the app's own DELETE reaches no key younger than 30 days", async () => {
    const org = newId();
    const young = await keyAged(org, '29 days');
    const old = await keyAged(org, '31 days');

    const deleted = await withTenant(app, org, (tx) =>
      sql<{ key: string }>`delete from idempotency.keys returning key`.execute(tx),
    );
    expect(deleted.rows).toEqual([{ key: old }]);
    expect(await kept(org)).toEqual([young]);
  });

  it.each([
    ['an organisation ID that is not a UUID', 'not-a-uuid', 100],
    ['no keys', undefined, 0],
    ['more than 10,000 keys', undefined, 10_001],
    ['part of a key', undefined, 1.5],
  ])('refuses a sweep of %s, before any SQL', async (_, orgId, most) => {
    const org = newId();
    await expect(withTenant(app, org, (tx) => sweepIdempotencyKeys(tx, orgId ?? org, most))).rejects.toMatchObject({
      name: 'IdempotencyFailed',
      reason: 'bad_request',
    });
  });

  it('B1e-2 claims a key again when it is swept between the claim meeting it and the claim reading it', async () => {
    const org = newId();
    const key = await keyAged(org, '31 days', 'swept-mid-claim');
    const owner = database.as('owner');
    // The sweep, landing at that very moment: the claim's read of the key's
    // old row (the one with a result) deletes it, as the app may delete a key
    // past its retention, and doesn't see it. Once only, so the delete's own
    // read and every later one see rows as they are.
    await owner.query(
      `create function probe.swept_on_read(swept text, result integer) returns boolean
       language plpgsql set search_path = pg_catalog as $$
       begin
         if swept <> 'swept-mid-claim' or result is null or current_setting('probe.swept', true) = 'yes' then return true; end if;
         perform set_config('probe.swept', 'yes', true);
         delete from idempotency.keys where key = swept;
         return false;
       end $$`,
    );
    await owner.query('grant execute on function probe.swept_on_read(text, integer) to agentx_app');
    await owner.query(
      'create policy swept_on_read on idempotency.keys as restrictive for select using (probe.swept_on_read(key, result_status))',
    );
    let outcome: IdempotentWrite;
    try {
      outcome = await write(requestFor(key, { orgId: org, payload: '{"label":"again"}' }));
    } finally {
      await owner.query('drop policy swept_on_read on idempotency.keys');
      await owner.query('drop function probe.swept_on_read(text, integer)');
    }

    expect(outcome).toMatchObject({ outcome: 'done' });
    expect(linesNamed('idempotency.claimed_again')).toEqual([
      expect.objectContaining({ level: 'info', idempotencyKey: key, orgId: org }),
    ]);
    expect(linesNamed('idempotency.unreadable')).toEqual([]);
    expect(await kept(org)).toEqual([key]);
  });

  it('B1e-2 answers from the row of a request that claimed the swept key first, never taking it for hidden', async () => {
    const org = newId();
    const key = await keyAged(org, '31 days', 'swept-and-reclaimed');
    const owner = database.as('owner');
    // As above, and another request claims the key between the sweep and this
    // claim's second try: its row, with its own request's hash, stands there.
    await owner.query(
      `create function probe.reclaimed_on_read(swept text, result integer, org uuid) returns boolean
       language plpgsql set search_path = pg_catalog as $$
       begin
         if swept <> 'swept-and-reclaimed' or result is null or current_setting('probe.swept', true) = 'yes' then return true; end if;
         perform set_config('probe.swept', 'yes', true);
         delete from idempotency.keys where key = swept;
         insert into idempotency.keys
           (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at, result_status, result_id)
         values (org, 'agent', '0199a0f1-0000-7000-8000-0000000000a1', 'items.create', swept,
           pg_catalog.decode(pg_catalog.repeat('07', 32), 'hex'), 1, pg_catalog.now(), 201, org);
         return false;
       end $$`,
    );
    await owner.query('grant execute on function probe.reclaimed_on_read(text, integer, uuid) to agentx_app');
    await owner.query(
      'create policy reclaimed_on_read on idempotency.keys as restrictive for select using (probe.reclaimed_on_read(key, result_status, org_id))',
    );
    let outcome: IdempotentWrite;
    try {
      outcome = await write(requestFor(key, { orgId: org }));
    } finally {
      await owner.query('drop policy reclaimed_on_read on idempotency.keys');
      await owner.query('drop function probe.reclaimed_on_read(text, integer, uuid)');
    }

    expect(outcome).toEqual({ outcome: 'conflict' });
    expect(linesNamed('idempotency.claimed_again')).toHaveLength(1);
    expect(linesNamed('idempotency.unreadable')).toEqual([]);
  });

  it('FX-RACE a claim meeting a sweep still deleting its key waits for the sweep, then claims the key afresh', async () => {
    const org = newId();
    const key = await keyAged(org, '31 days');
    let swept = (): void => undefined;
    const hasSwept = new Promise<void>((resolve) => {
      swept = resolve;
    });
    const sweeping = withTenant(app, org, async (tx) => {
      const count = await sweepIdempotencyKeys(tx, org, 100);
      swept();
      // Still open, so the key's deletion isn't committed until the claim waits on it.
      await waitUntilQueued(admin, 1, QUEUE_WAIT);
      return count;
    });
    await hasSwept;
    const claiming = write(requestFor(key, { orgId: org, payload: '{"label":"again"}' }));

    expect(await sweeping).toBe(1);
    expect(await within(QUEUE_WAIT.timeoutMs, claiming, 'the claim to finish')).toMatchObject({ outcome: 'done' });
    expect(linesNamed('idempotency.claimed_again')).toEqual([]);
  });

  it("takes 10,000, and refuses to sweep outside the organisation's own withTenant", async () => {
    const [org, other] = [newId(), newId()];
    expect(await sweep(org, 10_000)).toBe(0);
    await expect(withTenant(app, other, (tx) => sweepIdempotencyKeys(tx, org, 1))).rejects.toBeInstanceOf(
      TenantContextError,
    );
  });
});

describe('the table itself (db/migrations/0006)', () => {
  it.each([
    [
      'change a request hash',
      (key: string) => sql`update idempotency.keys set request_hash = ${fill(1)} where key = ${key}`,
    ],
    ['change a key', (key: string) => sql`update idempotency.keys set key = 'another' where key = ${key}`],
    [
      'move a key past its retention, where a sweep could reach it (B1e)',
      (key: string) =>
        sql`update idempotency.keys set created_at = pg_catalog.now() - pg_catalog.make_interval(days => 31) where key = ${key}`,
    ],
    [
      'move a key to another client',
      (key: string) => sql`update idempotency.keys set client_id = ${OTHER_AGENT} where key = ${key}`,
    ],
  ])("doesn't let the app %s", async (_what, statement) => {
    const key = newKey();
    await firstWrite(requestFor(key));

    await expect(withTenant(app, ORG, (tx) => statement(key).execute(tx))).rejects.toMatchObject({ code: '42501' });
    expect(await storedKeys(key)).toHaveLength(1);
  });

  /** A row the app could insert by hand, past this step: sound, but for the changes given. */
  interface HandRow {
    client_kind: string;
    operation: string;
    key: string;
    request_hash: Buffer;
    request_hash_key_version: number;
    result_status: number | null;
    result_id: string | null;
  }
  const insertByHand = (changes: Partial<HandRow>) => {
    const row: HandRow = {
      client_kind: 'agent',
      operation: 'items.create',
      key: newKey(),
      request_hash: fill(1),
      request_hash_key_version: 1,
      result_status: 201,
      result_id: AGENT,
      ...changes,
    };
    return withTenant(app, ORG, (tx) =>
      sql`insert into idempotency.keys
            (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at, result_status, result_id)
          values (${ORG}, ${row.client_kind}, ${AGENT}, ${row.operation}, ${row.key}, ${row.request_hash},
                  ${row.request_hash_key_version}, pg_catalog.now(), ${row.result_status}, ${row.result_id})`.execute(
        tx,
      ),
    );
  };

  it('takes a sound row by hand, so each refusal below is its own check', async () => {
    await expect(insertByHand({})).resolves.toBeDefined();
  });

  it.each<[string, Partial<HandRow>]>([
    ['a result status without its resource', { result_id: null }],
    ['a resource without its result status', { result_status: null }],
    ['a result status below 200', { result_status: 199 }],
    ['a result status above 299', { result_status: 300 }],
    ['a client of another kind', { client_kind: 'operator' }],
    ['an empty operation', { operation: '' }],
    ['an operation longer than 64 bytes', { operation: 'o'.repeat(65) }],
    ['an empty key', { key: '' }],
    ['a key longer than 255 bytes', { key: 'k'.repeat(256) }],
    ['a request hash that is not 32 bytes', { request_hash: Buffer.alloc(31, 1) }],
    ['a key version below 1', { request_hash_key_version: 0 }],
  ])('refuses %s', async (_what, changes) => {
    await expect(insertByHand(changes)).rejects.toMatchObject({ code: '23514' });
  });

  it('lets the backup role read every organisation, and nothing more', async () => {
    const key = newKey();
    await firstWrite(requestFor(key));
    await firstWrite(requestFor(key, { orgId: OTHER_ORG }));
    const backup = database.as('backup');

    expect(await backup.query('select org_id from idempotency.keys where key = $1', [key])).toHaveLength(2);
    const refused = { code: '42501' };
    await expect(backup.query('delete from idempotency.keys where key = $1', [key])).rejects.toMatchObject(refused);
    await expect(
      backup.query('update idempotency.keys set result_status = 200 where key = $1', [key]),
    ).rejects.toMatchObject(refused);
    await expect(
      backup.query(
        "insert into idempotency.keys (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at) select org_id, client_kind, client_id, operation, key || '-copy', request_hash, request_hash_key_version, created_at from idempotency.keys where key = $1",
        [key],
      ),
    ).rejects.toMatchObject(refused);
    expect(await storedKeys(key)).toEqual([
      expect.objectContaining({ org_id: ORG, result_status: 201 }),
      expect.objectContaining({ org_id: OTHER_ORG, result_status: 201 }),
    ]);
  });
});
