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
import { PURPOSES } from '../keys/purposes.ts';
import { createLogger } from '../observability/index.ts';
import { createDatabase, type Database } from './database.ts';
import {
  createIdempotentWrites,
  type IdempotencyClient,
  IdempotencyFailed,
  type IdempotentRequest,
  type IdempotentResult,
  type IdempotentWrite,
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

/** Every purpose's stand-in key, each its own, with the request-hash key given. */
function keysWith(requestHash: PurposeKeys): KeyProvider {
  const material = Object.fromEntries(
    PURPOSES.map((purpose, index) => [
      purpose,
      purpose === 'request-hash' ? requestHash : { current: 1, versions: new Map([[1, fill(0x10 + index)]]) },
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
    expect(Math.abs((row?.created_at.getTime() ?? 0) - Date.now())).toBeLessThan(60_000);
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

  it('keeps each organisation, client and operation to its own keys', async () => {
    const key = newKey();
    const others: readonly Partial<IdempotentRequest>[] = [
      {},
      { orgId: OTHER_ORG },
      { client: { kind: 'agent', id: OTHER_AGENT } },
      { client: { kind: 'user', id: AGENT } },
      { operation: 'items.rename' },
    ];

    for (const changes of others) {
      expect(await write(requestFor(key, changes))).toMatchObject({ outcome: 'done' });
    }

    expect(await storedKeys(key)).toHaveLength(others.length);
  });

  it('takes IDs in any case, as Postgres reads a uuid', async () => {
    const key = newKey();
    const result = await firstWrite(requestFor(key));

    const shouted = requestFor(key, {
      orgId: ORG.toUpperCase(),
      client: { kind: 'agent', id: AGENT.toUpperCase() },
    });
    expect(await write(shouted)).toEqual({ outcome: 'replayed', result });
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

  it("can't read or claim another organisation's key (SEC-TEN-01)", async () => {
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
  });

  it('SEC-DATA-07 matches a retry during a key rotation, checked with the version its row was made with', async () => {
    const key = newKey();
    const result = await firstWrite(requestFor(key));
    const rotated = keysWith(ROTATED);

    expect(await write(requestFor(key), { keys: rotated })).toEqual({ outcome: 'replayed', result });
    expect(await write(requestFor(key, { payload: 'changed' }), { keys: rotated })).toEqual({ outcome: 'conflict' });

    // New keys are hashed with the current version.
    const fresh = newKey();
    await firstWrite(requestFor(fresh), { keys: rotated });
    expect(await storedKeys(fresh)).toEqual([expect.objectContaining({ request_hash_key_version: 2 })]);
  });

  it("refuses a row made with a key version this process doesn't hold, rather than call it a conflict", async () => {
    const key = newKey();
    await firstWrite(requestFor(key), { keys: keysWith(ROTATED) });

    const refused = write(requestFor(key));

    await expect(refused).rejects.toBeInstanceOf(IdempotencyFailed);
    await expect(refused).rejects.toMatchObject({ reason: 'unreadable' });
    expect(linesNamed('idempotency.unreadable')).toEqual([
      expect.objectContaining({ level: 'error', problem: 'key_version_not_held', keyVersion: 2, idempotencyKey: key }),
    ]);
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
      await waitUntilQueued(admin, waiting);
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
        await waitUntilQueued(admin, 1);
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

  it('refuses a claim whose result was written by something else first', async () => {
    const key = newKey();
    const before = await items();

    await unreadable(
      write(requestFor(key), {
        work: async (tx, orgId) => {
          await sql`update idempotency.keys set result_status = 200, result_id = ${AGENT} where key = ${key}`.execute(
            tx,
          );
          return createItem(tx, orgId);
        },
      }),
    );
    expect(linesNamed('idempotency.unreadable')).toEqual([
      expect.objectContaining({ level: 'error', problem: 'claim_lost' }),
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
    expect(await write(requestFor(key))).toMatchObject({ outcome: 'replayed' });
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
      'move a key to another client',
      (key: string) => sql`update idempotency.keys set client_id = ${OTHER_AGENT} where key = ${key}`,
    ],
    ['delete a key', (key: string) => sql`delete from idempotency.keys where key = ${key}`],
  ])("doesn't let the app %s", async (_what, statement) => {
    const key = newKey();
    await firstWrite(requestFor(key));

    await expect(withTenant(app, ORG, (tx) => statement(key).execute(tx))).rejects.toMatchObject({ code: '42501' });
    expect(await storedKeys(key)).toHaveLength(1);
  });

  it.each([
    ['a result status without its resource', 201, null],
    ['a resource without its result status', null, AGENT],
    ['a result status outside 200 to 299', 404, AGENT],
  ])('refuses %s', async (_what, status, resourceId) => {
    const insert = withTenant(app, ORG, (tx) =>
      sql`insert into idempotency.keys
            (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at, result_status, result_id)
          values (${ORG}, 'agent', ${AGENT}, 'items.create', ${newKey()}, ${fill(1)}, 1, pg_catalog.now(), ${status}, ${resourceId})`.execute(
        tx,
      ),
    );

    await expect(insert).rejects.toMatchObject({ code: '23514' });
  });

  it('lets the backup role read every organisation, and nothing more', async () => {
    const key = newKey();
    await firstWrite(requestFor(key));
    await firstWrite(requestFor(key, { orgId: OTHER_ORG }));
    const backup = database.as('backup');

    expect(await backup.query('select org_id from idempotency.keys where key = $1', [key])).toHaveLength(2);
    await expect(backup.query('delete from idempotency.keys where key = $1', [key])).rejects.toMatchObject({
      code: '42501',
    });
  });
});
