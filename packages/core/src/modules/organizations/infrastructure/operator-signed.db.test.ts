// The operator's events on an organisation's chain, believed only signed with
// its own key (PL-57), as on the platform chain: its creation of the
// organisation (ACTIVE, the hold CLEAR) and any later act of its. The API holds
// the chains' MAC and only the public half of the operator's key, so a foothold
// in it can seal an event naming the operator but never sign one: every read
// that believes an organisation's state (the freeze read a decision and an
// unfreeze rest on, the integrity hold) and the chain's own check refuse an
// operator's event unsigned, signed by another key, or carrying a signature
// moved from another event or organisation. One recorded before 0079 ran on
// its chain needs none.
import { createPrivateKey, createPublicKey } from 'node:crypto';

import { createDatabase, type Database, withTenant } from '@agentx/platform/db';
import { API_PURPOSES, createKeyProvider, KeyError, type KeyProvider, PURPOSES } from '@agentx/platform/keys';
import {
  createTestDatabase,
  LogCapture,
  SequentialIds,
  type TestDatabase,
  testLogger,
  type TestSession,
} from '@agentx/testing';
import { sql } from 'kysely';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, createAuditTrail, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { createOrganization, ORGANIZATIONS } from './organizations.ts';
import type { OrganizationsTables } from './tables.ts';

type Tables = OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
/** The API's role. */
let app: Database<Tables>;
/** The operator's command's own role, the only one that may add a signature. */
let operator: Database<Tables>;
/** The FX-TAMPER attacker: the server's superuser, past every wall, holding none of the app's keys. */
let attacker: TestSession;

/** Stand-in keys, one per purpose: the operator's command holds these. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);

/** An Ed25519 seed's public half, as the API is given it. */
function publicHalf(seed: Buffer): Buffer {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const key = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: 'der', type: 'pkcs8' });
  return Buffer.from(String(createPublicKey(key).export({ format: 'jwk' }).x), 'base64url');
}

/** The API's keys: every one but the operator's, whose public half alone it checks with. */
const apiKeys = createKeyProvider(
  Object.fromEntries(
    API_PURPOSES.map((purpose) => [
      purpose,
      { current: 1, versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + 1)]]) },
    ]),
  ),
  API_PURPOSES,
  { 'operator-signing': new Map([[1, publicHalf(Buffer.alloc(32, PURPOSES.indexOf('operator-signing') + 1))]]) },
);

/** A forger's own Ed25519 key, in place of the operator's. */
const forgersOwn = createKeyProvider(
  { 'operator-signing': { current: 1, versions: new Map([[1, Buffer.alloc(32, 0xf0)]]) } },
  ['operator-signing'],
);

/** A forger's keys: the chains' MAC as the API holds it, checking as the API does, signing with its own key. */
const forgerKeys: KeyProvider = {
  ...apiKeys,
  sign: (purpose, message) => (purpose === 'operator-signing' ? forgersOwn : apiKeys).sign(purpose, message),
};

/**
 * A foothold in the API: its own code, which records an event naming the
 * operator with the chains' MAC as the API holds it and simply adds no
 * signature (operatorSignature finds none to add).
 */
const footholdKeys: KeyProvider = {
  ...apiKeys,
  sign: (purpose, message) => (purpose === 'operator-signing' ? (undefined as never) : apiKeys.sign(purpose, message)),
};

const OPERATOR = { type: 'system', id: 'operator' } as const;
const ids = new SequentialIds(0x700);

let number = 0;
/** A new UUID, so no two tests share an organisation. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x7000 + number).toString(16).padStart(12, '0')}`;
};

let capture: LogCapture;
let org: string;

/** The organisation created as the operator's command creates one: its role, its keys, its name as the actor. */
const created = (id = org): Promise<unknown> =>
  withSignedStates(operator, id, { keys, ids, logger: testLogger() }, (tx, states) =>
    createOrganization(tx, states, { id, name: 'Acme Trading LLC', actor: OPERATOR }),
  );

/** The organisation frozen in the operator's name, by `db`'s role with `withKeys`. */
const frozenBy = (db: Database<Tables>, withKeys: KeyProvider): Promise<unknown> =>
  withSignedStates(db, org, { keys: withKeys, ids, logger: testLogger() }, (tx, states) =>
    states.changeStatus(tx, ORGANIZATIONS, { orgId: org, id: org }, 'freeze', {
      actor: OPERATOR,
      action: 'organization.freeze',
      details: {},
    }),
  );

/** The organisation's state as the API reads it for a decision (`share`) or an unfreeze (`change`). */
const readByApi = (lock: 'share' | 'change' = 'share') =>
  withSignedStates(app, org, { keys: apiKeys, ids, logger: testLogger(capture) }, (tx, states) =>
    states.verifiedState(tx, ORGANIZATIONS, { orgId: org, id: org }, lock),
  );

/** The organisation's status, as the API's read for a decision believes it, or how that read ended. */
const statusByApi = async (): Promise<unknown> => {
  const read = await readByApi();
  return read.outcome === 'verified' ? read.fields.get('status') : read;
};

/** The integrity hold as the API reads it. */
const holdByApi = () =>
  withSignedStates(app, org, { keys: apiKeys, ids, logger: testLogger(capture) }, (tx, states) =>
    states.integrityHold(tx, org, 'none'),
  );

/** The organisation's chain checked whole, as the API checks it. */
const checkedByApi = (id = org) =>
  withTenant(app, id, (tx) => createAuditTrail({ keys: apiKeys, ids }).verify(tx, id, undefined));

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

/** Runs a statement as the attacker. */
const tamper = async (statement: string, values: readonly unknown[] = [org]): Promise<void> => {
  // eslint-disable-next-line agentx/no-string-built-sql -- The statements are fixed text, written in the tests below.
  await attacker.query(statement, [...values]);
};

const eventCount = async (): Promise<number> =>
  (await attacker.query('select 1 from audit.events where org_id = $1', [org])).length;

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 6 }, testLogger());
  operator = createDatabase<Tables>({ ...database.connection('operator'), maxConnections: 4 }, testLogger());
  attacker = database.as('admin');
});

afterAll(async () => {
  await app.destroy();
  await operator.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
  org = newId();
});

describe(`the operator's events on an organisation's chain, believed only signed with its own key (PL-57, Postgres ${server.version})`, () => {
  it('signs each as the operator records it, and the API believes them with the public half alone', async () => {
    await created();
    await frozenBy(operator, keys);

    expect(
      await attacker.query('select seq::text, key_version from audit.operator_signatures where org_id = $1', [org]),
    ).toEqual([
      { seq: '1', key_version: 1 },
      { seq: '2', key_version: 1 },
      { seq: '3', key_version: 1 },
    ]);
    expect(await statusByApi()).toBe('FROZEN');
    expect(await holdByApi()).toMatchObject({ outcome: 'clear' });
    expect(await checkedByApi()).toMatchObject({ ok: true, seq: 3n });
    expect(alarms()).toEqual([]);
  });

  it("refuses the API an operator's event: with its own keys it can't sign one, nor its role add one signed", async () => {
    await created();

    await expect(frozenBy(app, apiKeys)).rejects.toThrow(KeyError);
    // Every key, the operator's too, still leaves the API's role unable to add the signature: nothing is written.
    await expect(frozenBy(app, keys)).rejects.toMatchObject({ code: '42501' });
    expect(await eventCount()).toBe(2);
    expect(await statusByApi()).toBe('ACTIVE');
  });

  it("refuses a freeze in the operator's name from the API's role as it is written (0080): nothing recorded", async () => {
    await created();
    const before = await eventCount();
    await expect(frozenBy(app, footholdKeys)).rejects.toMatchObject({ code: '42501' });

    expect(await eventCount()).toBe(before);
    expect(await statusByApi()).toBe('ACTIVE');
    expect(await checkedByApi()).toMatchObject({ ok: true });
    expect(alarms()).toEqual([]);
  });

  it("refuses a freeze in the operator's name the API's role recorded unsigned past 0080's rule, with the alarm", async () => {
    await created();
    // The rule switched off, as someone past the app could: the readers' own check behind it is what's tested.
    await tamper('alter table audit.events disable trigger operator_events_by_operator', []);
    try {
      await frozenBy(app, footholdKeys);
    } finally {
      await tamper('alter table audit.events enable trigger operator_events_by_operator', []);
    }

    expect(await readByApi()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(await readByApi('change')).toMatchObject({ outcome: 'tampered' });
    expect(alarms()).toEqual([
      expect.objectContaining({ level: 'error', orgId: org, subjectType: 'organization', reason: 'log' }),
      expect.objectContaining({ level: 'error', orgId: org, subjectType: 'organization' }),
    ]);
    expect(await checkedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 3n } });
  });

  it("refuses a freeze signed with another key than the operator's", async () => {
    await created();
    await frozenBy(operator, forgerKeys);

    expect(await readByApi()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(await checkedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 3n } });
  });

  it("refuses the hold's CLEAR when its signature is gone: the hold, too, is believed only signed", async () => {
    await created();
    await tamper('delete from audit.operator_signatures where org_id = $1 and seq = 2');

    expect(await holdByApi()).toMatchObject({ outcome: 'tampered' });
    expect(await checkedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 2n } });
  });

  it('believes an unsigned operator freeze recorded before 0079 started signing on its chain, and names one at the start', async () => {
    await created();
    await frozenBy(operator, keys);
    // As if 0079 ran with this chain at 3: all three recorded before PL-57, unsigned.
    await tamper('delete from audit.operator_signatures where org_id = $1');
    await tamper('insert into audit.operator_signing_starts (org_id, signed_from) values ($1, 4)');

    expect(await statusByApi()).toBe('FROZEN');
    expect(await checkedByApi()).toMatchObject({ ok: true, seq: 3n });

    // Had 0079 run at 2, the freeze at 3 is past it, and unsigned.
    await tamper('update audit.operator_signing_starts set signed_from = 3 where org_id = $1');
    expect(await readByApi()).toEqual({ outcome: 'tampered', sign: 'log' });
    expect(await checkedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 3n } });
  });

  it("refuses a signature moved from another organisation's event at the same place", async () => {
    const other = newId();
    await created(other);
    await created();
    // This organisation's first event given the other's signature on its own first.
    await tamper(
      `update audit.operator_signatures set signature = (
         select s.signature from audit.operator_signatures s where s.org_id = $2 and s.seq = 1
       ) where org_id = $1 and seq = 1`,
      [org, other],
    );

    expect(await checkedByApi(other)).toMatchObject({ ok: true });
    expect(await readByApi()).toMatchObject({ outcome: 'tampered' });
    expect(await checkedByApi()).toEqual({ ok: false, problem: { reason: 'mac', seq: 1n } });
  });

  it("refuses the API's role a signature or a start of its own: only the operator's role adds one, and none a start", async () => {
    await created();
    const signature = sql`insert into audit.operator_signatures (org_id, seq, signature, key_version)
      values (${org}, 9, ${Buffer.alloc(64)}, 1)`;
    const start = sql`insert into audit.operator_signing_starts (org_id, signed_from) values (${org}, 99)`;
    for (const [db, statement] of [
      [app, signature],
      [app, start],
      [operator, start],
    ] as const) {
      await expect(withTenant(db, org, (tx) => statement.execute(tx))).rejects.toMatchObject({ code: '42501' });
    }
  });
});
