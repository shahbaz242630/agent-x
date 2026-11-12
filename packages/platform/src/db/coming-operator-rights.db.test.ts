// OR2b (decision 49): a right a coming migration grants the operator's role on a table
// already built. The role holds exactly its list, so the image before the migration must
// know the right exactly, or raises a false tamper alarm when the migration ends; and
// knowing one must soften nothing else: a wider right, another column, or the coming one
// handed on, stays the alarm at once. Each grant below is made as `agentx_owner`, as a
// widened right would be.
import { createTestDatabase, type TestDatabase, type TestSession } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import COMING from './coming.json' with { type: 'json' };
import { createDatabase } from './database.ts';
import { liveSchemaDrift, liveSchemaProblems } from './schema-guard.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;
let owner: TestSession;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;
const MEMBERSHIPS = 'identity.memberships';
const ID = `SELECT on column ${MEMBERSHIPS}.id`;
const STATUS = `SELECT on column ${MEMBERSHIPS}.status`;
const may = (right: string) => `agentx_operator may ${right}`;

/** The GRANT that gives a right as the guard prints it: on a table, or on one column of it (`a.b.c`). */
function grantOf(right: string): string {
  const on = right.indexOf(' on ');
  const [privilege, object] = [right.slice(0, on), right.slice(on + ' on '.length)];
  if (!object.startsWith('column ')) return `grant ${privilege} on ${object} to agentx_operator`;
  const parts = object.slice('column '.length).split('.');
  return `grant ${privilege} (${parts[2] ?? ''}) on ${parts.slice(0, 2).join('.')} to agentx_operator`;
}

const drift = (comingOperatorRights: readonly string[] = [ID]) =>
  liveSchemaDrift(app, { ...ROLES, comingOperatorRights });

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  owner = database.as('owner');
  app = createDatabase(
    { ...database.connection('app'), tls: 'disable' },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'error', eventCapPerMinute: 1000 } },
      destination: { write: () => undefined },
    }),
  );
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

const GRANT_ID = 'grant select (id) on identity.memberships to agentx_operator';

describe("a right a coming migration grants the operator's role on a table already built", () => {
  afterEach(async () => {
    await owner.query('revoke all on identity.memberships from agentx_operator');
    await owner.query('revoke all (id, status) on identity.memberships from agentx_operator');
  });

  it('known as coming and not yet granted says nothing: the image before the migration ran', async () => {
    expect(await drift()).toEqual({ atOnce: [], releaseShaped: [] });
  });

  it('is release-shaped once granted exactly, and nothing is the alarm at once', async () => {
    await owner.query(GRANT_ID);
    expect(await drift()).toEqual({ atOnce: [], releaseShaped: [may(ID)] });
  });

  it('is what a start still refuses on', async () => {
    await owner.query(GRANT_ID);
    expect(await liveSchemaProblems(app, { ...ROLES, comingOperatorRights: [ID] })).toEqual([may(ID)]);
  });

  it('to an image that does not know it, is the alarm at once: why it must land first', async () => {
    await owner.query(GRANT_ID);
    expect(await drift([])).toEqual({ atOnce: [may(ID)], releaseShaped: [] });
  });

  it('softens no other right: another column, or the whole table, is the alarm at once', async () => {
    await owner.query('grant select (id, status) on identity.memberships to agentx_operator');
    expect(await drift()).toEqual({ atOnce: [may(STATUS)], releaseShaped: [may(ID)] });
    await owner.query('grant select on identity.memberships to agentx_operator');
    expect((await drift()).atOnce).toEqual([may(STATUS), may(`SELECT on ${MEMBERSHIPS}`)]);
  });

  it('handed on (WITH GRANT OPTION), is the alarm at once, both the right and the handing on', async () => {
    await owner.query('grant select (id) on identity.memberships to agentx_operator with grant option');
    expect(await drift()).toEqual({ atOnce: [may(ID), `agentx_operator may grant ${ID}`], releaseShaped: [] });
  });

  // Nothing to prove while the list is empty: between a release's migration and the next coming right.
  it.skipIf(COMING.operatorRights.length === 0)(
    "the product's own list: each right in the guard's own wording, release-shaped once granted",
    async () => {
      const granted = COMING.operatorRights.map(grantOf);
      for (const statement of granted) {
        // eslint-disable-next-line agentx/no-string-built-sql -- coming.json's own entries, each held to the guard's plain names by migration-order's parseComing
        await owner.query(statement);
      }
      const found = await liveSchemaDrift(app, ROLES);
      for (const statement of granted) {
        // eslint-disable-next-line agentx/no-string-built-sql -- the same fixed entries, taken back
        await owner.query(statement.replace(/^grant (.*) to /, 'revoke $1 from '));
      }
      expect(found.atOnce).toEqual([]);
      expect(found.releaseShaped).toEqual(COMING.operatorRights.map(may).toSorted());
    },
  );
});
