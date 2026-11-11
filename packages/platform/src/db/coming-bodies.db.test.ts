// Decision 49 (PL-66): a body a coming migration writes over a guard function already
// built. The image before the migration must know it exactly, or raises a false tamper
// alarm when the migration ends; and knowing one must soften nothing else: any other body,
// or the coming one run with its owner's rights, stays the alarm at once. Each rewrite
// below is run as `agentx_owner`, as a planted one would be.
import { createHash } from 'node:crypto';

import { createTestDatabase, type TestDatabase, type TestSession } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, afterEach, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { type ComingBody, liveSchemaDrift, liveSchemaProblems } from './schema-guard.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;
let owner: TestSession;
let original = '';

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;
const GUARD = 'limit_reservations.guard_period';

/** A guard_period that refuses as 0040's does, written with another word, as a release changing it would. */
const NEXT = `
BEGIN
  RAISE EXCEPTION 'an agent''s period is locked, and never changed'
    USING ERRCODE = 'check_violation', CONSTRAINT = 'period_lock_only';
END;
`;
const OTHER = `
BEGIN
  RETURN NEW;
END;
`;
/** The function rewritten with that body, as a migration would; NEXT and OTHER are fixed text. */
const replacedWith = (body: string) => `CREATE OR REPLACE FUNCTION ${GUARD}() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$${body}$$`;
const hashOf = (body: string) => createHash('sha256').update(body).digest('hex');
const COMING: ComingBody = { function: GUARD, body: hashOf(NEXT) };
const COMING_READS = `${GUARD} holds the body a coming migration writes`;
const REWRITTEN = `${GUARD} is not the function the migration wrote`;

const drift = (comingBodies: readonly ComingBody[] = [COMING]) => liveSchemaDrift(app, { ...ROLES, comingBodies });

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
  // The function as 0040 wrote it, so each test puts it back whole.
  const [row] = await owner.query<{ definition: string }>(
    "select pg_catalog.pg_get_functiondef('limit_reservations.guard_period()'::regprocedure) as definition",
  );
  original = row?.definition ?? '';
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe('a body a coming migration writes over a guard already built', () => {
  afterEach(async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Postgres's own text of 0040's function, read above.
    await owner.query(original);
    await owner.query('alter function limit_reservations.guard_period() security invoker');
  });

  it('known as coming and not yet written says nothing: the image before the migration ran', async () => {
    expect(original).toContain('CREATE OR REPLACE FUNCTION limit_reservations.guard_period()');
    expect(await drift()).toEqual({ atOnce: [], releaseShaped: [] });
  });

  it('is release-shaped when exact, and nothing is the alarm at once', async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(replacedWith(NEXT));
    expect(await drift()).toEqual({ atOnce: [], releaseShaped: [COMING_READS] });
  });

  it('is what a start still refuses on', async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(replacedWith(NEXT));
    expect(await liveSchemaProblems(app, { ...ROLES, comingBodies: [COMING] })).toEqual([COMING_READS]);
  });

  it('to an image that does not know it, is the alarm at once: why it must land first', async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(replacedWith(NEXT));
    expect(await drift([])).toEqual({ atOnce: [REWRITTEN], releaseShaped: [] });
  });

  it.each([
    ['any other body', OTHER],
    ['the coming body with one space more', `${NEXT} `],
  ])('%s, beside a coming one, is the alarm at once', async (_what, body) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(replacedWith(body));
    expect(await drift()).toEqual({ atOnce: [REWRITTEN], releaseShaped: [] });
  });

  it('the coming body for another function softens nothing for this one', async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(replacedWith(NEXT));
    const elsewhere = { function: 'limit_reservations.guard_reservation', body: COMING.body };
    expect(await drift([elsewhere])).toEqual({ atOnce: [REWRITTEN], releaseShaped: [] });
  });

  it("the coming body run with its owner's rights is the alarm at once", async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(replacedWith(NEXT));
    await owner.query('alter function limit_reservations.guard_period() security definer');
    expect(await drift()).toEqual({
      atOnce: [`${GUARD} runs with its owner's rights`],
      releaseShaped: [COMING_READS],
    });
  });

  it('a coming trigger calling a known function with another body leaves the body held now as it was', async () => {
    const trigger = {
      table: 'limit_reservations.agent_periods',
      name: 'a_coming_one',
      definition: `CREATE TRIGGER a_coming_one BEFORE UPDATE ON limit_reservations.agent_periods FOR EACH ROW EXECUTE FUNCTION ${GUARD}()`,
      function: GUARD,
      body: COMING.body,
    };
    const both = { ...ROLES, comingBodies: [], comingTriggers: [trigger] };
    expect(await liveSchemaDrift(app, both)).toEqual({ atOnce: [], releaseShaped: [] });
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(replacedWith(NEXT));
    expect(await liveSchemaDrift(app, both)).toEqual({ atOnce: [], releaseShaped: [COMING_READS] });
  });
});
