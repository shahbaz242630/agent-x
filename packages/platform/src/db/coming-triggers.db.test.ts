// 4D2e D6 (PL-66): a trigger a coming migration adds to a table already built. The image
// before the migration must know it exactly, or raises a false tamper alarm when the
// migration ends; and knowing one must soften nothing for any other. Each stranger below
// is run as `agentx_owner`, as a planted trigger would be.
import { createHash } from 'node:crypto';

import { createTestDatabase, type TestDatabase, type TestSession } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { liveSchemaDrift, liveSchemaProblems, type WrittenTrigger } from './schema-guard.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;
let owner: TestSession;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const BODY = ' begin return null; end ';
const MAKE_FUNCTION = `create function audit.coming_mark() returns trigger language plpgsql
  set search_path = pg_catalog as $$${BODY}$$`;

const REQUESTS = 'spend_requests.requests';
const CREATE_EXACT = `create constraint trigger coming_mark after insert or update on ${REQUESTS}
  deferrable initially deferred for each row when (new.status = 'APPROVED')
  execute function audit.coming_mark('a_job', '0 seconds')`;
const COMING: WrittenTrigger = {
  table: REQUESTS,
  name: 'coming_mark',
  definition: `CREATE CONSTRAINT TRIGGER coming_mark AFTER INSERT OR UPDATE ON ${REQUESTS} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN ((new.status = 'APPROVED'::text)) EXECUTE FUNCTION audit.coming_mark('a_job', '0 seconds')`,
  function: 'audit.coming_mark',
  body: createHash('sha256').update(BODY).digest('hex'),
};
const EXACT_READS = `${REQUESTS} carries "coming_mark", a coming trigger`;

const drift = () => liveSchemaDrift(app, { ...ROLES, comingTriggers: [COMING] });

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

describe('a trigger a coming migration adds to a table already built', () => {
  beforeEach(async () => {
    await owner.query(MAKE_FUNCTION);
  });

  afterEach(async () => {
    await owner.query('drop function if exists audit.coming_mark() cascade');
  });

  it('is release-shaped when exact, and nothing is the alarm at once', async () => {
    await owner.query(CREATE_EXACT);
    expect(await drift()).toEqual({ atOnce: [], releaseShaped: [EXACT_READS] });
  });

  it('is what a start still refuses on', async () => {
    await owner.query(CREATE_EXACT);
    expect(await liveSchemaProblems(app, { ...ROLES, comingTriggers: [COMING] })).toEqual([EXACT_READS]);
  });

  it('its function known and no trigger yet says nothing: the image before the migration ran', async () => {
    expect(await drift()).toEqual({ atOnce: [], releaseShaped: [] });
  });

  it('to an image that does not know it, is the alarm at once: why it must land first', async () => {
    await owner.query(CREATE_EXACT);
    expect(await liveSchemaDrift(app, { ...ROLES, comingTriggers: [] })).toEqual({
      atOnce: [`${REQUESTS} carries the trigger "coming_mark"`],
      releaseShaped: ['audit.coming_mark is a function our schemas should not hold'],
    });
  });

  const CONSTRAINT = 'create constraint trigger';
  const LATER = 'deferrable initially deferred for each row';
  const CALL = "execute function audit.coming_mark('a_job', '0 seconds')";
  const WHEN = "when (new.status = 'APPROVED')";
  const UP = `after insert or update on ${REQUESTS}`;

  it.each([
    ['its name changed', 'other_mark', `${CONSTRAINT} other_mark ${UP} ${LATER} ${WHEN} ${CALL}`, REQUESTS],
    [
      'on another table',
      'coming_mark',
      `${CONSTRAINT} coming_mark after insert or update on transactions.transactions ${LATER} when (new.status = 'SUBMITTED') ${CALL}`,
      'transactions.transactions',
    ],
    [
      'another condition',
      'coming_mark',
      `${CONSTRAINT} coming_mark ${UP} ${LATER} when (new.status = 'DENIED') ${CALL}`,
      REQUESTS,
    ],
    ['no condition', 'coming_mark', `${CONSTRAINT} coming_mark ${UP} ${LATER} ${CALL}`, REQUESTS],
    [
      'not deferred',
      'coming_mark',
      `${CONSTRAINT} coming_mark ${UP} deferrable initially immediate for each row ${WHEN} ${CALL}`,
      REQUESTS,
    ],
    [
      'not a constraint trigger',
      'coming_mark',
      `create trigger coming_mark ${UP} for each row ${WHEN} ${CALL}`,
      REQUESTS,
    ],
    [
      'before the row',
      'coming_mark',
      `create trigger coming_mark before insert or update on ${REQUESTS} for each row ${WHEN} ${CALL}`,
      REQUESTS,
    ],
    [
      'on fewer events',
      'coming_mark',
      `${CONSTRAINT} coming_mark after update on ${REQUESTS} ${LATER} ${WHEN} ${CALL}`,
      REQUESTS,
    ],
    [
      'other arguments',
      'coming_mark',
      `${CONSTRAINT} coming_mark ${UP} ${LATER} ${WHEN} execute function audit.coming_mark('other_job', '0 seconds')`,
      REQUESTS,
    ],
    [
      'another function',
      'coming_mark',
      `${CONSTRAINT} coming_mark ${UP} ${LATER} ${WHEN} execute function state_rules.guard_made_once()`,
      REQUESTS,
    ],
  ])('%s is the alarm at once', async (_what, name, create, table) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(create);
    try {
      const { atOnce, releaseShaped } = await drift();
      expect(atOnce).toEqual([`${table} carries the trigger "${name}"`]);
      expect(releaseShaped).toEqual([]);
    } finally {
      // eslint-disable-next-line agentx/no-string-built-sql -- The name and table are fixed text, written above.
      await owner.query(`drop trigger ${name} on ${table}`);
    }
  });

  it.each(['disable', 'enable replica', 'enable always'])(
    'exact in every word but switched by "%s" is the alarm at once',
    async (how) => {
      await owner.query(CREATE_EXACT);
      // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, from the list above.
      await owner.query(`alter table ${REQUESTS} ${how} trigger coming_mark`);
      expect(await drift()).toEqual({ atOnce: [`${REQUESTS} carries the trigger "coming_mark"`], releaseShaped: [] });
    },
  );

  it.each([
    [
      'its body rewritten',
      `create or replace function audit.coming_mark() returns trigger language plpgsql
         set search_path = pg_catalog as $$ begin perform 1; return null; end $$`,
      'audit.coming_mark is not the function the migration wrote',
    ],
    [
      'its search path left open',
      'alter function audit.coming_mark() reset search_path',
      'audit.coming_mark does not pin its search_path',
    ],
    [
      'run with its owner rights',
      'alter function audit.coming_mark() security definer',
      "audit.coming_mark runs with its owner's rights",
    ],
  ])('the trigger exact but its function %s is the alarm at once', async (_what, tamper, problem) => {
    await owner.query(CREATE_EXACT);
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(tamper);
    const { atOnce } = await drift();
    expect(atOnce).toEqual([problem]);
  });

  it("a known table's other drift beside it is still the alarm at once", async () => {
    await owner.query(CREATE_EXACT);
    await owner.query(`alter table ${REQUESTS} no force row level security`);
    try {
      expect(await drift()).toEqual({
        atOnce: [`${REQUESTS} does not have row-level security forced`],
        releaseShaped: [EXACT_READS],
      });
    } finally {
      await owner.query(`alter table ${REQUESTS} force row level security`);
    }
  });
});

describe("the product's own list", () => {
  /** What the release's migration will run, on the tables it names, as far as the guard can see it. */
  const MIGRATION = [
    `create function directory.mark_org_work() returns trigger language plpgsql
SET search_path = pg_catalog AS $$ BEGIN
  INSERT INTO directory.org_work (org_id, job, due_at)
  VALUES (NEW.org_id, TG_ARGV[0], pg_catalog.now() + TG_ARGV[1]::interval)
  ON CONFLICT (org_id, job) DO UPDATE SET marks = org_work.marks + 1,
    due_at = LEAST(org_work.due_at, EXCLUDED.due_at);
  RETURN NULL;
END $$`,
    `create constraint trigger marks_hand_off after insert or update on spend_requests.requests
       deferrable initially deferred for each row when (new.status in ('APPROVED', 'INSTRUCTION_READY'))
       execute function directory.mark_org_work('hand_off', '0 seconds')`,
    `create constraint trigger marks_hand_off_sweep after insert or update on transactions.transactions
       deferrable initially deferred for each row when (new.status = 'SUBMISSION_PENDING')
       execute function directory.mark_org_work('hand_off_sweep', '10 minutes')`,
    `create constraint trigger marks_payment_check after insert or update on transactions.transactions
       deferrable initially deferred for each row
       when (new.status in ('SUBMISSION_PENDING', 'SUBMITTED', 'PROCESSING', 'UNKNOWN'))
       execute function directory.mark_org_work('payment_check', '0 seconds')`,
  ];

  afterEach(async () => {
    await owner.query('drop function if exists directory.mark_org_work() cascade');
  });

  it('knows the marks exactly, by default: the image that must reach a release before 0070 runs', async () => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    for (const statement of MIGRATION) await owner.query(statement);
    expect(await liveSchemaDrift(app, ROLES)).toEqual({
      atOnce: [],
      releaseShaped: [
        'spend_requests.requests carries "marks_hand_off", a coming trigger',
        'transactions.transactions carries "marks_hand_off_sweep", a coming trigger',
        'transactions.transactions carries "marks_payment_check", a coming trigger',
      ],
    });
  });
});
