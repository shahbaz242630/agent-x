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
import BUILT_CHECKS from './built-checks.json' with { type: 'json' };
import BUILT_TABLES from './built-tables.json' with { type: 'json' };
import {
  BUILT_TRIGGERS,
  liveSchemaDrift,
  liveSchemaProblems,
  MARK_TRIGGERS,
  type WrittenTrigger,
} from './schema-guard.ts';
import { SCHEMA_POLICY } from './schema-policy.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;
let owner: TestSession;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const BODY = ' begin return null; end ';
// Plain text, as the SQL rule asks: BODY written out again between the dollar quotes.
const MAKE_FUNCTION = `create function audit.coming_mark() returns trigger language plpgsql
  set search_path = pg_catalog as $$ begin return null; end $$`;

const REQUESTS = 'spend_requests.requests';
const CREATE_EXACT = `create constraint trigger coming_mark after insert or update on spend_requests.requests
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
    await owner.query('alter table spend_requests.requests no force row level security');
    try {
      expect(await drift()).toEqual({
        atOnce: [`${REQUESTS} does not have row-level security forced`],
        releaseShaped: [EXACT_READS],
      });
    } finally {
      await owner.query('alter table spend_requests.requests force row level security');
    }
  });
});

/** What `says` makes of each trigger named as `table name`, in the list's order. */
const eachNamed = (named: readonly string[], says: (table: string, name: string) => string) =>
  named.map((one) => {
    const [table = '', name = ''] = one.split(' ');
    return says(table, name);
  });

describe('0077, read as the image before it would read it (4D2e D10)', () => {
  const NAMED = ['activity_exports.files marks_background_downloads', 'identity.factor_resets marks_factor_removals'];
  const ours = ({ table, name }: WrittenTrigger) => NAMED.includes(`${table} ${name}`);
  const each = (says: (table: string, name: string) => string) => eachNamed(NAMED, says);
  // The image before knew every trigger before 0077's as written, these two as coming, and the job CHECK as 0075 made it.
  const before = {
    triggers: BUILT_TRIGGERS.filter((one) => !ours(one)),
    tables: BUILT_TABLES,
    checks: BUILT_CHECKS.map((one) =>
      one.name === 'org_work_job_check'
        ? {
            ...one,
            expression:
              "(job = ANY (ARRAY['hand_off'::text, 'hand_off_sweep'::text, 'payment_check'::text, 'request_expiry'::text, 'mandate_expiry'::text, 'request_voids'::text, 'waiting_rejections'::text, 'carry_rest'::text]))",
          }
        : one,
    ),
  };
  const coming = MARK_TRIGGERS.filter(ours);

  it('knowing its triggers as coming: nothing is the alarm at once, and all of it warns first', async () => {
    expect(coming.map(({ table, name }) => `${table} ${name}`).toSorted()).toEqual(NAMED);
    expect(await liveSchemaDrift(app, { ...ROLES, built: before, comingTriggers: coming })).toEqual({
      atOnce: [],
      releaseShaped: [
        `directory.org_work's CHECK constraint "org_work_job_check" reads differently`,
        ...each((table, name) => `${table} carries "${name}", a coming trigger`),
      ].toSorted(),
    });
  });

  it('not knowing them: the false alarm D10a landed first to prevent, on those two alone', async () => {
    const { atOnce } = await liveSchemaDrift(app, { ...ROLES, built: before, comingTriggers: [] });
    expect(atOnce).toEqual(each((table, name) => `${table} carries the trigger "${name}"`));
  });

  const PUT_BACK = `drop trigger if exists marks_factor_removals on identity.factor_resets;
    create constraint trigger marks_factor_removals after update on identity.factor_resets
      deferrable initially deferred for each row when (new.status = 'COOLING_OFF')
      execute function directory.mark_org_work('factor_removals', '24 hours');
    drop trigger if exists marks_background_downloads on activity_exports.files;
    create constraint trigger marks_background_downloads after insert on activity_exports.files
      deferrable initially deferred for each row
      execute function directory.mark_org_work('background_downloads', '0 seconds')`;

  it.each([
    [
      'the removals firing on an insert too',
      `drop trigger marks_factor_removals on identity.factor_resets;
       create constraint trigger marks_factor_removals after insert or update on identity.factor_resets
        deferrable initially deferred for each row when (new.status = 'COOLING_OFF')
        execute function directory.mark_org_work('factor_removals', '24 hours')`,
      "identity.factor_resets's marks_factor_removals is not the trigger its migration wrote",
    ],
    [
      'the removals marked later than the cooling-off',
      `drop trigger marks_factor_removals on identity.factor_resets;
       create constraint trigger marks_factor_removals after update on identity.factor_resets
        deferrable initially deferred for each row when (new.status = 'COOLING_OFF')
        execute function directory.mark_org_work('factor_removals', '48 hours')`,
      "identity.factor_resets's marks_factor_removals is not the trigger its migration wrote",
    ],
    [
      'the downloads firing on a condition',
      `drop trigger marks_background_downloads on activity_exports.files;
       create constraint trigger marks_background_downloads after insert on activity_exports.files
        deferrable initially deferred for each row when (new.state = 'building')
        execute function directory.mark_org_work('background_downloads', '0 seconds')`,
      "activity_exports.files's marks_background_downloads is not the trigger its migration wrote",
    ],
  ])('once its image is in, one written otherwise, %s, is the alarm at once', async (_what, made, problem) => {
    expect(await liveSchemaDrift(app, ROLES)).toEqual({ atOnce: [], releaseShaped: [] });
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(made);
    try {
      expect(await liveSchemaDrift(app, ROLES)).toEqual({ atOnce: [problem], releaseShaped: [] });
    } finally {
      await owner.query(PUT_BACK);
    }
    expect(await liveSchemaDrift(app, ROLES)).toEqual({ atOnce: [], releaseShaped: [] });
  });
});

describe('0075, read as the image before it would read it (4D2e D9)', () => {
  /** Each trigger 0075 makes, as `table name`. */
  const NAMED = [
    'agents.agents marks_request_voids',
    'funding_sources.sources marks_request_voids',
    'mandates.mandates marks_carry_rest',
    'mandates.mandates marks_request_voids',
    'mandates.policies marks_waiting_rejections',
    'organizations.organizations marks_request_voids',
    'suppliers.suppliers marks_request_voids',
  ];
  const ours = ({ table, name }: WrittenTrigger) => NAMED.includes(`${table} ${name}`);
  const each = (says: (table: string, name: string) => string) => eachNamed(NAMED, says);
  // The image before knew 0072's and 0073's triggers as written, these seven as coming, and the job CHECK as 0073 made it.
  const before = {
    triggers: BUILT_TRIGGERS.filter((one) => !ours(one)),
    tables: BUILT_TABLES,
    checks: BUILT_CHECKS.map((one) =>
      one.name === 'org_work_job_check'
        ? {
            ...one,
            expression:
              "(job = ANY (ARRAY['hand_off'::text, 'hand_off_sweep'::text, 'payment_check'::text, 'request_expiry'::text, 'mandate_expiry'::text]))",
          }
        : one,
    ),
  };
  const coming = MARK_TRIGGERS.filter(ours);

  it('knowing its triggers as coming: nothing is the alarm at once, and all of it warns first', async () => {
    expect(coming.map(({ table, name }) => `${table} ${name}`).toSorted()).toEqual(NAMED);
    expect(await liveSchemaDrift(app, { ...ROLES, built: before, comingTriggers: coming })).toEqual({
      atOnce: [],
      releaseShaped: [
        `directory.org_work's CHECK constraint "org_work_job_check" reads differently`,
        ...each((table, name) => `${table} carries "${name}", a coming trigger`),
      ].toSorted(),
    });
  });

  it('not knowing them: the false alarm D9a landed first to prevent, on those seven alone', async () => {
    const { atOnce } = await liveSchemaDrift(app, { ...ROLES, built: before, comingTriggers: [] });
    expect(atOnce).toEqual(each((table, name) => `${table} carries the trigger "${name}"`));
  });

  it('once its image is in, each held as written: one firing on more or on less is the alarm at once', async () => {
    expect(await liveSchemaDrift(app, ROLES)).toEqual({ atOnce: [], releaseShaped: [] });
    await owner.query(`drop trigger marks_carry_rest on mandates.mandates;
      create constraint trigger marks_carry_rest after update on mandates.mandates
        deferrable initially deferred for each row
        when (new.current_version_id is distinct from old.current_version_id or new.status <> 'ACTIVE')
        execute function directory.mark_org_work('carry_rest', '0 seconds');
      drop trigger marks_request_voids on funding_sources.sources;
      create constraint trigger marks_request_voids after insert or update on funding_sources.sources
        deferrable initially deferred for each row
        execute function directory.mark_org_work('request_voids', '0 seconds')`);
    try {
      expect((await liveSchemaDrift(app, ROLES)).atOnce).toEqual([
        "funding_sources.sources's marks_request_voids is not the trigger its migration wrote",
        "mandates.mandates's marks_carry_rest is not the trigger its migration wrote",
      ]);
    } finally {
      await owner.query(`drop trigger marks_carry_rest on mandates.mandates;
        create constraint trigger marks_carry_rest after update on mandates.mandates
          deferrable initially deferred for each row
          when (new.current_version_id is distinct from old.current_version_id)
          execute function directory.mark_org_work('carry_rest', '0 seconds');
        drop trigger marks_request_voids on funding_sources.sources;
        create constraint trigger marks_request_voids after update on funding_sources.sources
          deferrable initially deferred for each row
          execute function directory.mark_org_work('request_voids', '0 seconds')`);
    }
    expect(await liveSchemaDrift(app, ROLES)).toEqual({ atOnce: [], releaseShaped: [] });
  });
});

describe('0073, read as the image before it would read it (4D2e D8)', () => {
  const EXPIRY = ['marks_request_expiry', 'marks_mandate_expiry'];
  // The image before knew 0072's three triggers as written, these two as coming, and the job CHECK as 0072 made it.
  const before = {
    triggers: BUILT_TRIGGERS.filter(({ name }) => !EXPIRY.includes(name)),
    tables: BUILT_TABLES,
    checks: BUILT_CHECKS.map((one) =>
      one.name === 'org_work_job_check'
        ? { ...one, expression: "(job = ANY (ARRAY['hand_off'::text, 'hand_off_sweep'::text, 'payment_check'::text]))" }
        : one,
    ),
  };
  const coming = MARK_TRIGGERS.filter(({ name }) => EXPIRY.includes(name));

  it('knowing its triggers as coming: nothing is the alarm at once, and all of it warns first', async () => {
    expect(coming.map(({ name }) => name)).toEqual(EXPIRY);
    expect(await liveSchemaDrift(app, { ...ROLES, built: before, comingTriggers: coming })).toEqual({
      atOnce: [],
      releaseShaped: [
        `directory.org_work's CHECK constraint "org_work_job_check" reads differently`,
        'mandates.mandates carries "marks_mandate_expiry", a coming trigger',
        'spend_requests.requests carries "marks_request_expiry", a coming trigger',
      ],
    });
  });

  it('not knowing them: the false alarm D8a landed first to prevent, on those two alone', async () => {
    const { atOnce } = await liveSchemaDrift(app, { ...ROLES, built: before, comingTriggers: [] });
    expect(atOnce).toEqual([
      'mandates.mandates carries the trigger "marks_mandate_expiry"',
      'spend_requests.requests carries the trigger "marks_request_expiry"',
    ]);
  });
});

describe('0072, read as the image before it would read it', () => {
  const OURS = 'directory.org_work';
  const { [OURS]: _ours, ...tablesBefore } = SCHEMA_POLICY.globalTables;
  const knowingNothing = {
    triggers: [],
    tables: BUILT_TABLES.filter((name) => name !== OURS),
    checks: BUILT_CHECKS.filter((one) => one.table !== OURS),
  };
  const imageBefore = { ...ROLES, policy: { ...SCHEMA_POLICY, globalTables: tablesBefore }, built: knowingNothing };
  const SHAPE = [
    `directory.org_work does not have row-level security enabled`,
    `directory.org_work does not have row-level security forced`,
    `directory.org_work does not have exactly one row-security policy`,
  ];

  it('knowing the marks: nothing at all is the alarm at once, and all of it warns first', async () => {
    const { atOnce, releaseShaped } = await liveSchemaDrift(app, { ...imageBefore, comingTriggers: BUILT_TRIGGERS });
    expect(atOnce).toEqual([]);
    expect(releaseShaped).toEqual(
      expect.arrayContaining([
        'spend_requests.requests carries "marks_hand_off", a coming trigger',
        'transactions.transactions carries "marks_hand_off_sweep", a coming trigger',
        'transactions.transactions carries "marks_payment_check", a coming trigger',
        ...SHAPE,
        `directory.org_work's CHECK constraint "org_work_job_check" is not one the migrations built`,
      ]),
    );
  });

  it('not knowing them: the false alarm this all exists to prevent, on the triggers alone', async () => {
    const { atOnce, releaseShaped } = await liveSchemaDrift(app, { ...imageBefore, comingTriggers: [] });
    // The migrated database holds 0073's, 0075's, 0077's and 0080's as well, which that image knew no more of.
    expect(atOnce).toEqual(
      BUILT_TRIGGERS.map(({ table, name }) => `${table} carries the trigger "${name}"`).toSorted(),
    );
    expect(releaseShaped).toContain('directory.mark_org_work is a function our schemas should not hold');
  });
});

describe('0072 once its image is in: each part held at once', () => {
  const clean = () => liveSchemaDrift(app, ROLES);
  const WHEN = "when (new.status = 'APPROVED')";
  const CALL = "execute function directory.mark_org_work('hand_off', '0 seconds')";
  const LATER = 'deferrable initially deferred for each row';
  const ON = 'after insert or update on spend_requests.requests';
  const PUT_BACK = `drop trigger if exists marks_hand_off on spend_requests.requests;
    create constraint trigger marks_hand_off ${ON} ${LATER}
    when (new.status in ('APPROVED', 'INSTRUCTION_READY')) ${CALL}`;

  it('reads clean, with its function and triggers as written', async () => {
    expect(await clean()).toEqual({ atOnce: [], releaseShaped: [] });
  });

  it.each([
    [
      'its trigger dropped',
      'drop trigger marks_hand_off on spend_requests.requests',
      PUT_BACK,
      'spend_requests.requests carries no marks_hand_off',
    ],
    [
      'its trigger rewritten with a narrower condition',
      `drop trigger marks_hand_off on spend_requests.requests;
       create constraint trigger marks_hand_off ${ON} ${LATER} ${WHEN} ${CALL}`,
      PUT_BACK,
      "spend_requests.requests's marks_hand_off is not the trigger its migration wrote",
    ],
    [
      'its trigger pointed at another job',
      `drop trigger marks_hand_off on spend_requests.requests;
       create constraint trigger marks_hand_off ${ON} ${LATER} when (new.status in ('APPROVED', 'INSTRUCTION_READY'))
       execute function directory.mark_org_work('payment_check', '0 seconds')`,
      PUT_BACK,
      "spend_requests.requests's marks_hand_off is not the trigger its migration wrote",
    ],
    [
      'its trigger no longer deferred',
      `drop trigger marks_hand_off on spend_requests.requests;
       create constraint trigger marks_hand_off ${ON} deferrable initially immediate for each row
       when (new.status in ('APPROVED', 'INSTRUCTION_READY')) ${CALL}`,
      PUT_BACK,
      "spend_requests.requests's marks_hand_off is not the trigger its migration wrote",
    ],
    [
      'its trigger switched off',
      'alter table spend_requests.requests disable trigger marks_hand_off',
      'alter table spend_requests.requests enable trigger marks_hand_off',
      "spend_requests.requests's marks_hand_off is switched off",
    ],
    [
      'a trigger of its name on another table',
      `create constraint trigger marks_hand_off after insert or update on transactions.transactions ${LATER} ${CALL}`,
      'drop trigger marks_hand_off on transactions.transactions',
      'transactions.transactions carries the trigger "marks_hand_off"',
    ],
    [
      'a stranger calling its function',
      `create constraint trigger planted ${ON} ${LATER} ${CALL}`,
      'drop trigger planted on spend_requests.requests',
      'spend_requests.requests carries the trigger "planted"',
    ],
    [
      'the whole table granted for update',
      'grant update on directory.org_work to agentx_app',
      'revoke update on directory.org_work from agentx_app; grant update (due_at, marks) on directory.org_work to agentx_app',
      'agentx_app may UPDATE on directory.org_work',
    ],
    [
      'a column granted past its list',
      'grant update (job) on directory.org_work to agentx_app',
      'revoke update (job) on directory.org_work from agentx_app',
      `agentx_app may UPDATE directory.org_work's column "job"`,
    ],
    [
      'its rights widened to emptying it',
      'grant truncate on directory.org_work to agentx_app',
      'revoke truncate on directory.org_work from agentx_app',
      'agentx_app may TRUNCATE on directory.org_work',
    ],
    [
      'a column added',
      'alter table directory.org_work add column note text',
      'alter table directory.org_work drop column note',
      'directory.org_work no longer has exactly its columns',
    ],
  ])('%s is the alarm at once', async (_what, tamper, undo, problem) => {
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await owner.query(tamper);
    try {
      const { atOnce, releaseShaped } = await clean();
      expect(atOnce).toContain(problem);
      expect(releaseShaped).toEqual([]);
    } finally {
      // eslint-disable-next-line agentx/no-string-built-sql -- As above.
      await owner.query(undo);
    }
  });

  it('its function rewritten is the alarm at once, and put back reads clean', async () => {
    const [{ source } = { source: '' }] = await owner.query<{ source: string }>(
      `select p.prosrc as source from pg_catalog.pg_proc p where p.proname = 'mark_org_work'`,
    );
    const replacing = (body: string) => `create or replace function directory.mark_org_work() returns trigger
      language plpgsql set search_path = pg_catalog as $mark$${body}$mark$`;
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text and the body the migration wrote.
    await owner.query(replacing(' BEGIN RETURN NULL; END '));
    try {
      const { atOnce } = await clean();
      expect(atOnce).toEqual(['directory.mark_org_work is not the function the migration wrote']);
    } finally {
      // eslint-disable-next-line agentx/no-string-built-sql -- As above.
      await owner.query(replacing(source));
    }
    expect(await clean()).toEqual({ atOnce: [], releaseShaped: [] });
  });
});
