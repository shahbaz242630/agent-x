// Decision 49 (PL-66): a migration whose trigger on a table already built, or whose new
// body for a function already written, the code before it didn't carry as coming is
// refused, so the image running while it migrates never raises a false tamper alarm.
// The rule is written out at the top of tooling/migration-order.ts.
//
// "The code before it" is read from git: for a migration not on main yet, where this
// branch meets origin/main; for one on main, the main commit before the one that
// brought it. Only a migration that changes something is looked up, so today, with
// every such one grandfathered, no history is read; once one is, CI's checkout must
// hold main's history (ci.yml: fetch-depth 0), and without it this fails, never passes.
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  type Coming,
  COMING_FILE,
  GRANDFATHERED,
  leftBehind,
  type Migration,
  MIGRATION_NAME,
  MIGRATIONS_FOLDER,
  parseComing,
  readMigrations,
  refusals,
  statements,
  unshipped,
} from '../migration-order.ts';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const NOTHING: Coming = { triggers: [], bodies: [] };
const HASH_A = 'a'.repeat(64);

// --- The repository's own migrations and coming list --------------------------------------------------------------

const MIGRATIONS: readonly Migration[] = readdirSync(path.join(ROOT, MIGRATIONS_FOLDER))
  .filter((name) => name.endsWith('.sql'))
  .toSorted()
  .map((name) => ({ name, sql: readFileSync(path.join(ROOT, MIGRATIONS_FOLDER, name), 'utf8') }));

/** git, here, with its arguments as a list: never through a shell. */
function git(...args: string[]): { readonly status: number | null; readonly stdout: string } {
  const done = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8', windowsHide: true });
  if (done.error !== undefined) throw new Error(`git couldn't be run: ${done.error.message}`);
  return { status: done.status, stdout: done.stdout.trim() };
}

const MAIN = 'origin/main';

/** The commit whose coming list a migration is held to (this file's header). */
function commitBefore(migration: string): string {
  if (git('rev-parse', '--verify', '--quiet', `${MAIN}^{commit}`).status !== 0) {
    throw new Error(`${migration} needs ${MAIN}'s history to be checked: fetch it whole (fetch-depth 0)`);
  }
  const file = `${MIGRATIONS_FOLDER}/${migration}`;
  if (git('cat-file', '-e', `${MAIN}:${file}`).status !== 0) {
    const base = git('merge-base', 'HEAD', MAIN);
    if (base.status !== 0) throw new Error(`no commit is shared with ${MAIN}, so ${migration} can't be checked`);
    return base.stdout;
  }
  const brought = git('log', '--first-parent', '--diff-filter=A', '--format=%H', MAIN, '--', file);
  const first = brought.stdout.split('\n').at(-1) ?? '';
  if (brought.status !== 0 || first === '') throw new Error(`git couldn't say which commit brought ${migration}`);
  return `${first}^1`;
}

/** coming.json as a commit had it; a commit without the file had nothing coming. A commit this clone lacks is an error. */
function comingAt(commit: string): Coming {
  const known = git('rev-parse', '--verify', '--quiet', `${commit}^{commit}`);
  if (known.status !== 0) throw new Error(`${commit} isn't in this clone: fetch main's history whole (fetch-depth 0)`);
  const shown = git('show', `${known.stdout}:${COMING_FILE}`);
  return parseComing(shown.status === 0 ? shown.stdout : undefined);
}

describe("the repository's migrations", () => {
  it('are each named as the runner names them', () => {
    expect(MIGRATIONS.filter(({ name }) => !MIGRATION_NAME.test(name))).toEqual([]);
  });

  it('refused with nothing ever coming are exactly the grandfathered ones: the list hides nothing later', () => {
    const refused = refusals(
      MIGRATIONS,
      MIGRATIONS.map(({ name }) => name),
      () => NOTHING,
      new Map(),
    );
    expect([...new Set(refused.map((line) => line.slice(0, 4)))]).toEqual([...GRANDFATHERED.keys()]);
  });

  it('each change after those was carried as coming by the code before it', () => {
    const refused = refusals(
      MIGRATIONS,
      MIGRATIONS.map(({ name }) => name),
      (migration) => comingAt(commitBefore(migration)),
    );
    expect(refused).toEqual([]);
  });

  it("read each function's body as Postgres keeps it: every last body's hash is the one schema-guard.ts holds", () => {
    const guard = readFileSync(path.join(ROOT, 'packages/platform/src/db/schema-guard.ts'), 'utf8');
    const { bodies } = readMigrations(MIGRATIONS);
    expect(bodies.size).toBeGreaterThan(10);
    expect([...bodies].filter(([, hash]) => !guard.includes(`'${hash}'`))).toEqual([]);
  });

  it("hold coming.json to what isn't built yet", () => {
    const coming = parseComing(readFileSync(path.join(ROOT, COMING_FILE), 'utf8'));
    expect(leftBehind(coming, readMigrations(MIGRATIONS))).toEqual([]);
  });

  it("can find the code before a migration on main: 0081's came after a commit without it", () => {
    const before = commitBefore('0081_month_total_index_only.sql');
    expect(git('cat-file', '-e', `${before}:${MIGRATIONS_FOLDER}/0081_month_total_index_only.sql`).status).not.toBe(0);
    expect(comingAt(before)).toEqual(NOTHING);
  });
});

// --- The rule, on migrations written for it -----------------------------------------------------------------------

const BUILT = {
  name: '0001_built.sql',
  sql: `CREATE TABLE app.things (id uuid PRIMARY KEY, status text NOT NULL);
CREATE FUNCTION app.guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$ BEGIN RETURN NEW; END $$;
CREATE TRIGGER guarded BEFORE UPDATE ON app.things FOR EACH ROW EXECUTE FUNCTION app.guard();`,
};
const NEW_BODY = ' BEGIN RETURN NULL; END ';
const fnWith = (body: string) => `CREATE FUNCTION app.f() RETURNS trigger LANGUAGE plpgsql AS $$${body}$$;`;
const hashOfText = (body: string): string =>
  readMigrations([{ name: '0001_x.sql', sql: fnWith(body) }]).bodies.get('app.f') ?? '';
const later = (sql: string): Migration[] => [BUILT, { name: '0002_later.sql', sql }];
const refusedOf = (sql: string, coming: Coming = NOTHING) =>
  refusals(later(sql), ['0002_later.sql'], () => coming, new Map());

const ADD_TRIGGER = `CREATE CONSTRAINT TRIGGER marks AFTER INSERT OR UPDATE ON app.things
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.guard();`;
const REPLACE_BODY = `CREATE OR REPLACE FUNCTION app.guard() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $body$${NEW_BODY}$body$;`;
const newHash = (): string => readMigrations(later(REPLACE_BODY)).bodies.get('app.guard') ?? '';
const comingTrigger = (over: Partial<Coming['triggers'][number]> = {}): Coming => ({
  triggers: [{ table: 'app.things', name: 'marks', function: 'app.guard', body: HASH_A, ...over }],
  bodies: [],
});

describe('a migration adding a trigger to a table already built', () => {
  it('is refused when the code before it did not carry it as coming', () => {
    expect(refusedOf(ADD_TRIGGER)).toEqual([
      "0002_later.sql adds marks on app.things, which the code before it didn't carry in coming.json's triggers",
    ]);
  });

  it('is accepted when it did, by table and name', () => {
    expect(refusedOf(ADD_TRIGGER, comingTrigger())).toEqual([]);
  });

  it.each([
    ['on another table', { table: 'app.others' }],
    ['by another name', { name: 'other_marks' }],
  ])('is refused when the coming trigger is %s', (_what, over) => {
    expect(refusedOf(ADD_TRIGGER, comingTrigger(over))).toHaveLength(1);
  });

  it('is refused when it is only a coming body', () => {
    expect(refusedOf(ADD_TRIGGER, { triggers: [], bodies: [{ function: 'app.guard', body: HASH_A }] })).toHaveLength(1);
  });

  it('is refused when made again after a drop, as a changed one', () => {
    expect(
      refusedOf(`DROP TRIGGER guarded ON app.things;
      CREATE TRIGGER guarded BEFORE INSERT OR UPDATE ON app.things FOR EACH ROW EXECUTE FUNCTION app.guard();`),
    ).toEqual([
      "0002_later.sql adds guarded on app.things, which the code before it didn't carry in coming.json's triggers",
    ]);
  });

  it('on a table the same migration builds, is nothing to tell', () => {
    expect(
      refusedOf(`CREATE TABLE app.fresh (id uuid);
        CREATE TRIGGER guarded BEFORE UPDATE ON app.fresh FOR EACH ROW EXECUTE FUNCTION app.guard();`),
    ).toEqual([]);
  });

  it('in a comment or a string, is nothing at all', () => {
    expect(
      refusedOf(`-- CREATE TRIGGER marks AFTER UPDATE ON app.things
        /* CREATE TRIGGER marks /* nested */ AFTER UPDATE ON app.things; */
        COMMENT ON TABLE app.things IS 'CREATE TRIGGER marks AFTER UPDATE ON app.things; it''s said';
        COMMENT ON TABLE app.things IS E'a quote \\' then; CREATE TRIGGER marks AFTER UPDATE ON app.things';`),
    ).toEqual([]);
  });

  it('quoted and in capitals, is read as Postgres folds it', () => {
    expect(
      refusedOf(
        `CREATE TRIGGER "marks" AFTER UPDATE ON "app"."things" FOR EACH ROW EXECUTE FUNCTION app.guard();`,
        comingTrigger(),
      ),
    ).toEqual([]);
  });
});

describe('a migration writing a new body over a function already written', () => {
  it('is refused when the code before it did not carry the body as coming', () => {
    expect(refusedOf(REPLACE_BODY)).toEqual([
      "0002_later.sql writes a new body for app.guard, which the code before it didn't carry in coming.json's bodies",
    ]);
  });

  it('is accepted when it did, by function and exact hash, in the bodies or a coming trigger', () => {
    expect(refusedOf(REPLACE_BODY, { triggers: [], bodies: [{ function: 'app.guard', body: newHash() }] })).toEqual([]);
    expect(refusedOf(REPLACE_BODY, comingTrigger({ name: 'x', body: newHash() }))).toEqual([]);
  });

  it.each([
    ['another hash', { function: 'app.guard', body: HASH_A }],
    ['the hash for another function', { function: 'app.other', body: '' }],
  ])('is refused when the coming body has %s', (_what, entry) => {
    const body = entry.body === '' ? newHash() : entry.body;
    expect(refusedOf(REPLACE_BODY, { triggers: [], bodies: [{ ...entry, body }] })).toHaveLength(1);
  });

  it('written again exactly as it was is nothing to tell', () => {
    expect(
      refusedOf(
        'CREATE OR REPLACE FUNCTION app.guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$ BEGIN RETURN NEW; END $$;',
      ),
    ).toEqual([]);
  });

  it('hashes the text between the dollar quotes, whatever their tag', () => {
    expect(newHash()).toBe(hashOfText(NEW_BODY));
  });

  it('new, is held to the body a coming trigger calling it carries', () => {
    const sql = `${fnWith(NEW_BODY)}\n${ADD_TRIGGER.replace('app.guard()', 'app.f()')}`;
    const calling = (body: string) => comingTrigger({ function: 'app.f', body });
    expect(refusedOf(sql, calling(hashOfText(NEW_BODY)))).toEqual([]);
    expect(refusedOf(sql, calling(HASH_A))).toEqual([
      '0002_later.sql writes app.f with another body than the coming trigger calling it carries',
    ]);
    expect(refusedOf(fnWith(NEW_BODY))).toEqual([]);
  });
});

describe('a migration doing what no coming entry describes', () => {
  it.each([
    ['dropping a trigger for good', 'DROP TRIGGER IF EXISTS guarded ON app.things;', 'drops guarded on app.things'],
    ['switching one off', 'ALTER TABLE app.things DISABLE TRIGGER guarded;', 'switches a trigger on or off'],
    [
      'switching one on always',
      'ALTER TABLE app.things ENABLE ALWAYS TRIGGER guarded;',
      'switches a trigger on or off',
    ],
    ['altering a function', 'ALTER FUNCTION app.guard() SECURITY DEFINER;', 'alters or drops app.guard'],
    ['dropping a function', 'DROP FUNCTION app.guard() CASCADE;', 'alters or drops app.guard'],
    [
      'running SQL from a DO block',
      "DO $$ BEGIN EXECUTE 'create trigger t after update on app.things'; END $$;",
      'runs a DO block naming a trigger, a function or EXECUTE',
    ],
    [
      'writing a body outside dollar quotes',
      "CREATE OR REPLACE FUNCTION app.guard() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';",
      'writes app.guard with no dollar-quoted body',
    ],
  ])('is refused outright: %s', (_what, sql, what) => {
    expect(refusedOf(sql, comingTrigger({ name: 'guarded', body: HASH_A }))).toEqual([
      `0002_later.sql ${what}: no coming entry can describe that, so the image before it would raise the tamper alarm`,
    ]);
  });

  it('a DO block touching no trigger or function, or a function no earlier migration wrote, is nothing to tell', () => {
    expect(
      refusedOf("DO $$ BEGIN UPDATE app.things SET status = 'x'; END $$; DROP FUNCTION app.never_built();"),
    ).toEqual([]);
  });
});

describe('refusals', () => {
  it('never refuses a grandfathered migration, and looks nothing up for one that changes nothing', () => {
    const asked: string[] = [];
    const before = (migration: string) => {
      asked.push(migration);
      return NOTHING;
    };
    expect(refusals(later(ADD_TRIGGER), ['0002_later.sql'], before, new Map([['0002', 'why']]))).toEqual([]);
    expect(refusals(later('SELECT 1;'), ['0002_later.sql'], before, new Map())).toEqual([]);
    expect(asked).toEqual([]);
    // A new function is looked up: a coming trigger calling it must carry its body.
    expect(refusals(later('SELECT 1;'), ['0001_built.sql'], before, new Map())).toEqual([]);
    expect(asked).toEqual(['0001_built.sql']);
  });

  it('grandfathers nothing after 0081 by default', () => {
    expect([...GRANDFATHERED.keys()].every((number) => number <= '0081')).toBe(true);
    expect(refusals(later(ADD_TRIGGER), ['0002_later.sql'], () => NOTHING)).toHaveLength(1);
  });
});

describe('leftBehind', () => {
  const reading = readMigrations(later(REPLACE_BODY));
  const oldHash = readMigrations([BUILT]).bodies.get('app.guard') ?? '';

  it('names a coming trigger already built, and a coming body already written, now or before', () => {
    expect(
      leftBehind(
        {
          triggers: [{ table: 'app.things', name: 'guarded', function: 'app.guard', body: HASH_A }],
          bodies: [
            { function: 'app.guard', body: newHash() },
            { function: 'app.guard', body: oldHash },
          ],
        },
        reading,
      ),
    ).toEqual([
      'coming trigger guarded on app.things is already built: move it out of coming.json',
      'coming body for app.guard is already written: take it out of coming.json',
      'coming body for app.guard is already written: take it out of coming.json',
    ]);
  });

  it('names a coming body for a function no migration wrote, and passes one still to come', () => {
    expect(
      leftBehind(
        {
          triggers: [{ table: 'app.things', name: 'marks', function: 'app.guard', body: HASH_A }],
          bodies: [
            { function: 'app.guard', body: HASH_A },
            { function: 'app.nowhere', body: HASH_A },
          ],
        },
        reading,
      ),
    ).toEqual(['coming body for app.nowhere names no function the migrations wrote']);
  });
});

describe('parseComing', () => {
  const trigger = { table: 't.t', name: 'n', definition: 'CREATE TRIGGER n', function: 'f.f', body: HASH_A };

  it('reads the list, and a commit without the file as nothing coming', () => {
    expect(parseComing(JSON.stringify({ triggers: [trigger], bodies: [{ function: 'f.f', body: HASH_A }] }))).toEqual({
      triggers: [{ table: 't.t', name: 'n', function: 'f.f', body: HASH_A }],
      bodies: [{ function: 'f.f', body: HASH_A }],
    });
    expect(parseComing(undefined)).toEqual(NOTHING);
  });

  it.each([
    ['not an object', '[]', 'coming.json lists triggers and bodies'],
    ['null', 'null', 'coming.json must be an object'],
    ['no bodies', '{"triggers": []}', 'coming.json lists triggers and bodies'],
    [
      'a body in capitals',
      JSON.stringify({ triggers: [], bodies: [{ function: 'f.f', body: 'A'.repeat(64) }] }),
      'SHA-256',
    ],
    [
      'a trigger with no definition',
      JSON.stringify({ triggers: [{ ...trigger, definition: '' }], bodies: [] }),
      'definition',
    ],
    ['an entry that is not an object', JSON.stringify({ triggers: [], bodies: ['f.f'] }), 'function, body'],
  ])('refuses %s', (_what, json, says) => {
    expect(() => parseComing(json)).toThrow(says);
  });
});

describe('statements', () => {
  it('splits on semicolons outside quotes, comments and bodies, keeping each body whole', () => {
    expect(
      statements(`SELECT ';'; -- a; comment\nCREATE FUNCTION a.b() AS $x$ one; $y$ two $x$; select "a;b"`),
    ).toEqual([
      { words: "select ';'", bodies: [] },
      { words: 'create function a.b() as $$', bodies: [' one; $y$ two '] },
      { words: 'select "a;b"', bodies: [] },
    ]);
  });

  it('takes a $1 or a name with $ in it as no body', () => {
    expect(statements('SELECT $1, a$b$ FROM t')).toEqual([{ words: 'select $1, a$b$ from t', bodies: [] }]);
  });

  it.each([
    ['a quote', "SELECT 'open"],
    ['a body', 'SELECT $$ open'],
    ['a comment', 'SELECT 1 /* open /* and */'],
  ])('refuses %s never closed', (_what, sql) => {
    expect(() => statements(sql)).toThrow('never closed');
  });

  it('ends a line comment at the end of the file', () => {
    expect(statements('SELECT 1 -- the end')).toEqual([{ words: 'select 1', bodies: [] }]);
  });
});

describe('unshipped', () => {
  it('says nothing for a new function no coming trigger calls', () => {
    expect(unshipped({ kind: 'new', function: 'a.b', body: HASH_A }, NOTHING)).toBeUndefined();
  });
});
