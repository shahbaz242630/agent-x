// S185: no migration destroys data or switches a guard off unless EXCEPTIONS
// names it (the rule is written out at the top of tooling/migration-danger.ts).
// Migrations run by themselves as the owner on every release, so this is the
// last place a person's eyes are guaranteed.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { dangerRefusals, EXCEPTIONS, plainOf } from '../migration-danger.ts';
import { type Migration, MIGRATIONS_FOLDER } from '../migration-order.ts';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const MIGRATIONS: readonly Migration[] = readdirSync(path.join(ROOT, MIGRATIONS_FOLDER))
  .filter((name) => name.endsWith('.sql'))
  .toSorted()
  .map((name) => ({ name, sql: readFileSync(path.join(ROOT, MIGRATIONS_FOLDER, name), 'utf8') }));

/** The refusals for one planted migration, numbered past every real one. */
const planted = (sql: string): string[] => dangerRefusals([{ name: '9999_planted.sql', sql }], []);

describe("the repository's migrations", () => {
  it('destroy nothing and switch no guard off, but for the exceptions named', () => {
    expect(MIGRATIONS.length).toBeGreaterThan(80);
    expect(dangerRefusals(MIGRATIONS)).toEqual([]);
  });

  it('name each exception with its reason, once', () => {
    for (const one of EXCEPTIONS) expect(one.reason.length).toBeGreaterThan(40);
    expect(new Set(EXCEPTIONS.map((one) => `${one.migration} ${one.rule}`)).size).toBe(EXCEPTIONS.length);
  });

  it('would refuse every excepted migration without its exception', () => {
    const excepted = MIGRATIONS.filter(({ name }) => EXCEPTIONS.some((one) => name.startsWith(`${one.migration}_`)));
    expect(dangerRefusals(excepted, []).map((said) => said.split(':')[0])).toEqual([
      '0054_agent_zones_signed.sql row-security-off',
      '0067_order_key_full_fold.sql drop-column',
      '0067_order_key_full_fold.sql row-security-off',
      '0079_operator_role.sql row-security-off',
    ]);
  });
});

describe('a planted migration', () => {
  it.each([
    ['DROP TABLE audit.events;', 'drop'],
    ['drop table if exists x.y cascade;', 'drop'],
    ['DROP SCHEMA security CASCADE;', 'drop'],
    ['DROP DATABASE agentx;', 'drop'],
    ['ALTER TABLE a.b DROP COLUMN c;', 'drop-column'],
    ['ALTER TABLE a.b DROP c;', 'drop-column'],
    ['ALTER TABLE IF EXISTS a.b ADD COLUMN d int, DROP IF EXISTS c;', 'drop-column'],
    ['TRUNCATE audit.events;', 'truncate'],
    ['truncate table only a.b;', 'truncate'],
    ['DELETE FROM audit.events WHERE true;', 'guarded-write'],
    ['delete from "audit"."events";', 'guarded-write'],
    ['DELETE FROM "Security" . events;', 'guarded-write'],
    ['UPDATE security.events SET at = now();', 'guarded-write'],
    ['WITH gone AS (DELETE FROM audit.heads RETURNING 1) SELECT 1;', 'guarded-write'],
    ['MERGE INTO audit.heads h USING x ON true WHEN MATCHED THEN DELETE;', 'guarded-write'],
    ['ALTER TABLE audit.events DISABLE TRIGGER ALL;', 'trigger-off'],
    ['SET session_replication_role = replica;', 'trigger-off'],
    ['ALTER TABLE a.b DISABLE ROW LEVEL SECURITY;', 'row-security-off'],
    ['ALTER TABLE a.b NO FORCE ROW LEVEL SECURITY;', 'row-security-off'],
    ['SET row_security = off;', 'row-security-off'],
    ["DO $$ BEGIN EXECUTE 'DROP TABLE ' || 'audit.events'; END $$;", 'dynamic-sql'],
    ['DO $$ BEGIN DELETE FROM audit.events; END $$;', 'guarded-write'],
    ['DO $outer$ BEGIN PERFORM 1; END $outer$; DO $a$ BEGIN TRUNCATE a.b; END $a$;', 'truncate'],
    ['CREATE FUNCTION a.f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN DROP TABLE a.b; END $$;', 'drop'],
    ["CREATE FUNCTION a.f() RETURNS void LANGUAGE sql AS 'DELETE FROM audit.events';", 'string-body'],
    ["DO 'BEGIN TRUNCATE a.b; END';", 'string-body'],
    ["DO LANGUAGE plpgsql 'BEGIN NULL; END';", 'string-body'],
    ['DELETE FROM U&"\\0061udit".events;', 'unreadable'],
    ["SELECT 'never closed;", 'unreadable'],
    ['SELECT $$ never closed;', 'unreadable'],
  ])('%s is refused for %s', (sql, rule) => {
    expect(planted(sql).map((said) => said.split(':')[0])).toContain(`9999_planted.sql ${rule}`);
  });

  it.each([
    'CREATE TRIGGER t BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON audit.events FOR EACH STATEMENT EXECUTE FUNCTION audit.f();',
    'GRANT SELECT, TRUNCATE, DELETE ON a.b TO r; REVOKE UPDATE, TRUNCATE ON audit.events FROM r;',
    'GRANT EXECUTE ON FUNCTION a.f() TO r;',
    'ALTER TABLE a.b DROP CONSTRAINT c, ALTER COLUMN d DROP NOT NULL, ALTER COLUMN e DROP DEFAULT;',
    'ALTER TABLE a.b ALTER COLUMN d DROP IDENTITY IF EXISTS, ALTER COLUMN e DROP EXPRESSION;',
    'ALTER TABLE a.b ENABLE ROW LEVEL SECURITY; ALTER TABLE a.b FORCE ROW LEVEL SECURITY;',
    "UPDATE a.b SET note = 'DROP TABLE audit.events; TRUNCATE x'; -- DELETE FROM audit.events",
    'DELETE FROM a.b WHERE c; /* DROP DATABASE agentx */ INSERT INTO audit.events VALUES (1);',
    "SELECT E'it\\'s DROP TABLE x';",
    'CREATE FUNCTION a.f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP = $q$DELETE$q$ THEN RETURN OLD; END IF; RETURN NEW; END $$;',
    'SELECT 1 FOR UPDATE;',
  ])('%s passes', (sql) => {
    expect(planted(sql)).toEqual([]);
  });

  it('is refused once for each rule and statement said alike', () => {
    expect(planted('DROP TABLE a.b; DROP TABLE a.b;')).toEqual([
      '9999_planted.sql drop: drops a table, schema or database',
    ]);
  });
});

describe('the exceptions', () => {
  const sql = 'ALTER TABLE a.b DROP COLUMN c;';

  it('let through only their own rule in their own migration', () => {
    const excepted = [{ migration: '0100', rule: 'drop-column' as const, reason: 'planted' }];
    expect(dangerRefusals([{ name: '0100_x.sql', sql }], excepted)).toEqual([]);
    expect(dangerRefusals([{ name: '0100_x.sql', sql: `${sql} TRUNCATE a.b;` }], excepted)).toEqual([
      '0100_x.sql truncate: truncates a table',
    ]);
    expect(dangerRefusals([{ name: '0101_x.sql', sql }], excepted)).toEqual([
      '0101_x.sql drop-column: drops a column',
      'exception 0100 drop-column names no migration: take it out',
    ]);
  });

  it('are refused when stale', () => {
    const excepted = [{ migration: '0100', rule: 'truncate' as const, reason: 'planted' }];
    expect(dangerRefusals([{ name: '0100_x.sql', sql: 'SELECT 1;' }], excepted)).toEqual([
      'exception 0100 truncate matches nothing its migration holds: take it out',
    ]);
  });
});

describe('the reader', () => {
  it('blanks strings and unquotes names, lower-cased', () => {
    expect(plainOf(`select 'a''b', e'c\\'d', "Audit"."E""v"`)).toBe(`select '', e'', audit.e"v`);
  });
});
