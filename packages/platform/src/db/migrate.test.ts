import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { loadMigrations, MigrationRefused, NO_TRANSACTION } from './migrate.ts';

let folder: string;

beforeEach(async () => {
  folder = await mkdtemp(path.join(tmpdir(), 'agentx-migrations-'));
});

afterEach(async () => {
  await rm(folder, { recursive: true, force: true });
});

const write = (name: string, text: string): Promise<void> => writeFile(path.join(folder, name), text, 'utf8');
const sha256 = (text: string): string => createHash('sha256').update(text).digest('hex');

async function refusal(): Promise<readonly string[]> {
  const error = await loadMigrations(folder).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(MigrationRefused);
  return (error as MigrationRefused).problems;
}

describe('loadMigrations', () => {
  it('reads the files in number order, with their checksums', async () => {
    await write('0002_second.sql', 'select 2;\n');
    await write('0001_first.sql', 'select 1;\n');
    expect(await loadMigrations(folder)).toEqual([
      { name: '0001_first.sql', sql: 'select 1;\n', checksum: sha256('select 1;\n') },
      { name: '0002_second.sql', sql: 'select 2;\n', checksum: sha256('select 2;\n') },
    ]);
  });

  it('gives a file the same checksum with Windows line endings, so a checkout cannot change it', async () => {
    await write('0001_first.sql', 'select 1;\r\nselect 2;\r\n');
    const [migration] = await loadMigrations(folder);
    expect(migration?.sql).toBe('select 1;\nselect 2;\n');
    expect(migration?.checksum).toBe(sha256('select 1;\nselect 2;\n'));
  });

  it('accepts an empty folder', async () => {
    expect(await loadMigrations(folder)).toEqual([]);
  });

  it.each([
    ['a number without four digits', '1_first.sql'],
    ['a dash instead of an underscore', '0001-first.sql'],
    ['capital letters', '0001_First.sql'],
    ['no words after the number', '0001.sql'],
    ['a double underscore', '0001__first.sql'],
    ['another file type', '0001_first.txt'],
    ['a stray file', 'README.md'],
  ])('refuses a file named with %s', async (_, name) => {
    await write(name, 'select 1;');
    expect(await refusal()).toEqual([`${name} is not a migration file named like 0001_words.sql`]);
  });

  it('refuses a folder among the files', async () => {
    await mkdir(path.join(folder, '0001_folder.sql'));
    expect(await refusal()).toEqual(['0001_folder.sql is not a migration file named like 0001_words.sql']);
  });

  it('refuses a gap in the numbers', async () => {
    await write('0001_first.sql', 'select 1;');
    await write('0003_third.sql', 'select 3;');
    expect(await refusal()).toEqual(['0003_third.sql is out of sequence: the next file must be numbered 0002']);
  });

  it('refuses two files with the same number', async () => {
    await write('0001_first.sql', 'select 1;');
    await write('0001_other.sql', 'select 1;');
    expect(await refusal()).toEqual(['0001_other.sql is out of sequence: the next file must be numbered 0002']);
  });

  it('refuses a file that does not start at 0001', async () => {
    await write('0002_second.sql', 'select 2;');
    expect(await refusal()).toEqual(['0002_second.sql is out of sequence: the next file must be numbered 0001']);
  });

  it('refuses an empty file, and one that starts with a byte-order mark', async () => {
    await write('0001_first.sql', ' \n\t\n');
    await write('0002_second.sql', `${String.fromCharCode(0xfe_ff)}select 2;`);
    expect(await refusal()).toEqual(['0001_first.sql is empty', '0002_second.sql starts with a byte-order mark']);
  });

  it('refuses a file that would begin or end its own transaction', async () => {
    await write('0001_first.sql', 'begin;\ncreate table t (id int);\ncommit;\n');
    expect(await refusal()).toEqual([
      '0001_first.sql has BEGIN, COMMIT: each file already runs in one transaction, so it must not begin or end one (write function bodies in $$ quotes, not BEGIN ATOMIC)',
    ]);
  });

  it('lets a function body keep its own BEGIN and END', async () => {
    await write(
      '0001_first.sql',
      'create function f() returns int language plpgsql as $$\nbegin\n  return 1;\nend;\n$$;\n',
    );
    expect(await loadMigrations(folder)).toHaveLength(1);
  });

  it('lists every problem at once', async () => {
    await write('0001_first.sql', '');
    await write('0003_third.sql', 'select 3;');
    await write('notes.txt', 'x');
    expect(await refusal()).toHaveLength(3);
  });

  describe('a file that runs outside a transaction (its first line NO_TRANSACTION)', () => {
    const BUILD = 'create index concurrently if not exists one_id on demo.one (id)';
    const DROP = 'drop index concurrently if exists demo.old_id';

    it('may hold concurrent builds and drops of named indexes on qualified tables, comments between them', async () => {
      await write(
        '0001_first.sql',
        `${NO_TRANSACTION}
-- why
${BUILD};
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS two_id ON ONLY demo.two (id) WHERE id > 0;
${DROP};
`,
      );
      expect(await loadMigrations(folder)).toHaveLength(1);
    });

    it.each([
      ['a table made', 'create table demo.three (id int)'],
      ['an index built in a transaction', 'create index one_id on demo.one (id)'],
      ['a build that would stop at one already there, not valid', 'create index concurrently one_id on demo.one (id)'],
      ['an unnamed index', 'create index concurrently if not exists on demo.one (id)'],
      ['a table not qualified', 'create index concurrently if not exists one_id on one (id)'],
      ['a drop that would fail on none', 'drop index concurrently demo.old_id'],
      ['a drop not qualified', 'drop index concurrently if exists old_id'],
      ['two drops in one statement', 'drop index concurrently if exists demo.a, demo.b'],
      ['a drop that cascades', 'drop index concurrently if exists demo.old_id cascade'],
    ])('refuses %s, naming the statement', async (_what, statement) => {
      await write(
        '0001_first.sql',
        `${NO_TRANSACTION}
${BUILD};
${statement};
`,
      );
      expect(await refusal()).toEqual([
        `0001_first.sql runs outside a transaction, so it may hold only CREATE INDEX CONCURRENTLY IF NOT EXISTS and DROP INDEX CONCURRENTLY IF EXISTS statements on schema-qualified names, one per statement: "${statement.slice(0, 80)}" is neither`,
      ]);
    });

    it('is only such a file with that line first: anywhere else it is a comment, and the file runs in a transaction', async () => {
      await write(
        '0001_first.sql',
        `-- first
${NO_TRANSACTION}
create table demo.three (id int);
`,
      );
      expect(await loadMigrations(folder)).toHaveLength(1);
    });
  });
});
