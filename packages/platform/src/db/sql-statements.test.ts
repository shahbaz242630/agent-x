import { describe, expect, it } from 'vitest';

import { transactionControl } from './sql-statements.ts';

describe('transactionControl', () => {
  it.each([
    ['begin;', ['BEGIN']],
    ['BEGIN WORK;', ['BEGIN']],
    ['start transaction isolation level serializable;', ['START']],
    ['commit;', ['COMMIT']],
    ['commit prepared $$x$$;', ['COMMIT']],
    ['end;', ['END']],
    ['abort;', ['ABORT']],
    ['rollback;', ['ROLLBACK']],
    ['rollback and chain;', ['ROLLBACK']],
    ["prepare transaction 'x';", ['PREPARE']],
    ['create table t (id int); commit; insert into t values (1)', ['COMMIT']],
    ['create table t (id int)\n;\n  Commit\n', ['COMMIT']],
    ['-- a comment first\ncommit;', ['COMMIT']],
    ['/* a comment first */ commit;', ['COMMIT']],
    ['select 1;;commit', ['COMMIT']],
    ['begin; select 1; commit;', ['BEGIN', 'COMMIT']],
    // Found by the adversarial review: Postgres reads a comment between two words as a space.
    ["prepare/**/transaction 'x';", ['PREPARE']],
    ["prepare -- a comment\ntransaction 'x';", ['PREPARE']],
    ['start/* a comment */transaction;', ['START']],
    ['commit/**/;', ['COMMIT']],
  ])('finds the statement in %j', (sql, expected) => {
    expect(transactionControl(sql)).toEqual(expected);
  });

  it.each([
    ['plain statements', 'create table t (id int);\ninsert into t values (1);'],
    [
      'a savepoint and a rollback to it, which stay inside the transaction',
      'savepoint s; rollback to savepoint s; release s;',
    ],
    ['rollback to without the word savepoint', 'savepoint s; rollback to s;'],
    ['rollback to with a comment between the words', 'savepoint s; rollback /* back */ to s;'],
    ['start without transaction', 'select 1; start_thing();'],
    ['a prepared statement', 'prepare q as select 1; execute q; deallocate q;'],
    ['words inside a line comment', '-- then commit;\nselect 1;'],
    ['words inside a block comment', '/* begin; commit; */ select 1;'],
    ['a nested block comment', '/* outer /* inner commit; */ still a comment; commit; */ select 1;'],
    ['a string', "select 'x; commit;';"],
    ['a string with a doubled quote', "select 'it''s; commit;';"],
    ['an E string with an escaped quote', "select E'it\\'s; commit;';"],
    ['a quoted name', 'select 1 as "a; commit;";'],
    ['a dollar-quoted body', 'do $$ begin perform 1; end; $$;'],
    [
      'a tagged dollar-quoted body',
      'create function f() returns int language plpgsql as $body$ begin return 1; end; $body$;',
    ],
    ['a parameter that looks like a dollar quote', 'select $1; select 2;'],
    ['a dollar sign inside a name', 'select 1 as a$b; select 2;'],
    ['an unclosed string', "select 'never closed; commit;"],
    ['an unclosed block comment', '/* never closed; commit;'],
    ['an unclosed dollar quote', 'do $$ begin commit; end;'],
    ['a line comment with no newline', 'select 1; -- commit'],
  ])('ignores %s', (_, sql) => {
    expect(transactionControl(sql)).toEqual([]);
  });

  it('treats a backslash in an ordinary string as an ordinary character', () => {
    expect(transactionControl("select 'a\\'; commit;")).toEqual(['COMMIT']);
  });

  it('reads an E string at the very start of the text', () => {
    expect(transactionControl("E'it\\'s; commit;'")).toEqual([]);
  });

  it('reads a statement that starts with a bracket or a quote, then the next one', () => {
    expect(transactionControl('(select 1); "odd name"; commit;')).toEqual(['COMMIT']);
  });

  it('does not take a name that ends in e for the E of an E string', () => {
    expect(transactionControl("select note'x\\'; commit;")).toEqual(['COMMIT']);
  });
});
