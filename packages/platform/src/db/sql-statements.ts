// Reads SQL files at the level of their statements, with comments, quoted
// strings, quoted names and dollar-quoted bodies (where a function's own BEGIN
// and END live) skipped over:
// - transactionControl finds the statements in a migration file that would
//   begin or end a transaction. The runner wraps each file in one
//   transaction, so a COMMIT in the file would commit part of it and leave the
//   rest to run on its own, making the file impossible to retry safely.
// - splitStatements cuts a db/bootstrap file into its statements, because the
//   set-up job sends them one at a time, as psql does: CREATE DATABASE can't
//   run with other statements in one query.

/** A dollar-quote tag: `$$` or `$name$`. A `$` followed by a digit is a parameter, not a quote. */
const DOLLAR_TAG = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/;
const WORD = /^[A-Za-z_]+/;
const NAME_CHARACTER = /[A-Za-z0-9_$]/;

/** Where the quoted text starting at `start` ends: the index just after its closing quote. */
function endOfQuoted(sql: string, start: number, quote: "'" | '"', backslashEscapes: boolean): number {
  let index = start + 1;
  while (index < sql.length) {
    const character = sql[index];
    if (backslashEscapes && character === '\\') {
      index += 2;
    } else if (character === quote) {
      // A doubled quote is a quote inside the text.
      if (sql[index + 1] !== quote) return index + 1;
      index += 2;
    } else {
      index += 1;
    }
  }
  return sql.length;
}

/** Where the block comment starting at `start` ends. Postgres lets block comments nest. */
function endOfBlockComment(sql: string, start: number): number {
  let depth = 0;
  let index = start;
  while (index < sql.length) {
    if (sql.startsWith('/*', index)) {
      depth += 1;
      index += 2;
    } else if (sql.startsWith('*/', index)) {
      depth -= 1;
      index += 2;
      if (depth === 0) return index;
    } else {
      index += 1;
    }
  }
  return sql.length;
}

/**
 * The index of the next token: whitespace and comments are skipped, because
 * Postgres treats a comment as whitespace (`prepare/**\/transaction` is PREPARE
 * TRANSACTION).
 */
function skipIgnorable(sql: string, start: number): number {
  let index = start;
  for (;;) {
    if (/\s/.test(sql.charAt(index))) {
      index += 1;
    } else if (sql.startsWith('--', index)) {
      const newline = sql.indexOf('\n', index);
      index = newline === -1 ? sql.length : newline + 1;
    } else if (sql.startsWith('/*', index)) {
      index = endOfBlockComment(sql, index);
    } else {
      return index;
    }
  }
}

/** The statement's first two words, lower case, with any comments between them skipped. */
function leadingWords(sql: string, start: number): [string, string] {
  const first = WORD.exec(sql.slice(start))?.[0] ?? '';
  const second = WORD.exec(sql.slice(skipIgnorable(sql, start + first.length)))?.[0] ?? '';
  return [first.toLowerCase(), second.toLowerCase()];
}

/** True if a statement starting with these words begins or ends a transaction. */
function controlsTransaction([first, second]: [string, string]): boolean {
  switch (first) {
    case 'begin':
    case 'commit':
    case 'end':
    case 'abort':
      return true;
    // ROLLBACK TO SAVEPOINT stays inside the transaction.
    case 'rollback':
      return second !== 'to';
    case 'start':
    case 'prepare':
      return second === 'transaction';
    default:
      return false;
  }
}

/** Skips one token: a quoted string, quoted name or dollar-quoted body as a whole, or one character. */
function endOfToken(sql: string, index: number): number {
  const character = sql[index];
  const previous = sql[index - 1] ?? '';
  if (character === "'") {
    // E'...' strings treat a backslash as an escape; an E that ends a longer name doesn't count.
    const escapes = /[Ee]/.test(previous) && !NAME_CHARACTER.test(sql[index - 2] ?? '');
    return endOfQuoted(sql, index, "'", escapes);
  }
  if (character === '"') return endOfQuoted(sql, index, '"', false);
  if (character === '$' && !NAME_CHARACTER.test(previous)) {
    const tag = DOLLAR_TAG.exec(sql.slice(index))?.[0];
    if (tag !== undefined) {
      const close = sql.indexOf(tag, index + tag.length);
      return close === -1 ? sql.length : close + tag.length;
    }
  }
  return index + 1;
}

/** Where each top-level statement starts and ends (its `;` excluded), comments between statements left out. */
function statementBounds(sql: string): { start: number; end: number }[] {
  const bounds: { start: number; end: number }[] = [];
  let start: number | undefined;
  let end = 0;
  let index = skipIgnorable(sql, 0);
  while (index < sql.length) {
    if (sql.charAt(index) === ';') {
      if (start !== undefined) bounds.push({ start, end });
      start = undefined;
      index += 1;
    } else {
      start ??= index;
      index = endOfToken(sql, index);
      end = index;
    }
    index = skipIgnorable(sql, index);
  }
  if (start !== undefined) bounds.push({ start, end });
  return bounds;
}

/** The first word, in capitals, of each top-level statement that begins or ends a transaction. */
export function transactionControl(sql: string): string[] {
  return statementBounds(sql)
    .map(({ start }) => leadingWords(sql, start))
    .filter(controlsTransaction)
    .map(([first]) => first.toUpperCase());
}

/** Each top-level statement, without its `;`: comments inside a statement stay, those between statements go. */
export function splitStatements(sql: string): string[] {
  return statementBounds(sql).map(({ start, end }) => sql.slice(start, end));
}
