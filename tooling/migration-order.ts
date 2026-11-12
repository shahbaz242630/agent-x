// Decision 49 (PL-66, Outstanding-Work AT6): no deliberate false tamper pages.
//
// **Why.** A release migrates first and swaps the API after (deploy/azure/release.ts),
// so while a migration runs, and until the swap, the image before it is the one
// checking the database (schema-guard.ts). Two things a migration can do read to that
// image as tampering at once: a trigger on a table it already knows, and a new body
// for a function it already knows. Neither can be softened by shape, as a planted
// trigger and a rewritten guard are exactly the attacks the guard is for. So that
// image must know each one exactly before the migration runs: it lands first, in
// packages/platform/src/db/coming.json, in a release of its own.
//
// **The rule, in plain words.** A migration may add or re-make a trigger on a table
// an earlier migration built, or write a new body over a function an earlier
// migration wrote, only if the code just before it already carried that trigger (by
// table and name) or that body (by function and SHA-256 hash) in coming.json. "Just
// before it" is, for a migration not yet on main, where its branch meets main; for
// one on main, the main commit before the one that brought it. So the coming entry
// and its migration can never arrive in one merge. A change no coming entry can
// describe (a trigger dropped and not made again, altered, switched on or off; a
// function, procedure or routine altered or dropped; a DO block naming a trigger,
// a routine or EXECUTE, however quoted) is refused outright, as is a trigger or
// routine named without its schema (its meaning hangs on the search_path) or in a
// form this reader can't parse whole. Quoted names keep their case. Once a
// migration has built an entry, it must leave coming.json in that same change, so
// the list only ever holds what is still to come.
//
// **A right granted to the operator's role (OR2b).** The live guard holds that role to
// exactly its list (schema-policy.ts operatorRights), so a new right on a table an
// earlier migration built reads to the image before it as a widened right: the alarm at
// once. So it lands first, the same way, in coming.json's operatorRights, as the guard
// prints it (`SELECT on column identity.registered_contacts.id`, `SELECT on
// audit.events`), and the migration granting it only after. A grant to the operator this
// reader can't print that way (on a schema, a function, a sequence, ALL, WITH GRANT
// OPTION, a name needing quotes), a right taken from it, anything else naming it, or a
// DO block naming it, is refused outright: the image before would raise the alarm, and
// no coming entry describes it. A grant on a table the same migration builds is that
// table's, which the guard already reads as a release's.
//
// tooling/checks/migration-order.test.ts holds every migration to this; the release
// (deploy/azure/release.ts) holds it again against what staging really runs, since
// GitHub may drop a waiting release, so the code before a merge isn't always what
// ran. Migrations up to 0081 were released before the rule: GRANDFATHERED, below.
//
// The SQL is read by hand, not by a parser: strings, quoted names, comments and
// dollar-quoted bodies are stepped over, so nothing inside them is read as a
// statement, and each body's hash is taken exactly as Postgres keeps it (prosrc,
// the text between its dollar quotes), which the check proves against the hashes
// schema-guard.ts holds. Nothing here imports a package: the release runs it with
// Node alone.
import { createHash } from 'node:crypto';

/** One migration file: its name (`NNNN_words.sql`) and its text. */
export interface Migration {
  readonly name: string;
  readonly sql: string;
}

/** A trigger the next release's migration adds, as coming.json lists it. */
interface ComingTrigger {
  readonly table: string;
  readonly name: string;
  readonly function: string;
  readonly body: string;
}

/** A body the next release's migration writes, as coming.json lists it. */
interface ComingBody {
  readonly function: string;
  readonly body: string;
}

/** What coming.json lists. */
export interface Coming {
  readonly triggers: readonly ComingTrigger[];
  readonly bodies: readonly ComingBody[];
  /** Rights the next release's migration grants the operator's role, as the live guard prints them; none when absent. */
  readonly operatorRights?: readonly string[];
}

/** The operator's command's own role (schema-guard.ts OPERATOR_ROLE): the role a coming right is granted to. */
const OPERATOR_ROLE = 'agentx_operator';

/** Where the list is kept, from the repository's root. */
export const COMING_FILE = 'packages/platform/src/db/coming.json';

/** Where the migrations are kept, from the repository's root. */
export const MIGRATIONS_FOLDER = 'db/migrations';

/** A migration file's name. */
export const MIGRATION_NAME = /^(\d{4})_[a-z0-9_]+\.sql$/;

/**
 * The migrations released before this rule, each by number with why it stands. The
 * check proves this is exactly the set it would refuse, so it can't hide a later one.
 */
export const GRANDFATHERED: ReadonlyMap<string, string> = new Map([
  ['0018', 'status_guard made again on identity.invitations (Phase 1), before any coming list existed'],
  ['0019', 'status_guard made again on identity.memberships (Phase 1), before any coming list existed'],
  ['0047', 'carried_version and a new fixed_at_creation on spend_requests.requests (Phase 3), before any coming list'],
  ['0054', 'made_once on limit_reservations.agent_zones (Phase 4 G3b), before any coming list existed'],
  ['0055', "guard_carried_version's new body (Phase 4 A3), before coming bodies existed"],
  ['0060', "guard_held_for_request's and guard_claim's new bodies (Phase 4 C3), before coming bodies existed"],
  ['0072', "D6's marks, the false alarm that made COMING_TRIGGERS, then in TypeScript"],
  ['0073', "D8's marks, shipped first in COMING_TRIGGERS when it was TypeScript, which this check can't read"],
  ['0075', "D9's marks, shipped first in COMING_TRIGGERS when it was TypeScript, which this check can't read"],
  ['0077', "D10's marks, shipped first in COMING_TRIGGERS when it was TypeScript, which this check can't read"],
  ['0079', "PL-57's operator role's first rights, before coming operator rights existed (OR2b)"],
  ['0080', "PL-57's operator rule, shipped first in COMING_TRIGGERS when it was TypeScript"],
]);

/** One thing a migration does that the image before it reads as tampering unless told. */
export type Change =
  | { readonly kind: 'trigger'; readonly table: string; readonly name: string }
  | { readonly kind: 'body'; readonly function: string; readonly body: string }
  | { readonly kind: 'operator'; readonly right: string }
  | { readonly kind: 'refused'; readonly what: string };

/** A statement as read: its words (unquoted ones lower case), with every body taken out (each a `$$`), and those bodies. */
interface Statement {
  readonly words: string;
  readonly bodies: readonly string[];
}

const DOLLAR_TAG = /^\$(?:[A-Za-z_\u0080-\uFFFF][A-Za-z0-9_\u0080-\uFFFF]*)?\$/;
/** A character that may stand inside an identifier, as Postgres's lexer allows ($ and non-ASCII among them). */
export const IDENTIFIER_CHAR = /[A-Za-z0-9_$\u0080-\uFFFF]/;

/** Where a quoted run that opened at `start` ends: past its closing quote, a doubled quote staying inside. */
export function pastQuoted(sql: string, start: number, quote: string, backslashes: boolean): number {
  let at = start + 1;
  while (at < sql.length) {
    const char = sql[at];
    if (backslashes && char === '\\') at += 2;
    else if (char !== quote) at += 1;
    else if (sql[at + 1] === quote) at += 2;
    else return at + 1;
  }
  throw new Error('a quote is never closed');
}

/** Where a comment that opened at `start` ends. Postgres nests block comments. */
function pastComment(sql: string, start: number): number {
  if (sql.startsWith('--', start)) {
    const end = sql.indexOf('\n', start);
    return end === -1 ? sql.length : end;
  }
  let depth = 0;
  let at = start;
  do {
    if (sql.startsWith('/*', at)) [depth, at] = [depth + 1, at + 2];
    else if (sql.startsWith('*/', at)) [depth, at] = [depth - 1, at + 2];
    else at += 1;
    if (at > sql.length) throw new Error('a comment is never closed');
  } while (depth > 0);
  return at;
}

/**
 * The statements of a migration, with strings and quoted names kept as written, comments gone and bodies taken out.
 * Every other word is lower-cased, as Postgres folds an unquoted name; a quoted one keeps its case, as Postgres does.
 */
export function statements(sql: string): Statement[] {
  const found: Statement[] = [];
  let words = '';
  let bodies: string[] = [];
  let at = 0;
  const end = () => {
    const said = words.replaceAll(/\s+/g, ' ').trim();
    if (said !== '') found.push({ words: said, bodies });
    [words, bodies] = ['', []];
  };
  while (at < sql.length) {
    const char = sql[at] ?? '';
    const tag = char === '$' ? DOLLAR_TAG.exec(sql.slice(at))?.[0] : undefined;
    if (tag !== undefined && !IDENTIFIER_CHAR.test(sql[at - 1] ?? '')) {
      const close = sql.indexOf(tag, at + tag.length);
      if (close === -1) throw new Error('a dollar-quoted body is never closed');
      bodies.push(sql.slice(at + tag.length, close));
      words += ' $$ ';
      at = close + tag.length;
    } else if (sql.startsWith('--', at) || sql.startsWith('/*', at)) {
      words += ' ';
      at = pastComment(sql, at);
    } else if (char === "'" || char === '"') {
      const escaped = char === "'" && /[Ee]/.test(sql[at - 1] ?? '') && !IDENTIFIER_CHAR.test(sql[at - 2] ?? '');
      const past = pastQuoted(sql, at, char, escaped);
      words += sql.slice(at, past);
      at = past;
    } else if (char === ';') {
      end();
      at += 1;
    } else {
      words += char.toLowerCase();
      at += 1;
    }
  }
  end();
  return found;
}

/** The SHA-256 of a body, as schema-guard.ts reads Postgres's own (prosrc, in UTF-8). */
const hashOf = (body: string): string => createHash('sha256').update(body, 'utf8').digest('hex');

/** One part of a name: quoted (its case kept, a doubled quote inside) or not (already lower case). */
const PART = String.raw`(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_$]*)`;
/** A name, its schema optional: each part captured. */
const NAME = String.raw`(${PART})(?:\.(${PART}))?`;

/** A name read: its parts unquoted and joined, and whether its schema was given. */
interface Named {
  readonly name: string;
  readonly qualified: boolean;
}

const unquoted = (part: string): string => (part.startsWith('"') ? part.slice(1, -1).replaceAll('""', '"') : part);
const nameAt = (match: RegExpExecArray, at: number): Named => {
  const [first = '', second] = [match[at], match[at + 1]];
  return second === undefined
    ? { name: unquoted(first), qualified: false }
    : { name: `${unquoted(first)}.${unquoted(second)}`, qualified: true };
};

/** A column a trigger fires on an update of. */
const COLUMNS = String.raw`${PART}(?: ?, ?${PART})*`;
/** One event a trigger fires on. */
const EVENT = String.raw`(?:insert|delete|truncate|update(?: of ${COLUMNS})?)`;

const CREATE_TABLE = new RegExp(String.raw`^create (?:unlogged )?table (?:if not exists )?${NAME}`);
const ANY_CREATE_TRIGGER = /^create (?:or replace )?(?:constraint )?trigger /;
/** Its whole head, word by word to the table, so a quoted column holding " on x " can't be read as the table. */
const CREATE_TRIGGER = new RegExp(
  String.raw`^create (?:or replace )?(?:constraint )?trigger ${NAME} (?:before|after|instead of) ${EVENT}(?: or ${EVENT})* on (?:only )?${NAME}(?: |$)`,
);
const DROP_TRIGGER = new RegExp(String.raw`^drop trigger (?:if exists )?${NAME} on ${NAME}(?: cascade| restrict)?$`);
const CREATE_FUNCTION = new RegExp(String.raw`^create (?:or replace )?(?:function|procedure) ${NAME} ?\(`);
/** An existing routine altered or dropped, under any of its three words; a drop may list several. */
const ALTER_ROUTINE = /^(?:alter|drop) (?:function|procedure|routine) (?:if exists )?(.*)$/;
const SWITCHED_TRIGGER = /^alter table .* (?:enable|disable)(?: replica| always)? trigger /;
const DYNAMIC = /\b(?:trigger|function|procedure|routine|execute)\b/i;
/**
 * A body that makes, alters or drops a trigger or routine, runs SQL it builds, or grants or revokes (S187 review: a
 * function the migration then calls could grant unseen): what it would do can't be read here.
 */
const BODY_DDL =
  /\b(?:create|alter|drop)\s+(?:or\s+replace\s+)?(?:constraint\s+)?(?:trigger|function|procedure|routine)\b|\bexecute\b(?!\s+(?:function|procedure)\b)|\b(?:grant|revoke)\b/i;
/**
 * A body's comments and strings, read left to right, taken out before BODY_DDL reads it: words there run nothing
 * (a string runs only through EXECUTE, refused on its own), so a message naming a "grant summary" is no grant (0089).
 */
const BODY_TEXT = /--[^\n]*|\/\*[\s\S]*?\*\/|(?<![A-Za-z0-9_$\u0080-￿])[eE]'(?:[^'\\]|\\.|'')*'|'(?:[^']|'')*'/g;
/** A table attached as a partition takes the parent's row triggers. */
const ATTACH_PARTITION = new RegExp(String.raw`^alter table (?:if exists )?(?:only )?\S+ attach partition ${NAME}`);

/** Each name in a list such as `a.b(int), c.d()`: commas inside the parentheses are an argument list's. */
function namesListed(list: string): Named[] {
  const items: string[] = [];
  let depth = 0;
  let item = '';
  for (const char of list) {
    if (char === '(') depth += 1;
    if (char === ')') depth -= 1;
    if (char === ',' && depth === 0) {
      items.push(item);
      item = '';
    } else item += char;
  }
  items.push(item);
  const head = new RegExp(String.raw`^ ?${NAME}`);
  return items.flatMap((one) => {
    const found = head.exec(one);
    return found === null ? [{ name: one.trim(), qualified: false }] : [nameAt(found, 1)];
  });
}

/** What the migrations have built so far, read in turn, or what one migration builds. */
interface Built {
  readonly tables: Set<string>;
  /** Each function's body as last written, by its hash. */
  readonly bodies: Map<string, string>;
  /** Each trigger made, as `table name`. */
  readonly triggers: Set<string>;
  /** Each right granted to the operator's role, as the live guard prints it. */
  readonly operatorRights: Set<string>;
}

const nothingBuilt = (): Built => ({
  tables: new Set(),
  bodies: new Map(),
  triggers: new Set(),
  operatorRights: new Set(),
});

/** A trigger dropped: a change only if the same migration doesn't make it again, which is known once it is read. */
interface Dropped {
  readonly kind: 'dropped';
  readonly table: string;
  readonly name: string;
}

/** A function a migration writes that no earlier one did: a coming trigger calling it must carry this body. */
export interface NewFunction {
  readonly kind: 'new';
  readonly function: string;
  readonly body: string;
}

type Read = Change | Dropped | NewFunction | undefined;

const refused = (what: string): Change => ({ kind: 'refused', what });

/** A name given without its schema: what it means hangs on the search_path, so no coming entry can match it. */
const unqualified = (what: string, { name }: Named): Change => refused(`${what} ${name} without its schema`);

/**
 * The body Postgres keeps (prosrc): the dollar-quoted text straight after AS, not one in a DEFAULT or SET before it.
 */
function bodyOf(words: string, bodies: readonly string[]): string | undefined {
  const as = words.search(/\bas \$\$/);
  if (as === -1) return undefined;
  return bodies[(words.slice(0, as).match(/\$\$/g) ?? []).length];
}

/** A function written: its body's change against what earlier migrations wrote, or a new function. */
function written(fn: Named, words: string, bodies: readonly string[], before: Built, own: Built): Read {
  if (!fn.qualified) return unqualified('writes', fn);
  const body = bodyOf(words, bodies);
  if (body === undefined) return refused(`writes ${fn.name} with no dollar-quoted body`);
  if (BODY_DDL.test(body.replaceAll(BODY_TEXT, ' ')))
    return refused(`writes ${fn.name} with a body that changes triggers or routines, runs built SQL, or grants`);
  const hash = hashOf(body);
  own.bodies.set(fn.name, hash);
  const was = before.bodies.get(fn.name);
  if (was === undefined) return { kind: 'new', function: fn.name, body: hash };
  return was === hash ? undefined : { kind: 'body', function: fn.name, body: hash };
}

/** A trigger made or dropped, on a table this migration didn't itself build. One the reader can't parse is refused. */
function triggerRead(words: string, own: Built): Read {
  const made = CREATE_TRIGGER.exec(words) ?? DROP_TRIGGER.exec(words);
  if (made === null) return refused('makes or drops a trigger in a form this check cannot read');
  const [name, table] = [nameAt(made, 1).name, nameAt(made, 3)];
  if (!table.qualified) return unqualified('names the table', table);
  if (ANY_CREATE_TRIGGER.test(words)) {
    own.triggers.add(`${table.name} ${name}`);
    return own.tables.has(table.name) ? undefined : { kind: 'trigger', table: table.name, name };
  }
  return own.tables.has(table.name) ? undefined : { kind: 'dropped', table: table.name, name };
}

/** Routines altered or dropped: refused for any an earlier migration wrote, or named without a schema. */
function routinesRead(list: string, before: Built): Read {
  const names = namesListed(list);
  const loose = names.find((one) => !one.qualified);
  if (loose !== undefined) return unqualified('alters or drops', loose);
  const known = names.find((one) => before.bodies.has(one.name));
  return known === undefined ? undefined : refused(`alters or drops ${known.name}`);
}

/** A name the live guard prints as it is written: lower case, nothing a quote would be needed for. */
const PLAIN_NAME = '[a-z_][a-z0-9_]*';
const PLAIN = new RegExp(`^${PLAIN_NAME}$`);
/** A privilege on a table, or on columns of it, each its own right in the guard's list; ALL is not read. */
const TABLE_PRIVILEGE = /^(select|insert|update|delete|truncate|references|trigger|maintain)(?: ?\((.+)\))?$/;
/** What a grant names that isn't a table: the guard prints those otherwise, and no coming entry describes them. */
const NOT_A_TABLE =
  /^(?:schema|sequence|function|procedure|routine|database|all|large object|foreign|domain|type|language|tablespace|parameter)\b/;

/** Each step through `text`, outside double quotes: where it is, and how deep in parentheses. */
function* outsideQuotes(text: string): Generator<{ readonly at: number; readonly depth: number }> {
  let [depth, quoted] = [0, false];
  for (let at = 0; at < text.length; at += 1) {
    const char = text[at];
    if (char === '"') quoted = !quoted;
    if (quoted || char === '"') continue;
    if (char === '(') depth += 1;
    if (char === ')') depth -= 1;
    yield { at, depth };
  }
}

/** `text` cut at each comma outside parentheses and double quotes, each part trimmed. */
function partsOf(text: string): string[] {
  const cuts = [...outsideQuotes(text)].filter(({ at, depth }) => depth === 0 && text[at] === ',').map(({ at }) => at);
  return [-1, ...cuts].map((cut, index) => text.slice(cut + 1, cuts[index] ?? text.length).trim());
}

/** Where ` word ` first stands in `text` outside parentheses and double quotes; -1 for nowhere. */
const wordAt = (text: string, word: string): number =>
  [...outsideQuotes(text)].find(({ at, depth }) => depth === 0 && text.startsWith(` ${word} `, at))?.at ?? -1;

/** A name part as Postgres keeps it, when the guard prints it as it is; undefined for any other. */
const plainPart = (part: string): string | undefined => {
  const name = unquoted(part.trim());
  return PLAIN.test(name) ? name : undefined;
};

/** The operator's role named anywhere, in any case. */
const OPERATOR_NAMED = new RegExp(String.raw`\b${OPERATOR_ROLE}\b`, 'i');

/** A Unicode-escaped identifier or string (`U&"…"`, `U&'…'`), which could spell the role unread. */
const UNICODE_ESCAPED = /\bu&["']/i;

/**
 * A string or a quoted name, read left to right so whichever opens first wins (S187 review: two chained passes let a
 * `"` inside a string, or an apostrophe inside a name, move where strings end). `E'…'` strings take backslash escapes,
 * an E starting one only where `statements()` (and Postgres) say so: not after an identifier's character (round 2).
 */
const QUOTED = /(?<![A-Za-z0-9_$\u0080-￿])[eE]'(?:[^'\\]|\\.|'')*'|'(?:[^']|'')*'|"(?:[^"]|"")*"/gs;

/**
 * A statement changing how later strings are read (`standard_conforming_strings`, `backslash_quote`): this reader
 * assumes Postgres's defaults, and every migration in a run shares one connection (round 2).
 */
const STRING_RULES = /\b(?:standard_conforming_strings|backslash_quote)\b/;

/**
 * Whether a statement's words, their strings taken out (quoted names kept), name the operator's role. A Unicode escape
 * counts as naming it, so its grant is refused as unreadable.
 */
const namesOperator = (words: string): boolean =>
  UNICODE_ESCAPED.test(words) ||
  OPERATOR_NAMED.test(words.replaceAll(QUOTED, (quoted) => (quoted.startsWith('"') ? quoted : "''")));

/** The rights one privilege of a grant gives on its tables, as the guard prints them; undefined for a form it can't. */
function rightsOf(privilege: string, tables: readonly string[]): string[] | undefined {
  const read = TABLE_PRIVILEGE.exec(privilege);
  if (read === null) return undefined;
  const [, name = '', listed] = read;
  const columns = listed === undefined ? [] : partsOf(listed).map(plainPart);
  if (columns.includes(undefined)) return undefined;
  const upper = name.toUpperCase();
  return tables.flatMap((table) =>
    listed === undefined ? [`${upper} on ${table}`] : columns.map((column) => `${upper} on column ${table}.${column}`),
  );
}

/**
 * The rights a GRANT naming the operator's role gives it, each as the live guard prints it, on tables this migration
 * didn't itself build; refused in any form this reader can't print exactly, or naming the role otherwise.
 */
function operatorGrantRead(words: string, own: Built): Read[] {
  const on = wordAt(words, 'on');
  const rest = on === -1 ? '' : words.slice(on + ' on '.length);
  const to = wordAt(rest, 'to');
  const granted = rest.slice(to + ' to '.length).replace(/ granted by .*$/, '');
  const handedOn = granted.endsWith(' with grant option');
  const roles = partsOf(granted.replace(/ with grant option$/, '')).map(plainPart);
  if (on === -1 || to === -1 || !roles.includes(OPERATOR_ROLE)) {
    return [refused("names the operator's role outside a grant this check can read")];
  }
  if (handedOn) return [refused("lets the operator's role hand a right on")];
  const objects = rest.slice(0, to);
  if (NOT_A_TABLE.test(objects)) return [refused("grants the operator's role a right on something other than a table")];
  const tables = partsOf(objects.replace(/^table /, '')).map((one) => one.split('.').map(plainPart));
  if (tables.some((parts) => parts.length !== 2 || parts.includes(undefined))) {
    return [refused("grants the operator's role a right on a table not named plainly with its schema")];
  }
  const named = tables.map((parts) => parts.join('.'));
  const rights = partsOf(words.slice('grant '.length, on)).map((privilege) => rightsOf(privilege, named));
  if (rights.includes(undefined)) return [refused("grants the operator's role a right this check can't print")];
  return rights.flat().flatMap((right) => {
    if (right === undefined) return [];
    own.operatorRights.add(right);
    // On a table this migration builds, the guard reads the right as that table's: a release's already.
    const table = right
      .replace(/^\w+ on (?:column )?/, '')
      .split('.')
      .slice(0, 2)
      .join('.');
    return own.tables.has(table) ? [] : [{ kind: 'operator' as const, right }];
  });
}

/** A statement naming the operator's role: its grant read, anything else refused, as the image before would alarm. */
function operatorRead(words: string, own: Built): Read[] | undefined {
  if (!namesOperator(words)) return undefined;
  if (words.startsWith('grant ')) return operatorGrantRead(words, own);
  if (words.startsWith('revoke ')) return [refused("takes a right from the operator's role")];
  return [refused("names the operator's role outside a grant this check can read")];
}

/** What one statement changes that the image before it must be told, given what earlier migrations built. */
function changeOf({ words, bodies }: Statement, before: Built, own: Built): Read {
  if (STRING_RULES.test(words) || bodies.some((body) => STRING_RULES.test(body))) {
    return refused('changes how strings are read, which this check assumes');
  }
  const table = CREATE_TABLE.exec(words);
  if (table !== null) {
    // IF NOT EXISTS over a table an earlier migration built does nothing in Postgres: it stays "known".
    const name = nameAt(table, 1).name;
    if (!before.tables.has(name)) own.tables.add(name);
    return undefined;
  }
  const attached = ATTACH_PARTITION.exec(words);
  if (attached !== null && before.tables.has(nameAt(attached, 1).name)) {
    return refused(`attaches ${nameAt(attached, 1).name} as a partition, which takes its parent's triggers`);
  }
  if (ANY_CREATE_TRIGGER.test(words) || words.startsWith('drop trigger ')) return triggerRead(words, own);
  if (words.startsWith('alter trigger ')) return refused('alters a trigger');
  if (SWITCHED_TRIGGER.test(words)) return refused('switches a trigger on or off');
  const fn = CREATE_FUNCTION.exec(words);
  if (fn !== null) return written(nameAt(fn, 1), words, bodies, before, own);
  const routines = ALTER_ROUTINE.exec(words);
  if (routines !== null) return routinesRead(routines[1] ?? '', before);
  // Any DO, however its body is quoted or its language named, that names a trigger, a routine or EXECUTE anywhere.
  if (/^do\b/.test(words) && [words, ...bodies].some((text) => DYNAMIC.test(text))) {
    return refused('runs a DO block naming a trigger, a function or EXECUTE');
  }
  // Or the operator's role, strings and all: a grant in a DO block is a grant as surely as one outside it.
  if (/^do\b/.test(words) && [words, ...bodies].some((text) => OPERATOR_NAMED.test(text))) {
    return refused("runs a DO block naming the operator's role");
  }
  return undefined;
}

/** What the migrations built, and what each changed that the image before it must be told, read in order. */
export interface Reading {
  readonly changes: ReadonlyMap<string, readonly (Change | NewFunction)[]>;
  /** Each function's body as last written. */
  readonly bodies: ReadonlyMap<string, string>;
  /** Each trigger ever made, as `table name`. */
  readonly triggers: ReadonlySet<string>;
  /** Each body ever written, as `function hash`. */
  readonly everWritten: ReadonlySet<string>;
  /** Each right ever granted to the operator's role, as the live guard prints it. */
  readonly operatorRights: ReadonlySet<string>;
}

/** What one statement changes: a statement naming the operator's role is read for that alone. */
const changesOf = (statement: Statement, before: Built, own: Built): Read[] =>
  operatorRead(statement.words, own) ?? [changeOf(statement, before, own)];

/** Every migration read in order. */
export function readMigrations(migrations: readonly Migration[]): Reading {
  const built = nothingBuilt();
  const everWritten = new Set<string>();
  const changes = new Map<string, (Change | NewFunction)[]>();
  for (const migration of migrations.toSorted((a, b) => (a.name < b.name ? -1 : 1))) {
    const own = nothingBuilt();
    const read = statements(migration.sql).flatMap((one) => changesOf(one, built, own).flatMap((each) => each ?? []));
    changes.set(
      migration.name,
      read.flatMap((one): (Change | NewFunction)[] => {
        if (one.kind !== 'dropped') return [one];
        // Made again in the same file, it is that trigger's change, read above.
        if (own.triggers.has(`${one.table} ${one.name}`)) return [];
        return [{ kind: 'refused', what: `drops ${one.name} on ${one.table}` }];
      }),
    );
    for (const table of own.tables) built.tables.add(table);
    for (const made of own.triggers) built.triggers.add(made);
    for (const right of own.operatorRights) built.operatorRights.add(right);
    for (const [name, hash] of own.bodies) {
      built.bodies.set(name, hash);
      everWritten.add(`${name} ${hash}`);
    }
  }
  return { changes, bodies: built.bodies, triggers: built.triggers, everWritten, operatorRights: built.operatorRights };
}

/** Why a change the code before a migration didn't carry as coming is refused, or nothing when it did. */
export function unshipped(change: Change | NewFunction, coming: Coming): string | undefined {
  switch (change.kind) {
    case 'refused':
      return `${change.what}: no coming entry can describe that, so the image before it would raise the tamper alarm`;
    case 'trigger':
      return coming.triggers.some(({ table, name }) => table === change.table && name === change.name)
        ? undefined
        : `adds ${change.name} on ${change.table}, which the code before it didn't carry in coming.json's triggers`;
    case 'operator':
      return (coming.operatorRights ?? []).includes(change.right)
        ? undefined
        : `grants the operator's role ${change.right}, which the code before it didn't carry in coming.json's operatorRights`;
    case 'body':
      return [...coming.bodies, ...coming.triggers].some(
        (one) => one.function === change.function && one.body === change.body,
      )
        ? undefined
        : `writes a new body for ${change.function}, which the code before it didn't carry in coming.json's bodies`;
    case 'new': {
      const calling = coming.triggers.filter((one) => one.function === change.function);
      return calling.length === 0 || calling.some((one) => one.body === change.body)
        ? undefined
        : `writes ${change.function} with another body than the coming trigger calling it carries`;
    }
  }
}

/**
 * Each coming entry the migrations have already built, or that names nothing they built: once built it must leave
 * the list in the same change (it would only widen what an image accepts), and one naming no known function is junk.
 */
export function leftBehind(coming: Coming, reading: Reading): string[] {
  return [
    ...coming.triggers
      .filter(({ table, name }) => reading.triggers.has(`${table} ${name}`))
      .map(({ table, name }) => `coming trigger ${name} on ${table} is already built: move it out of coming.json`),
    ...coming.bodies
      .filter((one) => reading.everWritten.has(`${one.function} ${one.body}`))
      .map((one) => `coming body for ${one.function} is already written: take it out of coming.json`),
    ...coming.bodies
      .filter((one) => !reading.bodies.has(one.function))
      .map((one) => `coming body for ${one.function} names no function the migrations wrote`),
    ...(coming.operatorRights ?? [])
      .filter((right) => reading.operatorRights.has(right))
      .map((right) => `coming operator right ${right} is already granted: take it out of coming.json`),
  ];
}

const HASH = /^[0-9a-f]{64}$/;
const text = (value: unknown): value is string => typeof value === 'string' && value !== '';
/** Postgres's table privileges, as the guard prints them: their names, not commands. */
const TABLE_PRIVILEGES = 'SELECT|INSERT|UPDATE|DELETE|TRUNCATE|REFERENCES|TRIGGER|MAINTAIN';

/** A coming operator right as the live guard prints one: a privilege on a table, or on a column of one, named plainly. */
const OPERATOR_RIGHT = new RegExp(
  String.raw`^(?:(?:${TABLE_PRIVILEGES}) on ${PLAIN_NAME}\.${PLAIN_NAME}` +
    String.raw`|(?:SELECT|INSERT|UPDATE|REFERENCES) on column ${PLAIN_NAME}\.${PLAIN_NAME}\.${PLAIN_NAME})$`,
);

/** The coming operator rights a coming.json lists, each as the guard prints one; none for a file from before them. */
function operatorRightsOf(listed: unknown): string[] {
  if (listed === undefined) return [];
  if (!Array.isArray(listed) || !listed.every((one) => typeof one === 'string' && OPERATOR_RIGHT.test(one))) {
    throw new Error(
      "coming.json's operatorRights lists rights as the guard prints them, such as SELECT on column a.b.c",
    );
  }
  return listed as string[];
}

/** coming.json read, or an error saying what is wrong with it; a commit without the file had nothing coming. */
export function parseComing(json: string | undefined): Coming {
  if (json === undefined) return { triggers: [], bodies: [], operatorRights: [] };
  const parsed = JSON.parse(json) as unknown;
  if (typeof parsed !== 'object' || parsed === null) throw new Error('coming.json must be an object');
  const { triggers, bodies, operatorRights } = parsed as Record<string, unknown>;
  if (!Array.isArray(triggers) || !Array.isArray(bodies)) throw new Error('coming.json lists triggers and bodies');
  const entry = (one: unknown, fields: readonly string[]): Record<string, unknown> => {
    const fieldsOf = typeof one === 'object' && one !== null ? (one as Record<string, unknown>) : {};
    if (!fields.every((field) => text(fieldsOf[field])) || !HASH.test(String(fieldsOf.body))) {
      throw new Error(`each coming entry needs ${fields.join(', ')}, its body a SHA-256 in lower-case hex`);
    }
    return fieldsOf;
  };
  return {
    triggers: triggers.map((one) => {
      const { table, name, function: fn, body } = entry(one, ['table', 'name', 'definition', 'function', 'body']);
      return { table: String(table), name: String(name), function: String(fn), body: String(body) };
    }),
    bodies: bodies.map((one) => {
      const { function: fn, body } = entry(one, ['function', 'body']);
      return { function: String(fn), body: String(body) };
    }),
    operatorRights: operatorRightsOf(operatorRights),
  };
}

/**
 * Each refusal for the migrations `added`, read against all `migrations` (theirs and every earlier one) and the coming
 * list `before` each: the release's gate and the check's alike. A grandfathered migration is never refused. The list
 * before one is read only when it changes something, so the history is needed only then.
 */
export function refusals(
  migrations: readonly Migration[],
  added: readonly string[],
  before: (migration: string) => Coming,
  grandfathered: ReadonlyMap<string, string> = GRANDFATHERED,
): string[] {
  const { changes } = readMigrations(migrations);
  return added
    .filter((name) => !grandfathered.has(name.slice(0, 4)))
    .flatMap((name) => {
      const found = changes.get(name) ?? [];
      if (found.length === 0) return [];
      const coming = before(name);
      return found.flatMap((change) => {
        const refused = unshipped(change, coming);
        return refused === undefined ? [] : [`${name} ${refused}`];
      });
    });
}
