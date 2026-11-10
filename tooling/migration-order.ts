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
// describe (a trigger dropped and not made again, switched on or off, a function
// altered or dropped, SQL run from inside a DO block) is refused outright. Once a
// migration has built an entry, it must leave coming.json in that same change, so
// the list only ever holds what is still to come.
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
}

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
  ['0080', "PL-57's operator rule, shipped first in COMING_TRIGGERS when it was TypeScript"],
]);

/** One thing a migration does that the image before it reads as tampering unless told. */
export type Change =
  | { readonly kind: 'trigger'; readonly table: string; readonly name: string }
  | { readonly kind: 'body'; readonly function: string; readonly body: string }
  | { readonly kind: 'refused'; readonly what: string };

/** A statement as read: its words, lower case, with every body taken out (each a `$$`), and those bodies. */
interface Statement {
  readonly words: string;
  readonly bodies: readonly string[];
}

const DOLLAR_TAG = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/;

/** Where a quoted run that opened at `start` ends: past its closing quote, a doubled quote staying inside. */
function pastQuoted(sql: string, start: number, quote: string, backslashes: boolean): number {
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

/** The statements of a migration, with strings and quoted names kept, comments gone and bodies taken out. */
export function statements(sql: string): Statement[] {
  const found: Statement[] = [];
  let words = '';
  let bodies: string[] = [];
  let at = 0;
  const end = () => {
    const said = words.replaceAll(/\s+/g, ' ').trim();
    if (said !== '') found.push({ words: said.toLowerCase(), bodies });
    [words, bodies] = ['', []];
  };
  while (at < sql.length) {
    const char = sql[at] ?? '';
    const tag = char === '$' ? DOLLAR_TAG.exec(sql.slice(at))?.[0] : undefined;
    if (tag !== undefined && !/[A-Za-z0-9_]/.test(sql[at - 1] ?? '')) {
      const close = sql.indexOf(tag, at + tag.length);
      if (close === -1) throw new Error('a dollar-quoted body is never closed');
      bodies.push(sql.slice(at + tag.length, close));
      words += ' $$ ';
      at = close + tag.length;
    } else if (sql.startsWith('--', at) || sql.startsWith('/*', at)) {
      words += ' ';
      at = pastComment(sql, at);
    } else if (char === "'" || char === '"') {
      const escaped = char === "'" && /(?:^|[^A-Za-z0-9_])[Ee]$/.test(sql.slice(Math.max(0, at - 2), at));
      const past = pastQuoted(sql, at, char, escaped);
      words += sql.slice(at, past);
      at = past;
    } else if (char === ';') {
      end();
      at += 1;
    } else {
      words += char;
      at += 1;
    }
  }
  end();
  return found;
}

/** A name as Postgres folds it: unquoted, lower case (it is read from the lower-cased words). */
const named = (name: string): string => name.replaceAll('"', '');

/** The SHA-256 of a body, as schema-guard.ts reads Postgres's own (prosrc, in UTF-8). */
const hashOf = (body: string): string => createHash('sha256').update(body, 'utf8').digest('hex');

const NAME = String.raw`("[^"]+"|[a-z_][a-z0-9_$]*)(?:\.("[^"]+"|[a-z_][a-z0-9_$]*))?`;
const qualified = (match: RegExpExecArray, at: number): string =>
  named(match[at + 1] === undefined ? (match[at] ?? '') : `${match[at] ?? ''}.${match[at + 1]}`);

const CREATE_TABLE = new RegExp(String.raw`^create (?:unlogged )?table (?:if not exists )?${NAME}`);
const CREATE_TRIGGER = new RegExp(
  String.raw`^create (?:or replace )?(?:constraint )?trigger ${NAME} .*? on (?:only )?${NAME}(?: |$)`,
);
const DROP_TRIGGER = new RegExp(String.raw`^drop trigger (?:if exists )?${NAME} on ${NAME}`);
const CREATE_FUNCTION = new RegExp(String.raw`^create (?:or replace )?function ${NAME} ?\(`);
const ALTER_FUNCTION = new RegExp(String.raw`^(?:alter|drop) function (?:if exists )?${NAME}`);
const SWITCHED_TRIGGER = /^alter table .* (?:enable|disable)(?: replica| always)? trigger /;
const DYNAMIC = /\b(?:trigger|function|execute)\b/i;

/** What the migrations have built so far, read in turn, or what one migration builds. */
interface Built {
  readonly tables: Set<string>;
  /** Each function's body as last written, by its hash. */
  readonly bodies: Map<string, string>;
  /** Each trigger made, as `table name`. */
  readonly triggers: Set<string>;
}

const nothingBuilt = (): Built => ({ tables: new Set(), bodies: new Map(), triggers: new Set() });

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

/** A function written: its body's change against what earlier migrations wrote, or a new function. */
function written(name: string, bodies: readonly string[], before: Built, own: Built): Read {
  const [body] = bodies;
  if (body === undefined) return { kind: 'refused', what: `writes ${name} with no dollar-quoted body` };
  const hash = hashOf(body);
  own.bodies.set(name, hash);
  const was = before.bodies.get(name);
  if (was === undefined) return { kind: 'new', function: name, body: hash };
  return was === hash ? undefined : { kind: 'body', function: name, body: hash };
}

/** A trigger made or dropped, on a table this migration didn't itself build. */
function triggerRead(words: string, own: Built): Read {
  const made = CREATE_TRIGGER.exec(words);
  if (made !== null) {
    const [name, table] = [qualified(made, 1), qualified(made, 3)];
    own.triggers.add(`${table} ${name}`);
    return own.tables.has(table) ? undefined : { kind: 'trigger', table, name };
  }
  const dropped = DROP_TRIGGER.exec(words);
  if (dropped === null) return undefined;
  const [name, table] = [qualified(dropped, 1), qualified(dropped, 3)];
  return own.tables.has(table) ? undefined : { kind: 'dropped', table, name };
}

/** What one statement changes that the image before it must be told, given what earlier migrations built. */
function changeOf({ words, bodies }: Statement, before: Built, own: Built): Read {
  const table = CREATE_TABLE.exec(words);
  if (table !== null) {
    own.tables.add(qualified(table, 1));
    return undefined;
  }
  if (CREATE_TRIGGER.test(words) || DROP_TRIGGER.test(words)) return triggerRead(words, own);
  if (SWITCHED_TRIGGER.test(words)) return { kind: 'refused', what: 'switches a trigger on or off' };
  const fn = CREATE_FUNCTION.exec(words);
  if (fn !== null) return written(qualified(fn, 1), bodies, before, own);
  const altered = ALTER_FUNCTION.exec(words);
  if (altered !== null && before.bodies.has(qualified(altered, 1))) {
    return { kind: 'refused', what: `alters or drops ${qualified(altered, 1)}` };
  }
  if (/^do(?: language [a-z]+)? \$\$/.test(words) && bodies.some((body) => DYNAMIC.test(body))) {
    return { kind: 'refused', what: 'runs a DO block naming a trigger, a function or EXECUTE' };
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
}

/** Every migration read in order. */
export function readMigrations(migrations: readonly Migration[]): Reading {
  const built = nothingBuilt();
  const everWritten = new Set<string>();
  const changes = new Map<string, (Change | NewFunction)[]>();
  for (const migration of migrations.toSorted((a, b) => (a.name < b.name ? -1 : 1))) {
    const own = nothingBuilt();
    const read = statements(migration.sql).flatMap((one) => changeOf(one, built, own) ?? []);
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
    for (const [name, hash] of own.bodies) {
      built.bodies.set(name, hash);
      everWritten.add(`${name} ${hash}`);
    }
  }
  return { changes, bodies: built.bodies, triggers: built.triggers, everWritten };
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
  ];
}

const HASH = /^[0-9a-f]{64}$/;
const text = (value: unknown): value is string => typeof value === 'string' && value !== '';

/** coming.json read, or an error saying what is wrong with it; a commit without the file had nothing coming. */
export function parseComing(json: string | undefined): Coming {
  if (json === undefined) return { triggers: [], bodies: [] };
  const parsed = JSON.parse(json) as unknown;
  if (typeof parsed !== 'object' || parsed === null) throw new Error('coming.json must be an object');
  const { triggers, bodies } = parsed as Record<string, unknown>;
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
