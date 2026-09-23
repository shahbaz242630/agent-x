// A3c (ADR-012 §2, ADR-007 §1): what a table that holds authority must look
// like in the database, checked on a real server against db/migrations
// (tooling/checks/authority-schema.db.test.ts). Each rule has a broken
// fixture that proves it fails (authority-checks.db.test.ts).
//
// A field grants, restores or limits authority (a status, a role, a limit, an
// expiry). The app reads one only through the audit module's verifiedState and
// writes one only through its record or changeStatus, which seal the row's
// state into the audit log. Those steps take the table's own description
// (@agentx/platform/db's SignedStateTable) and trust that the table beneath it
// is built to match. This is where that is checked, so a new authority table
// can't reach staging with a wall missing:
//
// - the signed-state columns are there, of the right type, and no unique key
//   covers them, or moving the pointer would be a key update and the row's
//   `FOR NO KEY UPDATE` lock could not hold it;
// - every declared field's column is of a type it is read as, or the canonical
//   text a seal is made from could read alike for two different values;
// - the app role can't delete a row (a deleted row takes its signed state out
//   of reach) or change a row's identity;
// - a status column is sealed like any other authority field, its allowed
//   values are the machine's states, and the database's own guard
//   (db/migrations/0004) carries exactly that machine's rules;
// - the table is one plain tenant table with row-level security forced, so
//   CI-06's walls (ADR-005) hold on it too.
//
// The checks read only the system catalogues, as the migration role, and
// change nothing. Two reference objects are built inside a transaction that is
// rolled back: a check constraint and a status guard written from the machine
// itself. Comparing what this server prints for them with what it prints for
// the real table means no rule here depends on how a Postgres version words a
// constraint or a trigger, only on the two agreeing (the same way CI-06
// compares the tenant policy with a reference policy).
import type pg from 'pg';

import { catalogueRows as rows, openCatalogue } from './catalogue.ts';
import type { TestDatabase } from './test-database.ts';

/** The type an authority field is read as: @agentx/platform/db's SignedFieldType. */
export type AuthorityFieldType = 'text' | 'uuid' | 'integer' | 'timestamptz';

/** One authority field: the column it is kept in, and the type it is read as. */
export interface AuthorityField {
  readonly column: string;
  readonly type: AuthorityFieldType;
}

/** One move a status machine allows, as the database's guard lists it. */
export interface AuthorityMove {
  readonly from: string;
  readonly to: string;
}

/**
 * What these checks need of a state machine: its states, the one a new row
 * starts in, and every move. The shared-kernel's defineStateMachine gives one,
 * and a StateMachine fits here whatever its states and events are, which
 * `StateMachine<string, string>` would not (its isFinal takes a state, so the
 * type is invariant in it).
 */
export interface AuthorityMachine {
  readonly name: string;
  readonly states: readonly string[];
  readonly initial: string;
  readonly moves: readonly AuthorityMove[];
}

/**
 * A table whose rows hold authority: the module's own SignedStateTable, and
 * the machine that rules its status when it has one. The registry of every
 * such table is tooling/authority-tables.ts.
 */
export interface AuthorityTable {
  /** Schema and table, as `schema.table`, in lower-case words. */
  readonly table: string;
  /** The type its rows are recorded as in the audit trail: each table has its own. */
  readonly subject: string;
  /** Every authority field, in the order they are sealed. */
  readonly fields: readonly AuthorityField[];
  /** The status machine, when the table has a status. */
  readonly status?: AuthorityMachine;
}

/** Names from our migrations: the shapes @agentx/platform/db accepts (signed-rows.ts, status.ts). */
const TABLE_NAME = /^[a-z][a-z0-9_]{0,62}\.[a-z][a-z0-9_]{0,62}$/;
const COLUMN_NAME = /^[a-z][a-z0-9_]{0,62}$/;
/** A subject type and a trigger name: lower-case words joined by single underscores. */
const LOWER_WORDS = /^[a-z]+(?:_[a-z]+)*$/;
/** A status: words in capitals, as defineStateMachine requires, so it is safe to write into a reference constraint. */
const STATE = /^[A-Z]+(?:_[A-Z]+)*$/;

const STATUS = 'status';
const VERSION = 'state_version';
const POINTER = 'state_event_id';
/** The columns that name the row, which nothing may change: the guard refuses them too (0004). */
const KEY = ['org_id', 'id'] as const;
/**
 * Postgres's `integer`, which `state_version` must be exactly: the app counts
 * versions up to 2,147,483,647 (signed-rows.ts's MAX_VERSION), so a smallint
 * would overflow in the database long before that, and a bigint would let a
 * version past what the app can hold. A declared `integer` field is freer
 * (COLUMN_TYPES), because there the reader only reads the value as text.
 */
const INTEGER = '23';
const GUARD = 'status_guard';
const GUARD_FUNCTION = 'state_rules.guard_status';
/** The table a trigger is on, as Postgres prints it in the trigger's definition. */
const ON_TABLE = / ON .+? FOR EACH ROW /;

/**
 * The column types each declared type may have, by the built-in types' fixed
 * IDs (pg_type's oid), which no name on the search path can stand in for.
 * These are the very numbers @agentx/platform/db's signed-rows.ts reads the
 * row with, so the check and the reader can't disagree; a printed type name
 * would, since it carries the modifier a column was declared with
 * (`timestamptz(3)` reads the same as `timestamptz`).
 */
const COLUMN_TYPES: Readonly<Record<AuthorityFieldType, readonly string[]>> = {
  text: ['25'],
  uuid: ['2950'],
  integer: ['21', '23', '20'],
  timestamptz: ['1184'],
};

/** The names of those types, for the message that refuses a column. */
const TYPE_NAMES: Readonly<Record<AuthorityFieldType, string>> = {
  text: 'text',
  uuid: 'uuid',
  integer: 'smallint, integer or bigint',
  timestamptz: 'timestamp with time zone',
};

/**
 * What the app role may hold on an authority table, and nothing else: it adds
 * rows and reads them, and changes the sealed fields column by column (checked
 * below). A right that isn't listed is refused whatever it is, so a privilege
 * we haven't thought about, or one a later Postgres adds, can't slip in. The
 * ones we have thought about say why the list is this short:
 * - DELETE or TRUNCATE would take a row's authority out of reach of the log
 *   that signed it (ADR-012 §2);
 * - TRIGGER would let the app write a trigger of its own that fires after the
 *   status guard has passed a row;
 * - REFERENCES would let it point a key of its own at these rows.
 * Nothing may be given to PUBLIC, which would hand the same right to every
 * role on the server, the backup role included (ADR-005 §3).
 */
const APP_MAY = ['SELECT', 'INSERT'];

const RELATION = `
  select pg_catalog.concat_ws('.', n.nspname, c.relname) as name, c.relkind::text as kind,
         c.relrowsecurity as rls, c.relforcerowsecurity as forced,
         exists (select 1 from pg_catalog.pg_inherits h where h.inhparent = c.oid) as has_children,
         exists (select 1 from pg_catalog.pg_inherits h where h.inhrelid = c.oid) as inherits,
         c.oid::pg_catalog.regclass::text as printed
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where pg_catalog.concat_ws('.', n.nspname, c.relname) = any($1::pg_catalog.text[])
    and c.relkind in ('r', 'p', 'v', 'm', 'f')
  order by n.nspname, c.relname
`;

/**
 * Every column of those tables: the type name, whether it is NOT NULL (a
 * Postgres 18 constraint that is NOT VALID marks the column while old rows may
 * still be null, so it doesn't count) and its default.
 *
 * **The NOT NULL expression is also in schema-checks.ts's COLUMNS query and
 * in the live schema guard's foreignKeys** (schema-guard.ts); the two CI
 * checkers share the connection and the query step, in catalogue.ts. A
 * Postgres version that changes how an unvalidated NOT NULL is recorded has to
 * be followed in all three.
 */
const COLUMNS = `
  select pg_catalog.concat_ws('.', n.nspname, c.relname) as table, a.attname::text as column,
         a.atttypid::pg_catalog.text as type_oid,
         pg_catalog.format_type(a.atttypid, a.atttypmod) as type,
         a.attgenerated <> '' or a.attidentity <> '' as given_by_the_database,
         a.attnotnull and not exists (
           select 1 from pg_catalog.pg_constraint k
           where k.conrelid = a.attrelid and k.contype = 'n' and not k.convalidated and k.conkey = array[a.attnum]
         ) as not_null,
         pg_catalog.pg_get_expr(d.adbin, d.adrelid) as default_expression
  from pg_catalog.pg_attribute a
  join pg_catalog.pg_class c on c.oid = a.attrelid
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  left join pg_catalog.pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
  where pg_catalog.concat_ws('.', n.nspname, c.relname) = any($1::pg_catalog.text[])
    and a.attnum > 0 and not a.attisdropped
  order by n.nspname, c.relname, a.attnum
`;

/**
 * The unique and exclusion keys of those tables, with their key columns in
 * order (columns only: a key built on expressions gives none, and is refused
 * on its own). A partial key rules out fewer rows than it seems to, so
 * whether it has a condition is read too.
 */
const KEYS = `
  select pg_catalog.concat_ws('.', n.nspname, c.relname) as table, ic.relname::text as key,
         i.indisexclusion as exclusion, i.indexprs is not null as expressions,
         i.indpred is not null as partial, i.indisvalid and i.indisready as enforced,
         (select pg_catalog.array_agg(a.attname::text order by k.position)
            from pg_catalog.unnest(i.indkey::pg_catalog.int2[]) with ordinality as k(attnum, position)
            join pg_catalog.pg_attribute a on a.attrelid = i.indrelid and a.attnum = k.attnum
           where k.position <= i.indnkeyatts) as columns
  from pg_catalog.pg_index i
  join pg_catalog.pg_class c on c.oid = i.indrelid
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  join pg_catalog.pg_class ic on ic.oid = i.indexrelid
  where pg_catalog.concat_ws('.', n.nspname, c.relname) = any($1::pg_catalog.text[])
    and (i.indisunique or i.indisexclusion)
  order by n.nspname, c.relname, ic.relname
`;

/**
 * What the app role may do to those tables, table by table and column by
 * column. A right given to PUBLIC is the app role's too, so it is read here as
 * well (CI-06 refuses every PUBLIC grant in our schemas, and no role of ours
 * is a member of another, so these are all the ways it can hold one).
 */
const APP_GRANTS = `
  select g.table, g.column, g.to_public, g.privilege
  from (
    select pg_catalog.concat_ws('.', n.nspname, c.relname) as table, '' as column,
           acl.grantee = 0 as to_public,
           case when acl.grantee = 0 then null else pg_catalog.pg_get_userbyid(acl.grantee)::text end as grantee,
           acl.privilege_type as privilege
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace,
    pg_catalog.aclexplode(c.relacl) acl
    where pg_catalog.concat_ws('.', n.nspname, c.relname) = any($1::pg_catalog.text[])
    union all
    select pg_catalog.concat_ws('.', n.nspname, c.relname), a.attname::text,
           acl.grantee = 0,
           case when acl.grantee = 0 then null else pg_catalog.pg_get_userbyid(acl.grantee)::text end,
           acl.privilege_type
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace,
    pg_catalog.aclexplode(a.attacl) acl
    where pg_catalog.concat_ws('.', n.nspname, c.relname) = any($1::pg_catalog.text[])
      and a.attnum > 0 and not a.attisdropped
  ) g
  where g.to_public or g.grantee = $2
  order by g.table collate "C", g.column collate "C", g.privilege collate "C", g.to_public
`;

/**
 * The triggers written on those tables: their definition as this server prints
 * it, whether they fire (`O` on origin, the usual; `A` always; `D` disabled;
 * `R` on a replica only) and the two type bits that say BEFORE and FOR EACH
 * ROW. Postgres's own foreign-key and constraint triggers are left out.
 */
const TRIGGERS = `
  select pg_catalog.concat_ws('.', n.nspname, c.relname) as table, t.tgname::text as name,
         pg_catalog.pg_get_triggerdef(t.oid) as definition, t.tgenabled::text as enabled,
         (t.tgtype & 1) <> 0 as for_each_row, (t.tgtype & 2) <> 0 as before,
         (t.tgtype & 4) <> 0 or (t.tgtype & 16) <> 0 as on_write
  from pg_catalog.pg_trigger t
  join pg_catalog.pg_class c on c.oid = t.tgrelid
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where pg_catalog.concat_ws('.', n.nspname, c.relname) = any($1::pg_catalog.text[]) and not t.tgisinternal
  order by n.nspname, c.relname, t.tgname collate "C"
`;

/** The check constraints on those tables, and whether each covers the status column. */
const CHECKS = `
  select pg_catalog.concat_ws('.', n.nspname, c.relname) as table, con.conname::text as name,
         pg_catalog.pg_get_constraintdef(con.oid) as definition,
         exists (
           select 1 from pg_catalog.unnest(con.conkey) as k(attnum)
           join pg_catalog.pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.attnum
           where a.attname = 'status'
         ) as on_status
  from pg_catalog.pg_constraint con
  join pg_catalog.pg_class c on c.oid = con.conrelid
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where pg_catalog.concat_ws('.', n.nspname, c.relname) = any($1::pg_catalog.text[]) and con.contype = 'c'
  order by n.nspname, c.relname, con.conname collate "C"
`;

/**
 * The statements that build one machine's reference objects, written by
 * Postgres itself from the machine (quote_ident and quote_literal), so no
 * state or name of ours is spliced into SQL by hand. A temporary table takes
 * the check constraint and the guard; DDL takes no bound parameters, so the
 * text is built and then run.
 */
const REFERENCE_STATEMENTS = `
  select pg_catalog.format('create temporary table %I (status text)', $1::pg_catalog.text) as table_statement,
         pg_catalog.format('alter table %I add constraint status_is_a_state check (status in (%s))',
           $1::pg_catalog.text,
           (select pg_catalog.string_agg(pg_catalog.quote_literal(state), ', ' order by position)
              from pg_catalog.unnest($2::pg_catalog.text[]) with ordinality as s(state, position))) as check_statement,
         pg_catalog.format('create trigger %I before insert or update on %I for each row execute function %s(%s)',
           $3::pg_catalog.text, $1::pg_catalog.text, $4::pg_catalog.text,
           (select pg_catalog.string_agg(pg_catalog.quote_literal(argument), ', ' order by position)
              from pg_catalog.unnest($5::pg_catalog.text[]) with ordinality as a(argument, position))) as guard_statement
`;

/** What this server prints for the reference check constraint and guard of one machine. */
const REFERENCE_DEFINITIONS = `
  select (select pg_catalog.pg_get_constraintdef(con.oid)
            from pg_catalog.pg_constraint con
            where con.conrelid = $1::pg_catalog.regclass and con.conname = 'status_is_a_state') as check_definition,
         (select pg_catalog.pg_get_triggerdef(t.oid)
            from pg_catalog.pg_trigger t
            where t.tgrelid = $1::pg_catalog.regclass and t.tgname = $2::pg_catalog.text) as guard_definition
`;

interface Relation {
  name: string;
  kind: string;
  rls: boolean;
  forced: boolean;
  has_children: boolean;
  inherits: boolean;
  /** The name this server prints for the table, which its triggers' definitions carry. */
  printed: string;
}

interface Column {
  table: string;
  column: string;
  /**
   * The built-in type's fixed ID, which is what the reader matches on, as
   * text: an oid is an unsigned 32-bit number, and narrowing one to Postgres's
   * signed integer would raise or come back negative on a database whose oid
   * counter has passed 2^31.
   */
  type_oid: string;
  /** The same type as this server prints it, for the messages. */
  type: string;
  /** True when the database gives the value itself (a generated or identity column), so no writer can set it. */
  given_by_the_database: boolean;
  not_null: boolean;
  default_expression: string | null;
}

interface Key {
  table: string;
  key: string;
  exclusion: boolean;
  expressions: boolean;
  partial: boolean;
  /** Valid and maintained: an index left behind by a failed CREATE INDEX CONCURRENTLY enforces nothing. */
  enforced: boolean;
  columns: string[] | null;
}

interface AppGrant {
  table: string;
  /** The column a column grant is on, or '' for a grant on the whole table. */
  column: string;
  to_public: boolean;
  privilege: string;
}

interface Trigger {
  table: string;
  name: string;
  definition: string;
  enabled: string;
  for_each_row: boolean;
  before: boolean;
  /** Fires on INSERT or UPDATE: a DELETE-only trigger can't rewrite a row being written. */
  on_write: boolean;
}

/** The trigger fires on writes here: on origin (the usual) or always, never disabled or replica-only. */
const fires = (trigger: Trigger): boolean => trigger.enabled === 'O' || trigger.enabled === 'A';

interface Check {
  table: string;
  name: string;
  definition: string;
  on_status: boolean;
}

/** One machine's reference objects as this server prints them, on the reference table they were built on. */
interface Reference {
  checkDefinition: string;
  guardDefinition: string;
}

interface Facts {
  relations: Relation[];
  columns: Column[];
  keys: Key[];
  grants: AppGrant[];
  triggers: Trigger[];
  checks: Check[];
  /** By table: each status table's own reference objects, built from its own machine. */
  references: Map<string, Reference>;
}

/**
 * Every way the database breaks the authority-table rules, or none. Connects
 * as the migration role and reads the system catalogues; the reference objects
 * it builds are rolled back, so it leaves the database as it was.
 */
export async function authorityProblems(database: TestDatabase, tables: readonly AuthorityTable[]): Promise<string[]> {
  const listed = listProblems(tables);
  // A registry that names a table twice, or a machine written wrong, would
  // make the facts below ambiguous, so nothing is read until it is sound.
  if (listed.length > 0) return listed;
  // No authority table listed (the fixtures that check the list alone): nothing to read.
  if (tables.length === 0) return [];
  const client = await openCatalogue(database);
  try {
    const facts = await readFacts(client, tables, database.server.roles.app.user);
    return tables.flatMap((table) => tableProblems(table, facts));
  } finally {
    await client.end();
  }
}

async function readFacts(client: pg.Client, tables: readonly AuthorityTable[], appRole: string): Promise<Facts> {
  const names = tables.map((table) => table.table);
  return {
    relations: await rows<Relation>(client, RELATION, [names]),
    columns: await rows<Column>(client, COLUMNS, [names]),
    keys: await rows<Key>(client, KEYS, [names]),
    grants: await rows<AppGrant>(client, APP_GRANTS, [names, appRole]),
    triggers: await rows<Trigger>(client, TRIGGERS, [names]),
    checks: await rows<Check>(client, CHECKS, [names]),
    references: await readReferences(client, tables),
  };
}

/**
 * The reference check constraint and guard for each table that has a status,
 * built and printed inside a transaction that is rolled back. They are kept
 * by table, not by machine: two tables may be ruled by machines of the same
 * name, and each must be judged against its own states and moves. Each gets a
 * temporary table of its own, so its guard can carry the trigger's real name.
 */
async function readReferences(client: pg.Client, tables: readonly AuthorityTable[]): Promise<Map<string, Reference>> {
  const withStatus = tables.flatMap((table) =>
    table.status === undefined ? [] : [[table.table, table.status] as const],
  );
  const references = new Map<string, Reference>();
  if (withStatus.length === 0) return references;
  // Two tables may be ruled by the same machine, and two machines may share a
  // name while differing: the reference objects are built once per machine
  // that is genuinely different (its states, first status and moves), and kept
  // against every table they belong to.
  const built = new Map<string, Reference>();
  const shapeOf = (machine: AuthorityMachine): string =>
    JSON.stringify([machine.states, machine.initial, machine.moves.map((move) => [move.from, move.to])]);
  await client.query('begin');
  try {
    let index = 0;
    for (const [name, machine] of withStatus) {
      const shape = shapeOf(machine);
      const already = built.get(shape);
      if (already !== undefined) {
        references.set(name, already);
        continue;
      }
      const reference = `authority_reference_${index++}`;
      const guardArguments = [machine.initial, ...machine.moves.map((move) => `${move.from}>${move.to}`)];
      const [statements] = await rows<{
        table_statement: string;
        check_statement: string;
        guard_statement: string;
      }>(client, REFERENCE_STATEMENTS, [reference, [...machine.states], GUARD, GUARD_FUNCTION, guardArguments]);
      if (statements === undefined) throw new Error('The reference statements were not built');
      for (const statement of [statements.table_statement, statements.check_statement, statements.guard_statement]) {
        // eslint-disable-next-line agentx/no-string-built-sql -- Postgres wrote this DDL itself from the machine (format with %I and %L above), and DDL takes no bound parameters.
        await client.query(statement);
      }
      const [printed] = await rows<{
        check_definition: string | null;
        guard_definition: string | null;
      }>(client, REFERENCE_DEFINITIONS, [reference, GUARD]);
      const missing = `The reference objects for ${name} were not created`;
      if (printed === undefined) throw new Error(missing);
      if (printed.check_definition === null || printed.guard_definition === null) throw new Error(missing);
      // The table a trigger is on is printed inside its definition, and a
      // temporary table is printed with a schema Postgres names itself, so the
      // real table's name is put in its place rather than swapped for a name
      // read another way.
      if (!ON_TABLE.test(printed.guard_definition)) {
        throw new Error(`The reference guard for ${name} was printed as ${printed.guard_definition}`);
      }
      const reading: Reference = {
        checkDefinition: printed.check_definition,
        guardDefinition: printed.guard_definition,
      };
      built.set(shape, reading);
      references.set(name, reading);
    }
    return references;
  } finally {
    await client.query('rollback');
  }
}

/**
 * The registry itself: each entry names a table once, with its own subject
 * type, authority fields that can be read and written, and a machine for its
 * status if it has one. These are the facts the SQL above is given, so they
 * are checked first.
 */
function listProblems(tables: readonly AuthorityTable[]): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const table of tables) {
    const at = (problem: string): void => {
      problems.push(`${table.table}: ${problem}`);
    };
    if (!TABLE_NAME.test(table.table)) at('an authority table is named schema.table, in lower-case words');
    if (seen.has(table.table)) at('is on the authority-table registry twice');
    seen.add(table.table);
    if (!LOWER_WORDS.test(table.subject)) at(`the subject type ${table.subject} must be lower-case words joined by _`);
    problems.push(...fieldListProblems(table));
    problems.push(...machineListProblems(table));
  }
  const subjects = new Map<string, string>();
  for (const table of tables) {
    const owner = subjects.get(table.subject);
    if (owner !== undefined && owner !== table.table) {
      problems.push(
        `${table.table}: records its rows as ${table.subject}, which ${owner} also does; each authority table has its own subject type, or one object's latest signed event could be found for another`,
      );
    } else subjects.set(table.subject, table.table);
  }
  return problems;
}

function fieldListProblems(table: AuthorityTable): string[] {
  const problems: string[] = [];
  const at = (problem: string): void => {
    problems.push(`${table.table}: ${problem}`);
  };
  if (table.fields.length === 0) at('an authority table seals at least one field');
  const columns = new Set<string>();
  for (const { column, type } of table.fields) {
    if (!COLUMN_NAME.test(column)) at(`the authority field ${column} must be a column in lower-case words`);
    else if (columns.has(column)) at(`the authority field ${column} is declared twice`);
    else if (column === VERSION || column === POINTER) {
      at(`${column} is a signed-state column, not an authority field: sealing it would need the seal it points at`);
    } else if ((KEY as readonly string[]).includes(column)) {
      at(
        `${column} names the row, so it is not an authority field: the seal already covers the organisation and the row's ID, and writing it would change the row's key`,
      );
    }
    if (!Object.hasOwn(COLUMN_TYPES, type)) at(`the authority field ${column} has no type the row is read as`);
    columns.add(column);
  }
  return problems;
}

function machineListProblems(table: AuthorityTable): string[] {
  const problems: string[] = [];
  const at = (problem: string): void => {
    problems.push(`${table.table}: ${problem}`);
  };
  const status = table.fields.find(({ column }) => column === STATUS);
  const machine = table.status;
  if (machine === undefined) {
    if (status !== undefined) {
      at('seals a status but names no state machine, so nothing would say which moves the database may allow');
    }
    return problems;
  }
  if (status === undefined) {
    at(
      `the ${machine.name} machine rules its status, so status must be one of its authority fields: an unsealed status could be flipped unseen (ADR-012 §2)`,
    );
  } else if (status.type !== 'text') {
    at(`the status field is read as ${status.type}; a status is text`);
  }
  if (!LOWER_WORDS.test(machine.name)) at(`the machine name ${machine.name} must be lower-case words joined by _`);
  if (machine.states.length === 0) at(`the ${machine.name} machine has no states`);
  const named = new Set([machine.initial, ...machine.states, ...machine.moves.flatMap((move) => [move.from, move.to])]);
  for (const state of [...named].filter((state) => !STATE.test(state))) {
    at(`the ${machine.name} machine's state ${state} must be words in capitals joined by _`);
  }
  if (!machine.states.includes(machine.initial)) {
    at(`the ${machine.name} machine starts in ${machine.initial}, which is not one of its states`);
  }
  for (const move of machine.moves.filter(
    (one) => !machine.states.includes(one.from) || !machine.states.includes(one.to),
  )) {
    at(`the ${machine.name} machine allows ${move.from}>${move.to}, which names a state it doesn't have`);
  }
  return problems;
}

/** Every rule about one authority table, in the order they are written above. */
function tableProblems(table: AuthorityTable, facts: Facts): string[] {
  const name = table.table;
  const at = (problem: string): string => `${name}: ${problem}`;
  const relation = facts.relations.find((one) => one.name === name);
  if (relation === undefined) {
    return [at('is on the authority-table registry, but no such table exists')];
  }
  const columns = facts.columns.filter((column) => column.table === name);
  return [
    ...relationProblems(relation).map(at),
    ...columnProblems(table, columns).map(at),
    ...keyProblems(facts.keys.filter((key) => key.table === name)).map(at),
    ...grantProblems(
      table,
      facts.grants.filter((grant) => grant.table === name),
    ).map(at),
    ...statusProblems(table, columns, facts, relation).map(at),
  ];
}

/** What a relation that isn't a plain table is, for the message that refuses it. */
const OTHER_KINDS: Readonly<Record<string, string>> = {
  v: 'a view',
  m: 'a materialized view',
  f: 'a foreign table',
};

/**
 * A plain table of its own, with the tenant walls forced on it (ADR-005 §2).
 * Neither partitions nor inheritance: a child table gets the parent's columns
 * and check constraints but not its triggers or its row-level security, and
 * its rows answer a read of the parent, so authority rows could be written
 * there with no guard, no tenant policy and no signed state at all.
 */
function relationProblems(relation: Relation): string[] {
  const problems: string[] = [];
  if (relation.kind === 'p') {
    problems.push(
      'is partitioned; a row moved between partitions is deleted and inserted, which would start it again at the first status and leave its signed state behind',
    );
  } else if (relation.kind !== 'r') {
    // RELATION asks for these kinds only, and the two above are handled, so
    // the lookup always finds one; the bare kind is a belt, not a case.
    problems.push(`is ${OTHER_KINDS[relation.kind] ?? relation.kind}, not a table, so nothing here holds`);
  }
  if (relation.has_children && relation.kind !== 'p') {
    problems.push(
      "has table inheritance children; a child gets this table's columns and checks but not its triggers or row security, and its rows answer a read of this table (ADR-005 §2, ADR-012 §2)",
    );
  }
  if (relation.inherits) {
    problems.push(
      'inherits from another table, so a read of that table answers with these rows, which its own walls never judged',
    );
  }
  if (!relation.rls) problems.push('row-level security is off (ADR-005 §2)');
  else if (!relation.forced) {
    problems.push("row-level security is enabled but not forced, so the table's owner bypasses it (ADR-005 §2)");
  }
  return problems;
}

/** The row's identity, the two signed-state columns, and every declared field's column. */
function columnProblems(table: AuthorityTable, columns: readonly Column[]): string[] {
  const problems: string[] = [];
  const of = (column: string): Column | undefined => columns.find((one) => one.column === column);
  for (const column of KEY) {
    const found = of(column);
    if (found === undefined)
      problems.push(`has no ${column} column; an authority row is named by its organisation and its own ID`);
    else if (!isType(found, 'uuid') || !found.not_null) problems.push(`${column} must be uuid NOT NULL`);
  }
  const version = of(VERSION);
  if (version === undefined)
    problems.push(`has no ${VERSION} column, which holds the version its latest signed event made`);
  else if (version.type_oid !== INTEGER || !version.not_null || version.default_expression !== '1') {
    problems.push(
      `${VERSION} must be integer NOT NULL DEFAULT 1, not ${version.type}${version.not_null ? '' : ' NULL'} DEFAULT ${version.default_expression ?? 'nothing'}`,
    );
  }
  const pointer = of(POINTER);
  if (pointer === undefined) problems.push(`has no ${POINTER} column, which points at that event`);
  else if (!isType(pointer, 'uuid')) problems.push(`${POINTER} must be uuid, not ${pointer.type}`);
  else if (pointer.not_null) {
    problems.push(`${POINTER} must take a null: a row is written before the event it will point at is recorded`);
  }
  for (const field of table.fields) {
    const found = of(field.column);
    if (found === undefined) problems.push(`has no ${field.column} column, which it declares as an authority field`);
    else if (!isType(found, field.type)) {
      problems.push(
        `the authority field ${field.column} is ${found.type}, which is not read as ${field.type} (${TYPE_NAMES[field.type]}): another type's text could read the same for another value`,
      );
    }
  }
  // The app writes every one of these itself: the key when it creates the row,
  // and the fields and the signed-state columns on every change. A column the
  // database gives itself (generated, or an identity column) can't be written
  // at all, so the row could never be created or sealed.
  for (const written of [...KEY, ...table.fields.map((field) => field.column), VERSION, POINTER]) {
    if (of(written)?.given_by_the_database === true) {
      problems.push(
        `${written} is a column the database gives itself (generated or an identity column), so nothing can write it and no row could be created or sealed`,
      );
    }
  }
  const hasStatus = columns.some((column) => column.column === STATUS);
  if (hasStatus && !table.fields.some((field) => field.column === STATUS)) {
    problems.push(
      `has a ${STATUS} column that it doesn't seal; a status that no signed event covers could be flipped unseen (ADR-012 §2)`,
    );
  }
  return problems;
}

/** The column's type is one the reader reads a field of that declared type with. */
const isType = (column: Column, declared: AuthorityFieldType): boolean =>
  COLUMN_TYPES[declared].includes(column.type_oid);

/**
 * One plain key on the row's identity, and no key over the signed-state
 * columns: the pointer is set after the audit head's lock, under the row's
 * `FOR NO KEY UPDATE`, which a key over those columns would turn into a key
 * update (ADR-006 §6).
 */
function keyProblems(keys: readonly Key[]): string[] {
  const problems: string[] = [];
  for (const key of keys) {
    const kind = key.exclusion ? 'exclusion constraint' : 'unique key';
    if (key.expressions || key.columns === null) {
      problems.push(
        `the ${kind} ${key.key} is built on expressions; an authority table's keys are over plain columns, so this check can see what they cover`,
      );
      continue;
    }
    const covered = key.columns.filter((column) => column === VERSION || column === POINTER);
    if (covered.length > 0) {
      problems.push(
        `the ${kind} ${key.key} covers ${covered.join(' and ')}; moving the pointer would then be a key update, which the row's FOR NO KEY UPDATE lock can't hold (ADR-006 §6)`,
      );
    }
  }
  const identity = keys.some(({ exclusion, partial, expressions, enforced, columns }) => {
    // An index a failed CREATE INDEX CONCURRENTLY left behind is in the
    // catalogue but enforces nothing, so it is no key at all.
    if (exclusion || partial || expressions || !enforced || columns === null) return false;
    return columns.length === KEY.length && KEY.every((column) => columns.includes(column));
  });
  if (!identity) {
    problems.push(
      `has no unique key on (${KEY.join(', ')}); without one, two rows could share a key and every read of the row would be unreadable`,
    );
  }
  return problems;
}

/**
 * What the app role may do: never delete or empty a row (its signed state
 * would be left with nothing to check), and change only the authority fields,
 * the status and the two signed-state columns, which record writes. A
 * table-wide UPDATE covers the row's identity too, so the grant is made column
 * by column.
 */
function grantProblems(table: AuthorityTable, grants: readonly AppGrant[]): string[] {
  const mayUpdate = new Set<string>([...table.fields.map((field) => field.column), VERSION, POINTER]);
  return grants.flatMap((grant) => {
    const on = grant.column === '' ? '' : ` on ${grant.column}`;
    // PUBLIC first: a right given to PUBLIC is every role's, the backup role's
    // included, so even the two the app may hold are refused there.
    if (grant.to_public) {
      return [
        `PUBLIC has ${grant.privilege}${on}; an authority table grants nothing to PUBLIC, which is every role on the server (ADR-005 §3)`,
      ];
    }
    if (APP_MAY.includes(grant.privilege)) return [];
    if (grant.privilege !== 'UPDATE') {
      return [
        `the app role has ${grant.privilege}${on}, which is not one of the rights the app has on an authority table (${APP_MAY.join(', ')}, and UPDATE of the sealed columns)`,
      ];
    }
    if (grant.column === '') {
      return [
        `the app role has UPDATE on the whole table, which covers ${KEY.join(' and ')}; grant UPDATE column by column (${[...mayUpdate].join(', ')})`,
      ];
    }
    return mayUpdate.has(grant.column)
      ? []
      : [`the app role has UPDATE on ${grant.column}, which is not an authority field or a signed-state column`];
  });
}

/**
 * The status, the machine and the database's guard: the allowed values are the
 * machine's states, the guard carries exactly its first status and its moves,
 * and no other trigger can rewrite the status after the guard has passed it.
 */
function statusProblems(table: AuthorityTable, columns: readonly Column[], facts: Facts, relation: Relation): string[] {
  const machine = table.status;
  const triggers = facts.triggers.filter((trigger) => trigger.table === table.table);
  if (machine === undefined) {
    return triggers
      .filter((trigger) => trigger.name === GUARD)
      .map(() => `has a ${GUARD} trigger but names no state machine, so nothing says which moves it should allow`);
  }
  const problems: string[] = [];
  const status = columns.find((column) => column.column === STATUS);
  if (status === undefined) problems.push(`has no ${STATUS} column, which the ${machine.name} machine rules`);
  else if (!isType(status, 'text') || !status.not_null)
    problems.push(`${STATUS} must be text NOT NULL, not ${status.type}${status.not_null ? '' : ' NULL'}`);
  const reference = facts.references.get(table.table);
  if (reference === undefined) throw new Error(`No reference objects were read for ${table.table}`);
  const checks = facts.checks.filter((check) => check.table === table.table);
  problems.push(...statusCheckProblems(machine, checks, reference));
  problems.push(...guardProblems(relation.printed, machine, triggers, reference));
  return problems;
}

/** Exactly one check constraint over the status, written as the machine's states. */
function statusCheckProblems(machine: AuthorityMachine, checks: readonly Check[], reference: Reference): string[] {
  const onStatus = checks.filter((check) => check.on_status);
  const [only, ...others] = onStatus;
  // The reference constraint, as this server prints it: the same shape the
  // real one is printed in, so the two halves of the message can be read
  // against each other. Written `CHECK (status IN (…))`, in the machine's own
  // order, it prints like this.
  const wanted = reference.checkDefinition;
  if (only === undefined || others.length > 0) {
    return [
      `has ${onStatus.length} check constraints over ${STATUS}; it has exactly one, listing the ${machine.name} machine's states: ${wanted}`,
    ];
  }
  return only.definition === wanted
    ? []
    : [
        `the check constraint ${only.name} is ${only.definition}, not the ${machine.name} machine's states in its own order: ${wanted}`,
      ];
}

/**
 * The status guard: the same trigger the machine would write, firing, and the
 * last BEFORE ROW trigger on the table by name. Postgres fires those in name
 * order, so one sorting after the guard could change the status the guard has
 * just passed; one sorting before it can only offer a change the guard then
 * judges, and a field it touched is caught when the row is read back before it
 * is sealed (record, A3b-2).
 */
function guardProblems(
  printed: string,
  machine: AuthorityMachine,
  triggers: readonly Trigger[],
  reference: Reference,
): string[] {
  const problems: string[] = [];
  // The name this server printed for the table itself, so a name it quotes
  // (a reserved word such as `user`) reads the same on both sides.
  const wanted = reference.guardDefinition.replace(ON_TABLE, () => ` ON ${printed} FOR EACH ROW `);
  const guard = triggers.find((trigger) => trigger.name === GUARD);
  if (guard === undefined) problems.push(`has no ${GUARD} trigger (db/migrations/0004): ${wanted}`);
  else {
    if (guard.definition !== wanted) {
      problems.push(`the ${GUARD} trigger is ${guard.definition}, not the ${machine.name} machine's rules: ${wanted}`);
    }
    if (!fires(guard)) {
      problems.push(
        `the ${GUARD} trigger doesn't fire on writes here (tgenabled ${guard.enabled}); it must be enabled`,
      );
    }
  }
  // A trigger that fires before a row is written could rewrite what the guard
  // has just passed. A DELETE-only trigger couldn't: it has no new row. One
  // that is switched off still counts, since switching it back on is a single
  // statement that changes no definition and adds nothing for a reviewer to
  // notice.
  const competing = triggers.filter((one) => one.before && one.for_each_row && one.on_write && one.name !== GUARD);
  for (const trigger of competing) {
    if (!LOWER_WORDS.test(trigger.name)) {
      problems.push(
        `the BEFORE ROW trigger ${trigger.name} isn't named in lower-case words, so which of it and ${GUARD} Postgres fires last can't be read off its name`,
      );
    } else if (trigger.name > GUARD) {
      problems.push(
        `the BEFORE ROW trigger ${trigger.name} sorts after ${GUARD}, so Postgres fires it last and it could rewrite a status the guard has passed`,
      );
    }
  }
  return problems;
}
