// A3e-1b (ADR-012 §2, SEC-DB-10): the running database's security-relevant
// catalogue, checked against what the migrations built — by the app itself, as
// the app role, on the app's own pool.
//
// **Why this exists.** The audit chain and the signed state both read the
// database through the very machinery an owner-level attacker can rewrite, so
// neither can see the rewrite. `agentx_owner` is no superuser, but it owns the
// tables, and on a real server (S32) every one of these worked:
//
//   ALTER POLICY tenant_isolation ON audit.events USING (true)  -- the wall goes
//   CREATE TRIGGER … BEFORE INSERT ON audit.events              -- a planted trigger
//   CREATE RULE … DO INSTEAD NOTHING                            -- a planted rule
//   ALTER TABLE audit.events NO FORCE ROW LEVEL SECURITY        -- the owner stops obeying it
//   GRANT UPDATE ON audit.events TO agentx_app                  -- a widened right
//   ALTER TABLE … RENAME; CREATE VIEW audit.events AS …         -- a table swapped for a view
//
// Each one changes what a query means while every row, hash and MAC still
// checks out. This is where they are seen.
//
// **What it is checked against.** SCHEMA_POLICY and the rules below, which ship
// in the image CI signs and a deploy verifies. The expectation must never live
// in the database, because the database is the thing the attacker controls.
// CI-06 checks the same policy against a freshly migrated database on Postgres
// 16 and 18, so the rules can't drift from db/migrations without CI going red.
//
// **What it can read.** Everything here is readable by an ordinary role —
// checked on 16 and 18 before it was written (pg_class, pg_namespace,
// pg_attribute, pg_policy, pg_trigger, pg_rewrite, pg_cast, pg_db_role_setting,
// pg_constraint; pg_authid is not, and is not needed). So no SECURITY DEFINER helper is
// required, which CI-06 forbids anyway.
//
// **What it deliberately does not do.** It never writes, never creates a
// reference object (the app role may not), and never echoes a value from the
// database into a problem — a problem names the rule and the object, so a log
// line can't carry tampered text out.
import { type Kysely, sql } from 'kysely';

import { SCHEMA_POLICY, type SchemaPolicy } from './schema-policy.ts';
import { OWN_COLUMNS, type SignedStateTable } from './signed-rows.ts';
import { TENANT_POLICY_EXPRESSION } from './tenant.ts';

/** The name every tenant table's one policy has (ADR-005 §2). */
const TENANT_POLICY = 'tenant_isolation';

/** The one trigger our schema is allowed, and the function it must call (0004_state_rules.sql, ADR-007 §1.1). */
const STATUS_GUARD = 'status_guard';
const STATUS_GUARD_FUNCTION = 'state_rules.guard_status';

/**
 * When the status guard must fire: BEFORE INSERT OR UPDATE, FOR EACH ROW.
 * Postgres's `tgtype` bits are ROW 1, BEFORE 2, INSERT 4, DELETE 8, UPDATE 16,
 * so 1 + 2 + 4 + 16 = 23.
 *
 * **The name and the function are not enough.** The owner can drop the guard
 * and put back one called `status_guard`, calling the same `guard_status`, but
 * BEFORE INSERT only — and every *move* between statuses then goes unchecked,
 * along with the key columns the guard holds still. Found by the A3e-1b review.
 */
const STATUS_GUARD_TYPE = 23;

/** What 0004 pins on the guard function, so no name inside it resolves anywhere else. */
const PINNED_FUNCTION_CONFIG = 'search_path=pg_catalog';

/**
 * The SHA-256 of `state_rules.guard_status`'s body, as 0004_state_rules.sql
 * wrote it. The owner can CREATE OR REPLACE the function without touching a
 * single table, and nothing else here would see it; comparing the hash covers
 * the whole body without this file carrying a copy. schema-guard.db.test.ts
 * proves this is the body on a freshly migrated database, so a change to 0004
 * fails there rather than on staging.
 */
const STATUS_GUARD_BODY = '52692e2d94ac490ceb626cc10024e4bb75fff4484ebd80fdf518cd34405cf246';

/**
 * Whether the status guard's arguments are the shape 0004 gives it: the status
 * a row is born in, then one FROM>TO for each move the machine allows.
 *
 * **Read by hand rather than by regular expression.** The first draft matched
 * the printed definition with a pattern whose nested quantifiers could
 * backtrack exponentially, and the text comes from the database — the one thing
 * an attacker here owns. A regular expression runs to completion on the event
 * loop, so a trigger defined to be pathological would have hung the whole
 * process, not merely the check, and the deadline could never fire because
 * nothing else would run. Found by CodeQL on the A3e-1b branch.
 *
 * Whether the arguments are the right ones *for that table's machine* is
 * A3c-1's question, which has the machine to compare them with; this is only
 * that they still look like a guard's.
 */
function guardArgumentsWellFormed(definition: string): boolean {
  const call = `${STATUS_GUARD_FUNCTION}(`;
  const open = definition.lastIndexOf(call);
  if (open === -1 || !definition.endsWith(')')) return false;
  const inside = definition.slice(open + call.length, -1);
  const parts = inside.split(', ');
  return parts.every((part, index) => {
    if (part.length < 3 || !part.startsWith("'") || !part.endsWith("'")) return false;
    const value = part.slice(1, -1);
    if (value === '' || value.includes("'")) return false;
    // The first is the first status; every later one is a move, FROM>TO.
    if (index === 0) return !value.includes('>');
    const move = value.split('>');
    return move.length === 2 && move[0] !== '' && move[1] !== '';
  });
}

/**
 * The rights the app role may hold on a table in an append-only schema, and on
 * one of the listed exceptions. Decoded privilege by privilege rather than
 * compared as a printed access list: Postgres 18 prints a MAINTAIN privilege
 * that 16 does not, so the raw text differs between versions for an unchanged
 * table.
 */
const APPEND_ONLY_RIGHTS = ['SELECT', 'INSERT'] as const;
const EXCEPTION_RIGHTS = ['SELECT', 'INSERT', 'UPDATE'] as const;

/**
 * The rights the app role may hold on any other table, tenant or global:
 * reading and writing rows, through the table's policies where it has them.
 * Never TRUNCATE, which empties a table past row security, every
 * organisation's rows at once; nor TRIGGER, REFERENCES or MAINTAIN, which would
 * let it plant a trigger, point a key at the rows, or lock and reindex them
 * (A3f-1; CI-06 holds the migrations to the same list).
 */
const APP_ROW_RIGHTS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as const;

/**
 * The rights the app role may hold on a narrow table as a whole: adding rows
 * and reading them. It changes a row only column by column, in the columns it
 * may change; UPDATE of the whole table would cover the row's identity too.
 * Never DELETE.
 * - An authority table (A3f-2) changes only in the sealed fields and the two
 *   signed-state columns, which is all record writes; a row gone takes its
 *   authority out of reach of the log that signed it (ADR-012 §2). A3c-1 holds
 *   the migrations to the same rule in CI.
 * - A fill-in table (A5b) changes only in the columns the schema policy lists:
 *   an idempotency key gone, or its hash changed, lets a retry do its write
 *   again. CI-06 holds the migrations to the same rule.
 */
const NARROW_RIGHTS = ['SELECT', 'INSERT'] as const;
/** What the app may hold on a narrow table's columns; UPDATE only on the ones it may change. */
const NARROW_COLUMN_RIGHTS = ['SELECT', 'INSERT', 'UPDATE'] as const;

/**
 * Every privilege Postgres can grant on a table: the ones the app role is
 * asked about. A privilege a later Postgres adds isn't asked about until it is
 * listed here; CI-06 refuses it in the migrations meanwhile, whatever it is.
 *
 * **MAINTAIN arrived in Postgres 17.** Asking `has_table_privilege` about it on
 * 16 is not a false answer but an error — "unrecognized privilege type" — which
 * would take the whole check down on the older version we support. So the list
 * is trimmed to what the server in front of us knows.
 */
const TABLE_RIGHTS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'] as const;

/** The first version that knows MAINTAIN (17.0), as `server_version_num` counts. */
const MAINTAIN_FROM = 170_000;

/**
 * The privileges Postgres lets you grant on single columns. A column grant is
 * invisible to has_table_privilege — GRANT UPDATE (details) ON audit.events
 * leaves the table-level answer false — so these are asked a second way.
 */
const COLUMN_RIGHTS = new Set(['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']);

/** The oldest version we support (16.0), as `server_version_num` counts. */
const OLDEST_SUPPORTED = 160_000;

/**
 * The server's version number, read once per check, as text and turned into a
 * number here rather than cast in SQL: a cast to integer is one more thing a
 * planted cast could answer for (see PresentRow). An answer that is no version
 * we support throws, so the check fails rather than asking an older server's
 * questions of a newer one (B1d-1 review).
 */
async function serverVersion<Schema>(db: Kysely<Schema>): Promise<number> {
  const { rows } = await sql<{ version: string }>`
    select pg_catalog.current_setting('server_version_num') as version
  `.execute(db);
  const version = Number(rows[0]?.version);
  if (!Number.isInteger(version) || version < OLDEST_SUPPORTED) {
    throw new Error('The server did not give a version this check supports');
  }
  return version;
}

function rightsThisServerKnows(version: number): string[] {
  return version >= MAINTAIN_FROM ? [...TABLE_RIGHTS] : TABLE_RIGHTS.filter((right) => right !== 'MAINTAIN');
}

export interface SchemaGuardOptions {
  /** The role the app connects as; its rights are the ones checked. */
  readonly appRole: string;
  /** The role that owns the database and everything the migrations make. */
  readonly ownerRole: string;
  /** The decisions to check against. Defaults to the product's own. */
  readonly policy?: SchemaPolicy;
  /**
   * The authority tables (ADR-012 §2), from the product's own list
   * (@agentx/core/authority-tables), each held to its narrower rights. None
   * by default.
   */
  readonly authorityTables?: readonly SignedStateTable[];
}

/**
 * One thing that differs from what the migrations built. The text names the
 * rule and the object, never a value read from the database.
 */
export type SchemaProblem = string;

interface RelationRow {
  readonly name: string;
  /**
   * `schema.table` unquoted, as a module names its table and as A3c-1 reads
   * it: `name` quotes a part that needs it (a reserved word such as `user`).
   */
  readonly plain: string;
  /** Unquoted, straight from the catalogue: re-parsing it out of `name` would break on a name needing quotes. */
  readonly schema: string;
  readonly kind: string;
  readonly rls: boolean;
  readonly forced: boolean;
  readonly owner: string;
  readonly partitioned: boolean;
  readonly inherits: boolean;
}

interface PolicyRow {
  readonly table: string;
  readonly name: string;
  readonly command: string;
  readonly expression: string | null;
  readonly check_expression: string | null;
  /**
   * Whether the policy applies to every role. A policy written with no TO
   * clause holds the single OID 0, which is PUBLIC; naming roles instead would
   * leave every role not named with no policy at all, and forced row security
   * would then let them see everything.
   */
  readonly everyone: boolean;
}

interface TriggerRow {
  readonly table: string;
  readonly name: string;
  readonly function: string;
  readonly enabled: string;
  /** Postgres's bitmask of when the trigger fires. */
  readonly type: number;
  /** The whole CREATE TRIGGER, which carries the arguments the guard is given. */
  readonly definition: string;
}

interface FunctionRow {
  readonly name: string;
  readonly definer: boolean;
  readonly owner: string;
  readonly config: string | null;
  readonly body: string;
}

interface RuleRow {
  readonly table: string;
  readonly name: string;
}

interface IndexRow {
  readonly table: string;
  readonly name: string;
  readonly is_unique: boolean;
  readonly is_valid: boolean;
  readonly partial: boolean;
  readonly covers_org: boolean;
}

interface GrantRow {
  readonly table: string;
  readonly privilege: string;
  /** Held on the whole table, or on at least one of its columns. */
  readonly level: 'table' | 'column';
}

interface PublicGrantRow {
  readonly table: string;
  readonly privilege: string;
}

interface ColumnRow {
  readonly table: string;
  readonly column: string;
}

/** One column of a foreign key, in the key's order, with the column it points at. */
interface ForeignKeyRow {
  readonly table: string;
  /** The key's name, which is unique on its table. */
  readonly name: string;
  readonly target: string;
  readonly column: string;
  readonly target_column: string;
  /**
   * False for a key added NOT VALID and never validated, whose rows from
   * before may break it, and for one made NOT ENFORCED (Postgres 18 on), which
   * Postgres always marks not valid, and whose triggers it drops.
   */
  readonly validated: boolean;
  /** Whether it has triggers, and every one Postgres made to enforce it still fires. */
  readonly triggers_on: boolean;
  /**
   * Whether this column is NOT NULL, validated: a key skips a row whose column
   * is null, so a null org_id would be an organisation the directory's list
   * leaves out (B1d-1 review).
   */
  readonly not_null: boolean;
}

/**
 * A yes-or-no answered in SQL. The count is compared to zero on the server and
 * comes back as a boolean, so nothing here goes through a cast to text.
 *
 * **That matters more than it looks.** The first draft of this file asked for
 * `count(*)::text`, and the database test that plants `CREATE CAST (bigint AS
 * text)` made that read return the planted function's answer instead of the
 * number — so the check for planted casts was itself blinded by a planted cast,
 * and reported nothing. Found by that test, S32.
 */
interface PresentRow {
  readonly present: boolean;
}

interface SchemaRow {
  readonly name: string;
  readonly owner: string;
}

/**
 * Our schemas: every one but Postgres's own. Postgres refuses a name starting
 * with pg_ to anyone but a superuser, so nothing can hide a table there. A
 * fragment rather than a line repeated in each query, composed in by the sql
 * tag, so every query below asks exactly the same question.
 */
const OURS = sql`n.nspname not in ('pg_catalog', 'information_schema') and not pg_catalog.starts_with(n.nspname, 'pg_')`;

/** The relation kinds that hold or show rows; anything else in our schemas is not a table at all. */
const ROW_KINDS = sql`c.relkind in ('r', 'p', 'v', 'm', 'f')`;

/** `schema.table`, quoted the way Postgres quotes an identifier that needs it. */
const QUALIFIED = sql`pg_catalog.format('%I.%I', n.nspname, c.relname)`;

/** Every relation in our schemas, with what would make it something other than a plain owned table. */
async function relations<Schema>(db: Kysely<Schema>): Promise<RelationRow[]> {
  const { rows } = await sql<RelationRow>`
    select ${QUALIFIED} as name,
           pg_catalog.concat_ws('.', n.nspname, c.relname) as plain,
           n.nspname as schema,
           c.relkind as kind,
           c.relrowsecurity as rls,
           c.relforcerowsecurity as forced,
           pg_catalog.pg_get_userbyid(c.relowner) as owner,
           c.relkind = 'p' as partitioned,
           -- relhassubclass is true if the table has, or once had, a child and
           -- never clears: the same stickiness this file avoids for
           -- relhasrules. Left in, a table that once had a partition attached
           -- and detached would refuse every start for ever, with nothing the
           -- app could do about it. pg_inherits is the accurate question.
           exists (
             select 1 from pg_catalog.pg_inherits i where i.inhrelid = c.oid or i.inhparent = c.oid
           ) as inherits
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS} and ${ROW_KINDS}
    order by 1
  `.execute(db);
  return [...rows];
}

async function schemas<Schema>(db: Kysely<Schema>): Promise<SchemaRow[]> {
  const { rows } = await sql<SchemaRow>`
    select n.nspname as name, pg_catalog.pg_get_userbyid(n.nspowner) as owner
    from pg_catalog.pg_namespace n
    where ${OURS}
    order by 1
  `.execute(db);
  return [...rows];
}

async function policies<Schema>(db: Kysely<Schema>): Promise<PolicyRow[]> {
  const { rows } = await sql<PolicyRow>`
    select ${QUALIFIED} as table,
           p.polname as name,
           p.polcmd as command,
           pg_catalog.pg_get_expr(p.polqual, p.polrelid) as expression,
           pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) as check_expression,
           p.polroles = '{0}'::pg_catalog.oid[] as everyone
    from pg_catalog.pg_policy p
    join pg_catalog.pg_class c on c.oid = p.polrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS}
    order by 1, 2
  `.execute(db);
  return [...rows];
}

/**
 * Triggers someone wrote, not the ones Postgres makes for a foreign key, with
 * the function each one calls. The function matters as much as the name: a
 * planted trigger called `status_guard` that ran something else would otherwise
 * pass by its name alone.
 */
async function triggers<Schema>(db: Kysely<Schema>): Promise<TriggerRow[]> {
  const { rows } = await sql<TriggerRow>`
    select ${QUALIFIED} as table,
           t.tgname as name,
           pg_catalog.format('%I.%I', fn.nspname, f.proname) as function,
           t.tgenabled as enabled,
           t.tgtype as type,
           pg_catalog.pg_get_triggerdef(t.oid) as definition
    from pg_catalog.pg_trigger t
    join pg_catalog.pg_class c on c.oid = t.tgrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_proc f on f.oid = t.tgfoid
    join pg_catalog.pg_namespace fn on fn.oid = f.pronamespace
    where ${OURS} and not t.tgisinternal
    order by 1, 2
  `.execute(db);
  return [...rows];
}

/**
 * Rewrite rules on our tables, read from pg_rewrite rather than from
 * `pg_class.relhasrules`: that flag is a hint Postgres sets when a rule is made
 * and **does not clear when the rule is dropped**, so it reports a rule that is
 * no longer there (the same trap `relhassubclass` set for the A3c-1 review).
 *
 * `_RETURN` is left out: it is the rule that *is* a view, and every view on the
 * server has one. A view standing where a table should be is already caught by
 * the relation kind, and with a clearer problem than "carries a rule".
 */
async function rules<Schema>(db: Kysely<Schema>): Promise<RuleRow[]> {
  const { rows } = await sql<RuleRow>`
    select ${QUALIFIED} as table, r.rulename as name
    from pg_catalog.pg_rewrite r
    join pg_catalog.pg_class c on c.oid = r.ev_class
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS} and r.rulename <> '_RETURN'
    order by 1, 2
  `.execute(db);
  return [...rows];
}

/**
 * Every function in our schemas, and what would let one act for someone else.
 *
 * Today that is 0004's status guard alone. The owner can rewrite any of them
 * with CREATE OR REPLACE, or mark one SECURITY DEFINER so it runs with the
 * owner's rights rather than the caller's, or unpin its search_path so a name
 * inside it resolves somewhere else — none of which touches a table, and none
 * of which the rest of this file would see. CI-06 forbids SECURITY DEFINER at
 * migration time; this is the same rule on the running database.
 *
 * The body is compared by its hash, so the whole of it is covered without this
 * file carrying a copy of it.
 */
async function functions<Schema>(db: Kysely<Schema>): Promise<FunctionRow[]> {
  const { rows } = await sql<FunctionRow>`
    select pg_catalog.format('%I.%I', n.nspname, p.proname) as name,
           p.prosecdef as definer,
           pg_catalog.pg_get_userbyid(p.proowner) as owner,
           pg_catalog.array_to_string(p.proconfig, ',') as config,
           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc, 'UTF8')), 'hex') as body
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where ${OURS}
    order by 1
  `.execute(db);
  return [...rows];
}

/** Every index on our tables, and what would stop it holding a tenant wall up. */
async function indexes<Schema>(db: Kysely<Schema>): Promise<IndexRow[]> {
  const { rows } = await sql<IndexRow>`
    select ${QUALIFIED} as table,
           ic.relname as name,
           i.indisunique as is_unique,
           i.indisvalid as is_valid,
           i.indpred is not null as partial,
           -- Key columns only: indkey also holds an INCLUDE payload, and a
           -- payload column separates nothing. A unique index on (id) that
           -- merely INCLUDEs org_id still makes id unique across every
           -- organisation. pg_get_indexdef answers per key column, 1-based.
           exists (
             select 1 from pg_catalog.generate_series(1, i.indnkeyatts) as k(n)
             where pg_catalog.pg_get_indexdef(i.indexrelid, k.n, true) = 'org_id'
           ) as covers_org
    from pg_catalog.pg_index i
    join pg_catalog.pg_class c on c.oid = i.indrelid
    join pg_catalog.pg_class ic on ic.oid = i.indexrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS}
    order by 1, 2
  `.execute(db);
  return [...rows];
}

/**
 * The app role's and PUBLIC's rights, one row per privilege actually held.
 * `has_table_privilege` answers for a role through every route (a direct grant,
 * PUBLIC, or a role it is a member of), which is what matters: the question is
 * what the app can do, not how it came to be able to. The role and the list of
 * privileges are bound values, never written into the text.
 *
 * **A column grant is a second question.** `GRANT UPDATE (details) ON
 * audit.events TO agentx_app` leaves the table-level answer false while the app
 * can still rewrite that column, so the privileges Postgres allows per column
 * are asked again through has_any_column_privilege and the two are unioned.
 * Found by the A3e-1b review.
 *
 * The `::text` here, and on the bound values in updatableColumns and
 * roleSettings, and the `'{0}'::pg_catalog.oid[]` in policies, are the only
 * ones left in this file, and they are not casts in the sense that matters:
 * they give a type to a bound parameter or a literal that arrives untyped,
 * which is an input coercion and never looks in `pg_cast`.
 * Every read of a catalogue column goes uncast, because a planted cast would
 * otherwise be able to change what this file sees — as one did in the first
 * draft (see PresentRow).
 */
async function grants<Schema>(db: Kysely<Schema>, appRole: string, version: number): Promise<GrantRow[]> {
  const known = rightsThisServerKnows(version);
  const columnWise = known.filter((right) => COLUMN_RIGHTS.has(right));
  const { rows } = await sql<GrantRow>`
    select ${QUALIFIED} as table, r.privilege, 'table' as level
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    cross join (select pg_catalog.unnest(${sql.val(known)}::text[]) as privilege) r
    where ${OURS} and ${ROW_KINDS}
      and pg_catalog.has_table_privilege(${appRole}::text, c.oid, r.privilege)
    union
    select ${QUALIFIED} as table, r.privilege, 'column' as level
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    cross join (select pg_catalog.unnest(${sql.val(columnWise)}::text[]) as privilege) r
    where ${OURS} and ${ROW_KINDS}
      and pg_catalog.has_any_column_privilege(${appRole}::text, c.oid, r.privilege)
    order by 1, 2
  `.execute(db);
  return [...rows];
}

/**
 * Rights held by PUBLIC, which is every role there is or will be.
 *
 * This cannot go through `has_table_privilege`: PUBLIC is not a role, and
 * Postgres refuses the name. It is read from the access list instead, where
 * PUBLIC is the grantee with OID 0. The app-role check above would not stand in
 * for this one either — a right PUBLIC holds that the app is *allowed* to hold
 * would pass there while every other role on the server quietly held it too.
 * The A3c-1 review found exactly that hole in its first draft.
 */
async function publicGrants<Schema>(db: Kysely<Schema>): Promise<PublicGrantRow[]> {
  const { rows } = await sql<PublicGrantRow>`
    select ${QUALIFIED} as table, acl.privilege_type as privilege
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    cross join pg_catalog.aclexplode(c.relacl) as acl
    where ${OURS} and ${ROW_KINDS} and acl.grantee = 0
    union
    -- Column grants live on the column, not the table, so relacl alone would
    -- miss GRANT SELECT (details) ON audit.events TO PUBLIC entirely.
    select ${QUALIFIED} as table, acl.privilege_type as privilege
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    cross join pg_catalog.aclexplode(a.attacl) as acl
    where ${OURS} and ${ROW_KINDS} and acl.grantee = 0
    order by 1, 2
  `.execute(db);
  return [...rows];
}

async function columns<Schema>(db: Kysely<Schema>): Promise<ColumnRow[]> {
  const { rows } = await sql<ColumnRow>`
    select ${QUALIFIED} as table, a.attname as column
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS} and ${ROW_KINDS} and a.attnum > 0 and not a.attisdropped
    order by 1, a.attnum
  `.execute(db);
  return [...rows];
}

/**
 * Every foreign key from our tables, and what would stop it holding (B1d-1).
 * The owner can drop one, or re-add it NOT VALID, or (from Postgres 18) make
 * it NOT ENFORCED, which Postgres marks not valid too, all without touching a
 * row; switching off the triggers
 * that enforce it takes a superuser, a tier above, as a planted cast does.
 * One row per column, in the key's order; unnest over two arrays is SQL
 * syntax, not a function, so it takes no pg_catalog.
 */
async function foreignKeys<Schema>(db: Kysely<Schema>): Promise<ForeignKeyRow[]> {
  const { rows } = await sql<ForeignKeyRow>`
    select ${QUALIFIED} as table,
           con.conname as name,
           pg_catalog.format('%I.%I', tn.nspname, t.relname) as target,
           fa.attname as column,
           ta.attname as target_column,
           con.convalidated as validated,
           exists (select 1 from pg_catalog.pg_trigger tr where tr.tgconstraint = con.oid)
             and not exists (
               select 1 from pg_catalog.pg_trigger tr where tr.tgconstraint = con.oid and tr.tgenabled <> 'O'
             ) as triggers_on,
           -- Postgres 18 can add a NOT NULL constraint NOT VALID, which marks the
           -- column NOT NULL while rows from before may still be null; 16 has none.
           fa.attnotnull and not exists (
             select 1 from pg_catalog.pg_constraint nn
             where nn.conrelid = fa.attrelid and nn.contype = 'n' and not nn.convalidated
               and nn.conkey = array[fa.attnum]
           ) as not_null
    from pg_catalog.pg_constraint con
    join pg_catalog.pg_class c on c.oid = con.conrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_class t on t.oid = con.confrelid
    join pg_catalog.pg_namespace tn on tn.oid = t.relnamespace
    cross join unnest(con.conkey, con.confkey) with ordinality as k(from_attnum, to_attnum, position)
    join pg_catalog.pg_attribute fa on fa.attrelid = con.conrelid and fa.attnum = k.from_attnum
    join pg_catalog.pg_attribute ta on ta.attrelid = con.confrelid and ta.attnum = k.to_attnum
    where ${OURS} and con.contype = 'f'
    order by 1, 2, k.position
  `.execute(db);
  return [...rows];
}

/** A foreign key whole: its rows, gathered in order. */
interface ForeignKey {
  readonly table: string;
  readonly target: string;
  readonly columns: readonly string[];
  readonly targetColumns: readonly string[];
  readonly holds: { readonly validated: boolean; readonly triggers_on: boolean };
  /** Whether every one of its columns is NOT NULL. */
  readonly notNull: boolean;
}

function wholeKeys(rows: readonly ForeignKeyRow[]): ForeignKey[] {
  const keys = new Map<string, ForeignKey & { columns: string[]; targetColumns: string[]; notNull: boolean }>();
  for (const row of rows) {
    // A table's key names are unique on it.
    const id = JSON.stringify([row.table, row.name]);
    const key = keys.get(id) ?? {
      table: row.table,
      target: row.target,
      columns: [],
      targetColumns: [],
      holds: { validated: row.validated, triggers_on: row.triggers_on },
      notNull: true,
    };
    key.columns.push(row.column);
    key.notNull &&= row.not_null;
    key.targetColumns.push(row.target_column);
    keys.set(id, key);
  }
  return [...keys.values()];
}

/**
 * Every column the app role may UPDATE, through any route: a column grant, the
 * whole table's, PUBLIC or a role it is a member of. has_any_column_privilege
 * says only that some column is writable; an authority table needs to know
 * which (A3f-2).
 */
async function updatableColumns<Schema>(db: Kysely<Schema>, appRole: string): Promise<ColumnRow[]> {
  const { rows } = await sql<ColumnRow>`
    select ${QUALIFIED} as table, a.attname as column
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS} and ${ROW_KINDS} and a.attnum > 0 and not a.attisdropped
      and pg_catalog.has_column_privilege(${appRole}::text, c.oid, a.attnum, 'UPDATE')
    order by 1, a.attnum
  `.execute(db);
  return [...rows];
}

/**
 * Casts beyond the ones Postgres ships. A planted cast on a built-in type could
 * make a stored value and the app's value read alike, which is how canonical
 * text (and so a state seal) could be made to match for two different values.
 * Only a superuser or a type's owner can create one — `agentx_owner` was
 * refused `CREATE CAST (bigint AS text)` on a real server (S32) — so this
 * watches a tier above the database owner. Everything Postgres ships has an
 * OID below FirstNormalObjectId; anything at or above it was made later.
 */
async function plantedCasts<Schema>(db: Kysely<Schema>): Promise<boolean> {
  const { rows } = await sql<PresentRow>`
    select pg_catalog.count(*) > 0 as present from pg_catalog.pg_cast where oid >= 16384
  `.execute(db);
  return rows[0]?.present === true;
}

/**
 * Settings that would reach a session of ours: one pinned to this database
 * (whatever role it names), or one pinned cluster-wide to a role we connect as.
 *
 * `pg_db_role_setting` is a **shared** catalogue — it covers the whole server,
 * not this database — so the scope has to be exact. A setting on our role *in
 * another database* reaches nothing of ours and is deliberately not flagged;
 * an early draft matched any role setting anywhere and reported another test's
 * database as drift in ours.
 *
 * A `search_path` set this way is the trap A3e-1a pins against, so one can no
 * longer take effect; its presence is still a sign someone tried, and another
 * setting (a statement timeout, an isolation level) could change how a
 * statement behaves.
 */
async function roleSettings<Schema>(db: Kysely<Schema>, roles: readonly string[]): Promise<boolean> {
  const { rows } = await sql<PresentRow>`
    select pg_catalog.count(*) > 0 as present
    from pg_catalog.pg_db_role_setting s
    where s.setdatabase = (
            select d.oid from pg_catalog.pg_database d where d.datname = pg_catalog.current_database()
          )
       or (
            s.setdatabase = 0
            and s.setrole in (
              select r.oid from pg_catalog.pg_roles r where r.rolname = any(${sql.val([...roles])}::text[])
            )
          )
  `.execute(db);
  return rows[0]?.present === true;
}

const quoted = (name: string): string => `"${name}"`;

/**
 * Everything about the live database that differs from what the migrations
 * built. An empty list means no drift. It never throws for a difference: a
 * database that refuses the read throws, and the caller treats that as a failed
 * check in its own right.
 */
export async function liveSchemaProblems<Schema>(
  db: Kysely<Schema>,
  { appRole, ownerRole, policy = SCHEMA_POLICY, authorityTables = [] }: SchemaGuardOptions,
): Promise<SchemaProblem[]> {
  const problems: SchemaProblem[] = [];
  const version = await serverVersion(db);
  const [
    allRelations,
    allSchemas,
    allPolicies,
    allTriggers,
    allFunctions,
    allRules,
    allIndexes,
    allGrants,
    forPublic,
    allColumns,
    writable,
    casts,
    settings,
    allForeignKeys,
  ] = await Promise.all([
    relations(db),
    schemas(db),
    policies(db),
    triggers(db),
    functions(db),
    rules(db),
    indexes(db),
    grants(db, appRole, version),
    publicGrants(db),
    columns(db),
    updatableColumns(db, appRole),
    plantedCasts(db),
    roleSettings(db, [appRole, ownerRole]),
    foreignKeys(db),
  ]);

  // `public` is Postgres's own schema, not one our migrations make: since
  // version 15 it belongs to the built-in `pg_database_owner`, which *is* the
  // database's owner by definition. 0001_baseline.sql takes every right on it
  // away from PUBLIC and no module uses it, and the pinned search_path means
  // nothing unqualified reaches it either way.
  const OWNS = new Set([ownerRole, 'pg_database_owner']);
  for (const schema of allSchemas) {
    if (!OWNS.has(schema.owner)) problems.push(`schema ${quoted(schema.name)} is owned by another role`);
  }

  const globalTables = new Set(Object.keys(policy.globalTables));
  const appendOnly = new Set(policy.appendOnlySchemas);
  const exceptions = new Set(Object.keys(policy.appendOnlyExceptions));

  for (const relation of allRelations) {
    const name = relation.name;
    // A view or a foreign table in place of a table means every read now goes
    // somewhere else, with the policies of whatever it points at.
    if (relation.kind !== 'r') problems.push(`${name} is no longer a plain table`);
    if (relation.partitioned) problems.push(`${name} is partitioned`);
    if (relation.inherits) problems.push(`${name} is in an inheritance tree`);
    if (relation.owner !== ownerRole) problems.push(`${name} is owned by another role`);

    if (!globalTables.has(name)) {
      if (!relation.rls) problems.push(`${name} does not have row-level security enabled`);
      // Without FORCE, the table's owner is not subject to its own policies.
      if (!relation.forced) problems.push(`${name} does not have row-level security forced`);
    }
  }

  const known = new Set(allRelations.map((relation) => relation.name));
  for (const listed of globalTables) {
    if (!known.has(listed)) problems.push(`${listed} is listed as a global table but is not there`);
  }

  // Policies: a tenant table has exactly the tenant policy, and its expression
  // is the one ADR-005 §2 gives.
  const byTable = new Map<string, PolicyRow[]>();
  for (const one of allPolicies) byTable.set(one.table, [...(byTable.get(one.table) ?? []), one]);
  for (const relation of allRelations) {
    const forTable = byTable.get(relation.name) ?? [];
    if (globalTables.has(relation.name)) {
      if (forTable.length > 0) problems.push(`${relation.name} is a global table but carries a policy`);
      continue;
    }
    if (forTable.length !== 1) {
      problems.push(`${relation.name} does not have exactly one row-security policy`);
      continue;
    }
    const [one] = forTable as [PolicyRow];
    if (one.name !== TENANT_POLICY) problems.push(`${relation.name}'s policy is not ${TENANT_POLICY}`);
    // '*' is ALL: one policy covering select, insert, update and delete alike.
    if (one.command !== '*') problems.push(`${relation.name}'s policy no longer covers every command`);
    if (!one.everyone) problems.push(`${relation.name}'s policy is limited to named roles`);
    if (one.expression !== TENANT_POLICY_EXPRESSION) problems.push(`${relation.name}'s policy reads differently`);
    if (one.check_expression !== null && one.check_expression !== TENANT_POLICY_EXPRESSION) {
      problems.push(`${relation.name}'s policy writes differently`);
    }
  }

  // Every tenant policy is also compared with the others. This needs no
  // constant and so no version to be right about: rewriting one table's wall
  // makes it differ from the rest, which is the attack as it would really
  // happen.
  const expressions = new Set(
    allPolicies.filter((one) => !globalTables.has(one.table)).map((one) => one.expression ?? ''),
  );
  if (expressions.size > 1) problems.push('the tenant policies no longer all read the same way');

  // Functions: the status guard is the only one our schemas hold, and it must
  // still be the function 0004 wrote, running with its caller's rights and
  // looking names up where 0004 pinned them.
  for (const fn of allFunctions) {
    if (fn.definer) problems.push(`${fn.name} runs with its owner's rights`);
    if (fn.owner !== ownerRole) problems.push(`${fn.name} is owned by another role`);
    if (fn.config !== PINNED_FUNCTION_CONFIG) problems.push(`${fn.name} does not pin its search_path`);
    if (fn.name === STATUS_GUARD_FUNCTION && fn.body !== STATUS_GUARD_BODY) {
      problems.push(`${fn.name} is not the function the migration wrote`);
    }
    if (fn.name !== STATUS_GUARD_FUNCTION) problems.push(`${fn.name} is a function our schemas should not hold`);
  }

  // A rewrite rule can turn any statement into a different one, silently.
  for (const rule of allRules) {
    problems.push(`${rule.table} carries the rewrite rule ${quoted(rule.name)}`);
  }

  // The only trigger our schema has is the status guard 0004 installs, and it
  // must still be the guard: a planted trigger given that name would otherwise
  // pass on its name alone. A switched-off guard is drift too — Postgres keeps
  // the row and stops running it, which is tampering that leaves no trace in
  // the table.
  for (const trigger of allTriggers) {
    if (trigger.name !== STATUS_GUARD || trigger.function !== STATUS_GUARD_FUNCTION) {
      problems.push(`${trigger.table} carries the trigger ${quoted(trigger.name)}`);
      continue;
    }
    // A guard that fires on fewer events than 0004 installs leaves the moves it
    // no longer sees unchecked, while still passing on its name.
    if (trigger.type !== STATUS_GUARD_TYPE) problems.push(`${trigger.table}'s ${STATUS_GUARD} fires at other times`);
    else if (!guardArgumentsWellFormed(trigger.definition)) {
      problems.push(`${trigger.table}'s ${STATUS_GUARD} is given other arguments`);
    }
    // Postgres keeps a switched-off trigger's row and stops running it, which
    // is tampering that leaves no trace in the table itself.
    if (trigger.enabled !== 'O') problems.push(`${trigger.table}'s ${STATUS_GUARD} is switched off`);
  }

  // Indexes. A plain index missing is a matter of speed, so it is not checked
  // here; a **unique** one is a wall. An invalid one enforces nothing while
  // still being listed, a partial one enforces nothing outside its condition,
  // and a unique key that leaves org_id out would make two organisations
  // collide (SEC-TEN-05, which CI-06 checks at migration time — this is the
  // same rule on the running database).
  for (const index of allIndexes) {
    if (!index.is_valid) problems.push(`${index.table}'s index ${quoted(index.name)} is not valid`);
    if (!index.is_unique) continue;
    if (index.partial) problems.push(`${index.table}'s unique index ${quoted(index.name)} is partial`);
    if (!globalTables.has(index.table) && !index.covers_org) {
      problems.push(`${index.table}'s unique index ${quoted(index.name)} does not cover org_id`);
    }
  }

  // Rights: an allow-list, so a privilege nobody thought about is a problem
  // rather than an omission.
  const held = new Map<string, Set<string>>();
  for (const grant of allGrants) {
    held.set(grant.table, (held.get(grant.table) ?? new Set()).add(grant.privilege));
  }
  // Tables held to narrower rights than a tenant table's, by the name the rest
  // of this check uses, each with the columns the app may change:
  // - an authority table (A3f-2): its sealed fields and its two signed-state
  //   columns, which is all record writes. Listed by its plain name, as the
  //   module wrote it and as CI's A3c-1 check matches it;
  // - a fill-in table (A5b): the columns the schema policy lists, by the name
  //   Postgres quotes. CI-06 checks the list itself (a reason, a tenant table
  //   outside the append-only schemas, only columns granted), and the policy
  //   reaches a server only through CI, so it is taken as it stands here.
  // A table on both lists may change only in the columns both allow.
  const byPlainName = new Map(allRelations.map((relation) => [relation.plain, relation.name]));
  const narrow = new Map<string, ReadonlySet<string>>();
  for (const table of authorityTables) {
    const name = byPlainName.get(table.table);
    if (name === undefined) problems.push(`${table.table} is listed as an authority table but is not there`);
    else narrow.set(name, new Set([...table.fields.map((field) => field.column), ...OWN_COLUMNS]));
  }
  for (const [name, entry] of Object.entries(policy.fillInTables)) {
    const asAuthority = narrow.get(name);
    if (!known.has(name)) {
      problems.push(`${name} is listed as a fill-in table but is not there`);
    } else if (asAuthority === undefined) {
      narrow.set(name, new Set(entry.columns));
    } else {
      problems.push(`${name} is listed as both an authority table and a fill-in table`);
      narrow.set(name, new Set(entry.columns.filter((column) => asAuthority.has(column))));
    }
  }
  for (const relation of allRelations) {
    // Held to their own list, below.
    if (narrow.has(relation.name)) continue;
    // A global table that names its rights is held to them, on the table and
    // on each column alike (B1d-1): the directory's list is added to and read.
    const listed = globalTables.has(relation.name) ? policy.globalTables[relation.name]?.appMay : undefined;
    const allowed = new Set<string>(
      listed ??
        (appendOnly.has(relation.schema)
          ? exceptions.has(relation.name)
            ? EXCEPTION_RIGHTS
            : APPEND_ONLY_RIGHTS
          : APP_ROW_RIGHTS),
    );
    for (const right of held.get(relation.name) ?? []) {
      if (!allowed.has(right)) problems.push(`${appRole} may ${right} on ${relation.name}`);
    }
  }
  // A narrow table: rows added and read, and changed only in the columns it
  // may change, each granted on its own.
  const writableIn = new Map<string, string[]>();
  for (const { table, column } of writable) writableIn.set(table, [...(writableIn.get(table) ?? []), column]);
  for (const [name, mayChange] of narrow) {
    const grantsOn = allGrants.filter((grant) => grant.table === name);
    const onTable = new Set(grantsOn.filter((grant) => grant.level === 'table').map((grant) => grant.privilege));
    for (const right of onTable) {
      if (!(NARROW_RIGHTS as readonly string[]).includes(right)) problems.push(`${appRole} may ${right} on ${name}`);
    }
    for (const grant of grantsOn) {
      // A right on the whole table shows on its columns too; it is named once, above.
      if (grant.level !== 'column' || onTable.has(grant.privilege)) continue;
      if (!(NARROW_COLUMN_RIGHTS as readonly string[]).includes(grant.privilege)) {
        problems.push(`${appRole} may ${grant.privilege} on columns of ${name}`);
      }
    }
    for (const column of writableIn.get(name) ?? []) {
      if (!mayChange.has(column)) problems.push(`${appRole} may UPDATE ${name}'s column ${quoted(column)}`);
    }
  }
  // Nothing in our schemas is PUBLIC's, whatever the privilege: a right every
  // role holds reaches the app as well, and reaches every role made later.
  for (const grant of forPublic) {
    problems.push(`PUBLIC may ${grant.privilege} on ${grant.table}`);
  }

  // Global tables are listed with their exact columns, so a new one is a
  // reviewed change rather than something that appears.
  const columnsOf = new Map<string, string[]>();
  for (const column of allColumns) columnsOf.set(column.table, [...(columnsOf.get(column.table) ?? []), column.column]);
  for (const [name, entry] of Object.entries(policy.globalTables)) {
    const live = columnsOf.get(name);
    if (live === undefined) continue;
    if (live.join(',') !== [...entry.columns].join(',')) problems.push(`${name} no longer has exactly its columns`);
  }
  for (const relation of allRelations) {
    if (globalTables.has(relation.name)) continue;
    if (!(columnsOf.get(relation.name) ?? []).includes('org_id')) problems.push(`${relation.name} has no org_id`);
  }

  // The foreign keys something rests on: each still there, from exactly its
  // columns to exactly the ones it points at, and holding. Any number of keys
  // may match; one that holds is enough. Its columns must be NOT NULL too: a
  // key lets a row with a null column through unchecked.
  const keys = wholeKeys(allForeignKeys);
  const same = (a: readonly string[], b: readonly string[]): boolean =>
    a.length === b.length && a.every((each, index) => each === b[index]);
  for (const required of policy.requiredForeignKeys) {
    const named = `${required.table}'s foreign key to ${required.references}`;
    const matching = keys.filter(
      (key) =>
        key.table === required.table &&
        key.target === required.references &&
        same(key.columns, required.columns) &&
        same(key.targetColumns, required.referencedColumns),
    );
    const [first] = matching;
    if (first === undefined) problems.push(`${named} is not there`);
    else if (!matching.some(({ holds }) => holds.validated && holds.triggers_on)) {
      if (!first.holds.validated) problems.push(`${named} is not validated`);
      if (!first.holds.triggers_on) problems.push(`${named} has a trigger switched off`);
    }
    if (first !== undefined && !first.notNull) problems.push(`${named} has a column that may be null`);
  }

  if (casts) problems.push('the database carries a cast Postgres did not ship');
  if (settings) problems.push('a setting is pinned to this database or to a role');

  return problems.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
