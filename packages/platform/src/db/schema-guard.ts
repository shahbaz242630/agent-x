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
// pg_authid is not, and is not needed). So no SECURITY DEFINER helper is
// required, which CI-06 forbids anyway.
//
// **What it deliberately does not do.** It never writes, never creates a
// reference object (the app role may not), and never echoes a value from the
// database into a problem — a problem names the rule and the object, so a log
// line can't carry tampered text out.
import { type Kysely, sql } from 'kysely';

import { SCHEMA_POLICY, type SchemaPolicy } from './schema-policy.ts';
import { TENANT_POLICY_EXPRESSION } from './tenant.ts';

/** The name every tenant table's one policy has (ADR-005 §2). */
const TENANT_POLICY = 'tenant_isolation';

/**
 * The rights the app role may hold on a table in an append-only schema, and on
 * one of the listed exceptions. Decoded privilege by privilege rather than
 * compared as a printed access list: Postgres 18 prints a MAINTAIN privilege
 * that 16 does not, so the raw text differs between versions for an unchanged
 * table.
 */
const APPEND_ONLY_RIGHTS = ['SELECT', 'INSERT'] as const;
const EXCEPTION_RIGHTS = ['SELECT', 'INSERT', 'UPDATE'] as const;

/** Every privilege Postgres can grant on a table, so a new one shows up as unexpected rather than being missed. */
const TABLE_RIGHTS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'] as const;

export interface SchemaGuardOptions {
  /** The role the app connects as; its rights are the ones checked. */
  readonly appRole: string;
  /** The role that owns the database and everything the migrations make. */
  readonly ownerRole: string;
  /** The decisions to check against. Defaults to the product's own. */
  readonly policy?: SchemaPolicy;
}

/**
 * One thing that differs from what the migrations built. The text names the
 * rule and the object, never a value read from the database.
 */
export type SchemaProblem = string;

interface RelationRow {
  readonly name: string;
  readonly kind: string;
  readonly rls: boolean;
  readonly forced: boolean;
  readonly has_rules: boolean;
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
  readonly roles: string | null;
}

interface TriggerRow {
  readonly table: string;
  readonly name: string;
}

interface GrantRow {
  readonly table: string;
  readonly grantee: string;
  readonly privilege: string;
}

interface ColumnRow {
  readonly table: string;
  readonly column: string;
}

interface CountRow {
  readonly count: string;
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
async function relations(db: Kysely<unknown>): Promise<RelationRow[]> {
  const { rows } = await sql<RelationRow>`
    select ${QUALIFIED} as name,
           c.relkind::text as kind,
           c.relrowsecurity as rls,
           c.relforcerowsecurity as forced,
           c.relhasrules as has_rules,
           pg_catalog.pg_get_userbyid(c.relowner) as owner,
           c.relkind = 'p' as partitioned,
           (c.relhassubclass or exists (select 1 from pg_catalog.pg_inherits i where i.inhrelid = c.oid)) as inherits
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS} and ${ROW_KINDS}
    order by 1
  `.execute(db);
  return [...rows];
}

async function schemas(db: Kysely<unknown>): Promise<SchemaRow[]> {
  const { rows } = await sql<SchemaRow>`
    select n.nspname::text as name, pg_catalog.pg_get_userbyid(n.nspowner) as owner
    from pg_catalog.pg_namespace n
    where ${OURS}
    order by 1
  `.execute(db);
  return [...rows];
}

async function policies(db: Kysely<unknown>): Promise<PolicyRow[]> {
  const { rows } = await sql<PolicyRow>`
    select ${QUALIFIED} as table,
           p.polname::text as name,
           p.polcmd::text as command,
           pg_catalog.pg_get_expr(p.polqual, p.polrelid) as expression,
           pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) as check_expression,
           (select pg_catalog.string_agg(pg_catalog.pg_get_userbyid(r), ',' order by r)
            from pg_catalog.unnest(p.polroles) as r) as roles
    from pg_catalog.pg_policy p
    join pg_catalog.pg_class c on c.oid = p.polrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS}
    order by 1, 2
  `.execute(db);
  return [...rows];
}

/** Triggers someone wrote, not the ones Postgres makes for a foreign key. */
async function triggers(db: Kysely<unknown>): Promise<TriggerRow[]> {
  const { rows } = await sql<TriggerRow>`
    select ${QUALIFIED} as table, t.tgname::text as name
    from pg_catalog.pg_trigger t
    join pg_catalog.pg_class c on c.oid = t.tgrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS} and not t.tgisinternal
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
 */
async function grants(db: Kysely<unknown>, appRole: string): Promise<GrantRow[]> {
  const { rows } = await sql<GrantRow>`
    select ${QUALIFIED} as table, g.grantee, r.privilege
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    cross join (select pg_catalog.unnest(array[${appRole}::text, 'public'::text]) as grantee) g
    cross join (select pg_catalog.unnest(${sql.val([...TABLE_RIGHTS])}::text[]) as privilege) r
    where ${OURS} and ${ROW_KINDS}
      and pg_catalog.has_table_privilege(g.grantee, c.oid, r.privilege)
    order by 1, 2, 3
  `.execute(db);
  return [...rows];
}

async function columns(db: Kysely<unknown>): Promise<ColumnRow[]> {
  const { rows } = await sql<ColumnRow>`
    select ${QUALIFIED} as table, a.attname::text as column
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where ${OURS} and ${ROW_KINDS} and a.attnum > 0 and not a.attisdropped
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
async function plantedCasts(db: Kysely<unknown>): Promise<number> {
  const { rows } = await sql<CountRow>`
    select pg_catalog.count(*)::text as count from pg_catalog.pg_cast where oid >= 16384
  `.execute(db);
  return Number(rows[0]?.count ?? '0');
}

/**
 * Settings pinned to our database or to any role. A `search_path` set this way
 * is the trap A3e-1a pins against; the pin means one can no longer take effect,
 * but its presence is still a sign someone tried, and another setting could
 * change how a statement behaves.
 */
async function roleSettings(db: Kysely<unknown>): Promise<number> {
  const { rows } = await sql<CountRow>`
    select pg_catalog.count(*)::text as count
    from pg_catalog.pg_db_role_setting s
    where s.setdatabase = (
            select d.oid from pg_catalog.pg_database d where d.datname = pg_catalog.current_database()
          )
       or s.setrole <> 0
  `.execute(db);
  return Number(rows[0]?.count ?? '0');
}

const quoted = (name: string): string => `"${name}"`;

/** `schema.table` as Postgres's format('%I.%I') writes it, so a name needing quotes matches. */
function policyName(name: string): string {
  const [schema = '', table = ''] = name.split('.', 2);
  return `${schema}.${table}`;
}

/**
 * Everything about the live database that differs from what the migrations
 * built. An empty list means no drift. It never throws for a difference: a
 * database that refuses the read throws, and the caller treats that as a failed
 * check in its own right.
 */
export async function liveSchemaProblems(
  db: Kysely<unknown>,
  { appRole, ownerRole, policy = SCHEMA_POLICY }: SchemaGuardOptions,
): Promise<SchemaProblem[]> {
  const problems: SchemaProblem[] = [];
  const [allRelations, allSchemas, allPolicies, allTriggers, allGrants, allColumns, casts, settings] =
    await Promise.all([
      relations(db),
      schemas(db),
      policies(db),
      triggers(db),
      grants(db, appRole),
      columns(db),
      plantedCasts(db),
      roleSettings(db),
    ]);

  for (const schema of allSchemas) {
    if (schema.owner !== ownerRole) problems.push(`schema ${quoted(schema.name)} is owned by another role`);
  }

  const globalTables = new Set(Object.keys(policy.globalTables).map(policyName));
  const appendOnly = new Set(policy.appendOnlySchemas);
  const exceptions = new Set(Object.keys(policy.appendOnlyExceptions).map(policyName));

  for (const relation of allRelations) {
    const name = relation.name;
    // A view or a foreign table in place of a table means every read now goes
    // somewhere else, with the policies of whatever it points at.
    if (relation.kind !== 'r') problems.push(`${name} is no longer a plain table`);
    if (relation.partitioned) problems.push(`${name} is partitioned`);
    if (relation.inherits) problems.push(`${name} is in an inheritance tree`);
    if (relation.owner !== ownerRole) problems.push(`${name} is owned by another role`);
    // A rewrite rule can turn any statement into a different one, silently.
    if (relation.has_rules) problems.push(`${name} carries a rewrite rule`);

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
    if (one.roles !== null) problems.push(`${relation.name}'s policy is limited to named roles`);
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

  for (const trigger of allTriggers) {
    problems.push(`${trigger.table} carries the trigger ${quoted(trigger.name)}`);
  }

  // Rights: an allow-list, so a privilege nobody thought about is a problem
  // rather than an omission.
  const held = new Map<string, Set<string>>();
  for (const grant of allGrants) {
    const key = `${grant.grantee}\u0000${grant.table}`;
    held.set(key, (held.get(key) ?? new Set()).add(grant.privilege));
  }
  for (const relation of allRelations) {
    const schema = relation.name.split('.', 1)[0] ?? '';
    const allowed = new Set<string>(
      appendOnly.has(schema) ? (exceptions.has(relation.name) ? EXCEPTION_RIGHTS : APPEND_ONLY_RIGHTS) : TABLE_RIGHTS,
    );
    for (const right of held.get(`${appRole}\u0000${relation.name}`) ?? []) {
      if (!allowed.has(right)) problems.push(`${appRole} may ${right} on ${relation.name}`);
    }
    if ((held.get(`public\u0000${relation.name}`) ?? new Set()).size > 0) {
      problems.push(`PUBLIC has rights on ${relation.name}`);
    }
  }

  // Global tables are listed with their exact columns, so a new one is a
  // reviewed change rather than something that appears.
  const columnsOf = new Map<string, string[]>();
  for (const column of allColumns) columnsOf.set(column.table, [...(columnsOf.get(column.table) ?? []), column.column]);
  for (const [listed, entry] of Object.entries(policy.globalTables)) {
    const name = policyName(listed);
    const live = columnsOf.get(name);
    if (live === undefined) continue;
    if (live.join(',') !== [...entry.columns].join(',')) problems.push(`${name} no longer has exactly its columns`);
  }
  for (const relation of allRelations) {
    if (globalTables.has(relation.name)) continue;
    if (!(columnsOf.get(relation.name) ?? []).includes('org_id')) problems.push(`${relation.name} has no org_id`);
  }

  if (casts > 0) problems.push('the database carries a cast Postgres did not ship');
  if (settings > 0) problems.push('a setting is pinned to this database or to a role');

  return problems.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
