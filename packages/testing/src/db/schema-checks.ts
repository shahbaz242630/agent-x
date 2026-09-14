// CI-06 (ADR-005 §8): the checks every migrated schema must pass, run on a real
// server. tooling/checks/database-schema.db.test.ts runs them on db/migrations,
// so every new migration is checked, and each rule has a broken fixture that
// proves it fails (schema-checks.db.test.ts).
//
// Postgres applies row-level security only to tables that have it enabled, and
// to their owner only when it's forced. It lets unique and foreign-key checks
// bypass it, and it gives some rights to every role (PUBLIC) unless they are
// taken back. So every table is one of two kinds:
// - a tenant table: org_id uuid NOT NULL, row-level security enabled and
//   forced, exactly the tenant policy, and org_id in every unique index and in
//   every foreign key that points at a tenant table (SEC-TEN-05);
// - a global table: on the global-table list, with a reason and exactly its
//   columns (SEC-TEN-08).
// Across the database: no PUBLIC grants; of the roles that may connect, none
// but the backup role has BYPASSRLS, and none is a member of a role or has
// members; the backup role only reads; the app role only adds to and reads
// append-only tables (SEC-EVD-01).
//
// The checks read only the system catalogues, as the migration role, the one
// that applied the migrations. The tenant policy is compared with a reference
// policy created on the same server, because Postgres prints expressions
// slightly differently from one version to the next. Names are sorted byte
// by byte (Postgres's name type sorts that way), so every server lists the
// problems in the same order, whatever its locale.
import pg from 'pg';

import type { TestDatabase } from './test-database.ts';

/** A table with no org_id and no row-level security, allowed by name (ADR-005 §6). */
interface GlobalTable {
  /** Why it can't be a tenant table. */
  readonly reason: string;
  /** Every column it has, exactly: a new column is a reviewed change to the list (SEC-TEN-08). */
  readonly columns: readonly string[];
}

export interface SchemaPolicy {
  /**
   * The global tables, by schema-qualified name as Postgres quotes it
   * (`schema.table`). Every other table is a tenant table.
   */
  readonly globalTables: Readonly<Record<string, GlobalTable>>;
  /** Schemas whose tables the app role may only add to and read, such as the audit trail (SEC-EVD-01). */
  readonly appendOnlySchemas: readonly string[];
}

/** The name every tenant table's one policy has. */
const TENANT_POLICY = 'tenant_isolation';

/**
 * The tenant policy on a temporary table, as ADR-005 §2 gives it and a
 * migration writes it. It's created inside a transaction that is rolled back.
 */
const REFERENCE_TABLE = 'create temporary table ci06_reference (org_id uuid not null)';
const REFERENCE_POLICY = `
  create policy tenant_isolation on ci06_reference
    using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
    with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
`;
const REFERENCE_EXPRESSIONS = `
  select pg_catalog.pg_get_expr(p.polqual, p.polrelid) as using_expression,
         pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) as check_expression
  from pg_catalog.pg_policy p
  where p.polrelid = 'pg_temp.ci06_reference'::pg_catalog.regclass
`;

/** Our schemas: every one but Postgres's own. */
const SCHEMAS = `
  select n.oid from pg_catalog.pg_namespace n
  where n.nspname not in ('pg_catalog', 'information_schema') and not pg_catalog.starts_with(n.nspname, 'pg_')
`;

/** Tables and the other relations that hold or show rows. */
const RELATIONS = `
  select pg_catalog.format('%I.%I', n.nspname, c.relname) as name, c.relkind::text as kind,
         c.relrowsecurity as rls, c.relforcerowsecurity as forced
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where c.relnamespace = any($1::pg_catalog.oid[]) and c.relkind in ('r', 'p', 'v', 'm', 'f')
  order by n.nspname, c.relname
`;

const COLUMNS = `
  select pg_catalog.format('%I.%I', n.nspname, c.relname) as table, a.attname::text as column,
         a.atttypid = 'pg_catalog.uuid'::pg_catalog.regtype as is_uuid, a.attnotnull as not_null
  from pg_catalog.pg_attribute a
  join pg_catalog.pg_class c on c.oid = a.attrelid
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where c.relnamespace = any($1::pg_catalog.oid[]) and c.relkind in ('r', 'p', 'v', 'm', 'f')
    and a.attnum > 0 and not a.attisdropped
  order by n.nspname, c.relname, a.attnum
`;

const POLICIES = `
  select pg_catalog.format('%I.%I', n.nspname, c.relname) as table, p.polname::text as name,
         case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT' when 'w' then 'UPDATE' when 'd' then 'DELETE'
           else 'ALL' end as command,
         p.polpermissive as permissive,
         p.polroles = '{0}'::pg_catalog.oid[] as to_public,
         pg_catalog.pg_get_expr(p.polqual, p.polrelid) as using_expression,
         pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) as check_expression
  from pg_catalog.pg_policy p
  join pg_catalog.pg_class c on c.oid = p.polrelid
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where c.relnamespace = any($1::pg_catalog.oid[])
  order by n.nspname, c.relname, p.polname
`;

/**
 * Unique and exclusion indexes whose key columns leave out org_id. Included
 * columns (INCLUDE) come after the key columns and don't count.
 */
const UNIQUE_WITHOUT_ORG = `
  select pg_catalog.format('%I.%I', n.nspname, c.relname) as table, ic.relname::text as index,
         i.indisexclusion as exclusion
  from pg_catalog.pg_index i
  join pg_catalog.pg_class c on c.oid = i.indrelid
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  join pg_catalog.pg_class ic on ic.oid = i.indexrelid
  where c.relnamespace = any($1::pg_catalog.oid[]) and (i.indisunique or i.indisexclusion)
    and not exists (
      select 1
      from pg_catalog.unnest(i.indkey::pg_catalog.int2[]) with ordinality as k(attnum, position)
      join pg_catalog.pg_attribute a on a.attrelid = i.indrelid and a.attnum = k.attnum
      where k.position <= i.indnkeyatts and a.attname = 'org_id'
    )
  order by n.nspname, c.relname, ic.relname
`;

/**
 * Foreign keys in our schemas, and whether they pair org_id with org_id. A
 * partitioned table's key is listed for each partition too, since each
 * partition holds its own copy. unnest over two arrays is SQL syntax rather
 * than a function, like coalesce below, so neither is written with pg_catalog.
 */
const FOREIGN_KEYS = `
  select pg_catalog.format('%I.%I', sn.nspname, s.relname) as table, con.conname::text as name,
         pg_catalog.format('%I.%I', tn.nspname, t.relname) as target,
         exists (
           select 1
           from unnest(con.conkey, con.confkey) as k(from_attnum, to_attnum)
           join pg_catalog.pg_attribute fa on fa.attrelid = con.conrelid and fa.attnum = k.from_attnum
           join pg_catalog.pg_attribute ta on ta.attrelid = con.confrelid and ta.attnum = k.to_attnum
           where fa.attname = 'org_id' and ta.attname = 'org_id'
         ) as pairs_org_id
  from pg_catalog.pg_constraint con
  join pg_catalog.pg_class s on s.oid = con.conrelid
  join pg_catalog.pg_namespace sn on sn.oid = s.relnamespace
  join pg_catalog.pg_class t on t.oid = con.confrelid
  join pg_catalog.pg_namespace tn on tn.oid = t.relnamespace
  where con.contype = 'f' and s.relnamespace = any($1::pg_catalog.oid[])
  order by sn.nspname, s.relname, con.conname
`;

/**
 * Every right granted on the database and on what is in our schemas, one row
 * per grantee and privilege. A null ACL means Postgres's built-in defaults.
 * For a table, sequence or schema those give rights to its owner only, and the
 * owner is the migration role: a migration can't hand an object to another
 * role, because the migration role is a member of none. For a function they
 * include EXECUTE for PUBLIC, and for the database CONNECT and TEMPORARY for
 * PUBLIC, so those two are spelled out with acldefault. Types are left out:
 * every table's row type is usable by PUBLIC by default, and using a type
 * gives no access to any row. A default privilege for every schema has no
 * schema: quote_ident passes the null on, where format('%I') would fail.
 */
const GRANTS = `
  select g.object, g.kind, g.schema, g.grantee = 0 as to_public,
         case when g.grantee = 0 then null else pg_catalog.pg_get_userbyid(g.grantee)::text end as grantee,
         g.privilege
  from (
    select case c.relkind when 'S' then 'sequence ' else 'table ' end
             || pg_catalog.format('%I.%I', n.nspname, c.relname) as object,
           case c.relkind when 'S' then 'sequence' else 'table' end as kind,
           n.nspname::text as schema, acl.grantee, acl.privilege_type as privilege
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace,
    pg_catalog.aclexplode(c.relacl) acl
    where c.relnamespace = any($1::pg_catalog.oid[]) and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
    union all
    select 'column ' || pg_catalog.format('%I.%I.%I', n.nspname, c.relname, a.attname), 'column',
           n.nspname::text, acl.grantee, acl.privilege_type
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace,
    pg_catalog.aclexplode(a.attacl) acl
    where c.relnamespace = any($1::pg_catalog.oid[]) and a.attnum > 0 and not a.attisdropped
    union all
    select 'schema ' || pg_catalog.format('%I', n.nspname), 'schema', n.nspname::text, acl.grantee, acl.privilege_type
    from pg_catalog.pg_namespace n,
    pg_catalog.aclexplode(n.nspacl) acl
    where n.oid = any($1::pg_catalog.oid[])
    union all
    select 'function ' || p.oid::pg_catalog.regprocedure::text, 'function', n.nspname::text,
           acl.grantee, acl.privilege_type
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace,
    pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) acl
    where p.pronamespace = any($1::pg_catalog.oid[])
    union all
    select 'database ' || pg_catalog.format('%I', d.datname), 'database', null, acl.grantee, acl.privilege_type
    from pg_catalog.pg_database d,
    pg_catalog.aclexplode(coalesce(d.datacl, pg_catalog.acldefault('d', d.datdba))) acl
    where d.datname = pg_catalog.current_database()
    union all
    select pg_catalog.format('default privileges of %I for new %s', pg_catalog.pg_get_userbyid(da.defaclrole),
             case da.defaclobjtype when 'r' then 'tables' when 'S' then 'sequences' when 'f' then 'functions'
               when 'n' then 'schemas' when 'L' then 'large objects' else da.defaclobjtype::text end)
             || coalesce(' in schema ' || pg_catalog.quote_ident(dn.nspname), ''),
           'default', dn.nspname::text, acl.grantee, acl.privilege_type
    from pg_catalog.pg_default_acl da
    left join pg_catalog.pg_namespace dn on dn.oid = da.defaclnamespace,
    pg_catalog.aclexplode(da.defaclacl) acl
    where da.defaclobjtype <> 'T'
  ) g
  order by g.object collate "C", g.grantee = 0 desc, pg_catalog.pg_get_userbyid(g.grantee), g.privilege collate "C"
`;

/**
 * The roles that matter here: every one that may connect to this database,
 * ours included. Superusers are the server admin's; they bypass every check,
 * and the app refuses to run as one (assertRuntimeRole).
 */
const ROLES = `
  select r.rolname::text as name, r.rolbypassrls as bypass_rls
  from pg_catalog.pg_roles r
  where not r.rolsuper and pg_catalog.has_database_privilege(r.oid, pg_catalog.current_database(), 'CONNECT')
  order by r.rolname
`;

/** Explicit role grants to or from those roles. */
const MEMBERSHIPS = `
  select pg_catalog.pg_get_userbyid(m.member)::text as member, pg_catalog.pg_get_userbyid(m.roleid)::text as role
  from pg_catalog.pg_auth_members m
  where pg_catalog.pg_get_userbyid(m.member) = any($1::pg_catalog.text[])
     or pg_catalog.pg_get_userbyid(m.roleid) = any($1::pg_catalog.text[])
  order by pg_catalog.pg_get_userbyid(m.member), pg_catalog.pg_get_userbyid(m.roleid)
`;

interface Relation {
  name: string;
  kind: string;
  rls: boolean;
  forced: boolean;
}

interface Column {
  table: string;
  column: string;
  is_uuid: boolean;
  not_null: boolean;
}

interface PolicyExpressions {
  using_expression: string | null;
  check_expression: string | null;
}

interface Policy extends PolicyExpressions {
  table: string;
  name: string;
  command: string;
  permissive: boolean;
  to_public: boolean;
}

interface UniqueIndex {
  table: string;
  index: string;
  exclusion: boolean;
}

interface ForeignKey {
  table: string;
  name: string;
  target: string;
  pairs_org_id: boolean;
}

interface Grant {
  object: string;
  kind: 'table' | 'sequence' | 'column' | 'schema' | 'function' | 'database' | 'default';
  schema: string | null;
  to_public: boolean;
  grantee: string | null;
  privilege: string;
}

interface Role {
  name: string;
  bypass_rls: boolean;
}

interface Membership {
  member: string;
  role: string;
}

interface Facts {
  relations: Relation[];
  columns: Column[];
  reference: PolicyExpressions;
  policies: Policy[];
  uniqueIndexes: UniqueIndex[];
  foreignKeys: ForeignKey[];
  grants: Grant[];
  roles: Role[];
  memberships: Membership[];
}

/** The app and backup roles db/bootstrap/roles.sql creates. */
interface RoleNames {
  readonly app: string;
  readonly backup: string;
}

/**
 * Every way the database breaks the CI-06 rules, or none. Connects as the
 * migration role and reads the system catalogues; it changes nothing.
 */
export async function schemaProblems(database: TestDatabase, policy: SchemaPolicy): Promise<string[]> {
  const roles: RoleNames = { app: database.server.roles.app.user, backup: database.server.roles.backup.user };
  // With only pg_catalog on the search path, every name from our schemas is
  // printed with its schema, public included. (A look-alike function in a
  // policy prints with its schema either way: Postgres searches pg_catalog
  // first, so only its own current_setting prints without one.)
  const client = new pg.Client({ ...database.connection('owner'), ssl: false, options: '-c search_path=pg_catalog' });
  await client.connect();
  try {
    return checkFacts(await readFacts(client), policy, roles);
  } finally {
    await client.end();
  }
}

async function rows<Row extends object>(client: pg.Client, text: string, values: readonly unknown[]): Promise<Row[]> {
  // eslint-disable-next-line agentx/no-string-built-sql -- Passes on the fixed query texts above; the rule checks each where it is written.
  return (await client.query<Row>(text, [...values])).rows;
}

async function referenceExpressions(client: pg.Client): Promise<PolicyExpressions> {
  await client.query('begin');
  try {
    await client.query(REFERENCE_TABLE);
    await client.query(REFERENCE_POLICY);
    const [reference] = await rows<PolicyExpressions>(client, REFERENCE_EXPRESSIONS, []);
    if (reference === undefined) throw new Error('The reference tenant policy was not created');
    return reference;
  } finally {
    await client.query('rollback');
  }
}

async function readFacts(client: pg.Client): Promise<Facts> {
  const schemas = (await rows<{ oid: number }>(client, SCHEMAS, [])).map((row) => row.oid);
  const reference = await referenceExpressions(client);
  const inScope = await rows<Role>(client, ROLES, []);
  return {
    relations: await rows<Relation>(client, RELATIONS, [schemas]),
    columns: await rows<Column>(client, COLUMNS, [schemas]),
    reference,
    policies: await rows<Policy>(client, POLICIES, [schemas]),
    uniqueIndexes: await rows<UniqueIndex>(client, UNIQUE_WITHOUT_ORG, [schemas]),
    foreignKeys: await rows<ForeignKey>(client, FOREIGN_KEYS, [schemas]),
    grants: await rows<Grant>(client, GRANTS, [schemas]),
    roles: inScope,
    memberships: await rows<Membership>(client, MEMBERSHIPS, [inScope.map((role) => role.name)]),
  };
}

const TABLE_KINDS = new Set(['r', 'p']);
const OTHER_KINDS: Readonly<Record<string, string>> = { v: 'view', m: 'materialized view', f: 'foreign table' };

/** What the backup role may hold on each kind of object: reading only (ADR-005 §3). */
const BACKUP_MAY: Readonly<Record<Exclude<Grant['kind'], 'default'>, readonly string[]>> = {
  table: ['SELECT'],
  sequence: ['SELECT'],
  column: ['SELECT'],
  schema: ['USAGE'],
  database: ['CONNECT'],
  function: [],
};

/** What the app role may hold on an append-only table or its columns (ADR-005 §9). */
const APPEND_ONLY_APP_MAY = ['INSERT', 'SELECT'];

function checkFacts(facts: Facts, policy: SchemaPolicy, roles: RoleNames): string[] {
  const isGlobal = (name: string): boolean => Object.hasOwn(policy.globalTables, name);
  const tenantTables = facts.relations
    .filter((relation) => TABLE_KINDS.has(relation.kind) && !isGlobal(relation.name))
    .map((relation) => relation.name);
  const isTenant = new Set(tenantTables);

  return [
    ...globalListProblems(policy, facts),
    ...facts.relations.flatMap((relation) => (isGlobal(relation.name) ? [] : relationProblems(relation))),
    ...tenantTables.flatMap((table) => [
      ...orgIdProblems(
        table,
        facts.columns.find((column) => column.table === table && column.column === 'org_id'),
      ),
      ...tenantPolicyProblems(
        table,
        facts.policies.filter((row) => row.table === table),
        facts.reference,
      ),
    ]),
    ...facts.uniqueIndexes
      .filter((index) => isTenant.has(index.table))
      .map(
        (index) =>
          `${index.table}: ${index.exclusion ? 'exclusion constraint' : 'unique index'} ${index.index} leaves out org_id, so it could reveal another organisation's rows (SEC-TEN-05)`,
      ),
    ...facts.foreignKeys
      .filter((key) => isTenant.has(key.target) && !key.pairs_org_id)
      .map(
        (key) =>
          `${key.table}: foreign key ${key.name} points at the tenant table ${key.target} without pairing org_id with its org_id (SEC-TEN-05)`,
      ),
    ...facts.grants.flatMap((grant) => grantProblems(grant, policy, roles)),
    ...facts.roles
      .filter((role) => role.bypass_rls && role.name !== roles.backup)
      .map((role) => `role ${role.name} has BYPASSRLS; only ${roles.backup} may (ADR-005 §3)`),
    ...facts.memberships.map(
      (membership) =>
        `role ${membership.member} is a member of ${membership.role}; the database's roles take part in no role memberships (ADR-005 §3)`,
    ),
  ];
}

/** The list itself: every entry has a reason and its columns, and names a table that exists. */
function globalListProblems(policy: SchemaPolicy, facts: Facts): string[] {
  return Object.entries(policy.globalTables).flatMap(([name, table]) => {
    const problems: string[] = [];
    if (table.reason.trim() === '') problems.push(`${name}: the global-table list gives no reason for it`);
    if (new Set(table.columns).size !== table.columns.length) {
      problems.push(`${name}: the global-table list names a column twice`);
    }
    if (!facts.relations.some((relation) => relation.name === name)) {
      problems.push(`${name}: is on the global-table list, but no such table exists`);
      return problems;
    }
    const actual = facts.columns.filter((column) => column.table === name).map((column) => column.column);
    for (const column of actual.filter((column) => !table.columns.includes(column))) {
      problems.push(`${name}: column ${column} is not on the global-table list (SEC-TEN-08)`);
    }
    for (const column of table.columns.filter((column) => !actual.includes(column))) {
      problems.push(`${name}: the global-table list names column ${column}, which the table doesn't have`);
    }
    return problems;
  });
}

/** A relation that isn't on the global-table list must be a tenant table with its walls up. */
function relationProblems(relation: Relation): string[] {
  const other = OTHER_KINDS[relation.kind];
  if (other !== undefined) {
    return [
      `${relation.name}: a ${other} can't have forced row-level security, so it must be on the global-table list (ADR-005 §2)`,
    ];
  }
  if (!relation.rls) return [`${relation.name}: row-level security is off (ADR-005 §2)`];
  if (!relation.forced) {
    return [
      `${relation.name}: row-level security is enabled but not forced, so the table's owner bypasses it (ADR-005 §2)`,
    ];
  }
  return [];
}

function orgIdProblems(table: string, orgId: Column | undefined): string[] {
  if (orgId === undefined) return [`${table}: a tenant table needs an org_id column (ADR-005 §1)`];
  if (!orgId.is_uuid || !orgId.not_null) return [`${table}: org_id must be uuid NOT NULL (ADR-005 §1)`];
  return [];
}

/** Exactly one policy, the tenant policy: permissive, for every command and role, with the reference expressions. */
function tenantPolicyProblems(table: string, policies: readonly Policy[], reference: PolicyExpressions): string[] {
  const [only, ...others] = policies;
  if (only === undefined || others.length > 0) {
    return [
      `${table}: has ${policies.length} policies; a tenant table has exactly one, the tenant policy (ADR-005 §2)`,
    ];
  }
  const differences: string[] = [];
  if (only.name !== TENANT_POLICY) differences.push(`it is named ${only.name}, not ${TENANT_POLICY}`);
  if (!only.permissive) differences.push('it is restrictive');
  if (only.command !== 'ALL') differences.push(`it covers ${only.command} only`);
  if (!only.to_public) differences.push('it applies to named roles only');
  if (only.using_expression !== reference.using_expression) {
    differences.push(`its USING is ${only.using_expression ?? 'missing'}`);
  }
  if (only.check_expression !== reference.check_expression) {
    differences.push(`its WITH CHECK is ${only.check_expression ?? 'missing'}`);
  }
  return differences.length === 0
    ? []
    : [`${table}: policy ${only.name} is not the tenant policy (ADR-005 §2): ${differences.join('; ')}`];
}

/**
 * Default privileges are checked for PUBLIC only: what they give the backup or
 * app role shows up on each object once it is created, and is checked there.
 */
function grantProblems(grant: Grant, policy: SchemaPolicy, roles: RoleNames): string[] {
  if (grant.to_public) return [`${grant.object}: PUBLIC has ${grant.privilege} (ADR-005 §8)`];
  if (grant.grantee === roles.backup && grant.kind !== 'default' && !BACKUP_MAY[grant.kind].includes(grant.privilege)) {
    return [`${grant.object}: ${roles.backup} has ${grant.privilege}; it may only read (ADR-005 §3)`];
  }
  const appendOnly =
    (grant.kind === 'table' || grant.kind === 'column') &&
    grant.schema !== null &&
    policy.appendOnlySchemas.includes(grant.schema);
  if (appendOnly && grant.grantee === roles.app && !APPEND_ONLY_APP_MAY.includes(grant.privilege)) {
    return [
      `${grant.object}: ${roles.app} has ${grant.privilege} on an append-only table; it may only INSERT and SELECT (SEC-EVD-01)`,
    ];
  }
  return [];
}
