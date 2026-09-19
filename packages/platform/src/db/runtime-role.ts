// ADR-005 §3, APP-02: the running app connects as a role that can't get round
// the tenant walls. Forced row-level security binds every role except
// superusers and roles with BYPASSRLS, and a table's owner can switch it off.
// So at start-up the app checks the role it logged in as, and refuses to run
// as one that could bypass RLS itself, reach another role's rights, or own
// the database or anything in it. A mistaken connection setting, such as the
// server admin's login or the migration role's, then stops the start instead
// of silently removing the walls.
import { type Kysely, sql } from 'kysely';

export class UnsafeDatabaseRole extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`Refusing to run as this database role: ${problems.join('; ')}`);
    this.name = 'UnsafeDatabaseRole';
    this.problems = problems;
  }
}

interface RoleFacts {
  switched_role: boolean;
  superuser: boolean;
  bypass_rls: boolean;
  create_role: boolean;
  create_db: boolean;
  replication: boolean;
  member_of: string[];
  owns_database: boolean;
  owns_objects: boolean;
}

/**
 * Every reason the connected role is unsafe for the running app, or none.
 * The login role is the one checked (session_user): a SET ROLE, for example
 * from PGOPTIONS, could make current_user look safe while the login role can
 * switch back. Role names are listed, never other values.
 */
export async function runtimeRoleProblems<Schema>(db: Kysely<Schema>): Promise<string[]> {
  const { rows } = await sql<RoleFacts>`
    select
      session_user <> current_user as switched_role,
      r.rolsuper as superuser,
      r.rolbypassrls as bypass_rls,
      r.rolcreaterole as create_role,
      r.rolcreatedb as create_db,
      r.rolreplication as replication,
      array(
        select other.rolname::text from pg_catalog.pg_roles other
        where other.oid <> r.oid and pg_catalog.pg_has_role(r.oid, other.oid, 'MEMBER')
        order by other.rolname
      ) as member_of,
      exists (
        select 1 from pg_catalog.pg_database d
        where d.datname = pg_catalog.current_database() and d.datdba = r.oid
      ) as owns_database,
      -- Postgres records every owner of every object, in every database, here.
      exists (
        select 1 from pg_catalog.pg_shdepend s
        where s.refclassid = 'pg_catalog.pg_authid'::pg_catalog.regclass and s.refobjid = r.oid and s.deptype = 'o'
      ) as owns_objects
    from pg_catalog.pg_roles r
    where r.rolname = session_user
  `.execute(db);

  const facts = rows[0];
  if (facts === undefined) return ['the connected role was not found in pg_roles'];
  const problems: string[] = [];
  if (facts.switched_role) problems.push('the session has switched to another role (SET ROLE), and can switch back');
  if (facts.superuser) problems.push('it is a superuser, which bypasses row-level security');
  if (facts.bypass_rls) problems.push('it has BYPASSRLS');
  if (facts.create_role) problems.push('it can create roles');
  if (facts.create_db) problems.push('it can create databases');
  if (facts.replication) problems.push('it has REPLICATION');
  if (facts.member_of.length > 0) {
    problems.push(`it is a member of other roles, whose rights it can use (${facts.member_of.join(', ')})`);
  }
  if (facts.owns_database) problems.push('it owns the database');
  if (facts.owns_objects) {
    problems.push(
      'it owns objects (schemas, tables, functions or types), so it could change them or switch their row-level security off',
    );
  }
  return problems;
}

/** Throws UnsafeDatabaseRole, listing every problem, unless the role is safe. Run it at start-up. */
export async function assertRuntimeRole<Schema>(db: Kysely<Schema>): Promise<void> {
  const problems = await runtimeRoleProblems(db);
  if (problems.length > 0) throw new UnsafeDatabaseRole(problems);
}
