// A stand-in tenant table, for proving the tenant walls before any module has
// tables of its own. It is built exactly as ADR-005 requires of every tenant
// table: org_id leads the key, row-level security is enabled and forced, and
// one policy lets a query see or write a row only when its org_id equals the
// transaction's app.org_id setting. The policy names pg_catalog, as every
// module's should, so it can't pick up another function of the same name. The
// app may read and write the table; the backup role may only read it.
import type { TestDatabase } from './test-database.ts';

/** Creates probe.items(org_id, id, label) in the test database, as agentx_owner. */
export async function createTenantProbe(database: TestDatabase): Promise<void> {
  const owner = database.as('owner');
  await owner.query('create schema probe');
  await owner.query(
    'create table probe.items (org_id uuid not null, id uuid not null, label text not null, primary key (org_id, id))',
  );
  await owner.query('alter table probe.items enable row level security');
  await owner.query('alter table probe.items force row level security');
  await owner.query(
    "create policy tenant_isolation on probe.items using (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid) with check (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)",
  );
  await owner.query('grant usage on schema probe to agentx_app, agentx_backup');
  await owner.query('grant select, insert, update, delete on probe.items to agentx_app');
  await owner.query('grant select on probe.items to agentx_backup');
}
