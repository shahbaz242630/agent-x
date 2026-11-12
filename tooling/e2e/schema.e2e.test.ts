// AZ9 (CI-06 on the real database after migrate): Verify runs CI-06 and A3c on
// a template the test set-up builds itself (tooling/test-db: db/bootstrap by
// psql as the superuser, then the migrations). This runs the same two checks on
// the compose stack's database, which the product's own db-setup and migrate
// jobs built, as Azure runs them, with Zitadel's role on the same server and
// the API's own jobs having run against it. So a difference in how the jobs
// build a server (a grant, a membership, a role's rights) can't pass CI unseen.
// Staging's own database is held to the same lists by the live schema guard,
// as the app role, on every run of its schedule (A3e-1b).
//
// Nothing is written: the checks read the catalogues as the migration role and
// roll back the reference objects they build.
import { describe, expect, it } from 'vitest';

import { authorityProblems, type CatalogueTarget, schemaProblems } from '../../packages/testing/src/index.ts';
import { AUTHORITY_TABLES } from '../authority-tables.ts';
import { SCHEMA_POLICY } from '../schema-policy.ts';
import { localLogin } from './compose.ts';

/** The stack's database, as compose.e2e.yaml publishes it to this machine alone, and the roles db/bootstrap names. */
const stack: CatalogueTarget = {
  connection: () => ({
    host: '127.0.0.1',
    port: 56541,
    database: 'agentx',
    user: 'agentx_owner',
    password: localLogin('AGENTX_LOCAL_DB_OWNER_PASSWORD'),
    tls: 'disable',
  }),
  server: {
    roles: { app: { user: 'agentx_app' }, backup: { user: 'agentx_backup' }, operator: { user: 'agentx_operator' } },
  },
};

describe('AZ9: the database the db-setup and migrate jobs built keeps the tenant walls (CI-06) and the authority tables (A3c)', () => {
  it('passes every CI-06 check', async () => {
    expect(await schemaProblems(stack, SCHEMA_POLICY)).toEqual([]);
  });

  it('passes every A3c check', async () => {
    expect(await authorityProblems(stack, AUTHORITY_TABLES)).toEqual([]);
  });
});
