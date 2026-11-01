// Migrations that fill rows already there, run as staging and production run
// them: on a database migrated to the one before, holding rows, as the owner
// with no organisation named. The test databases every other test uses start
// empty, so a fill that reaches no rows (a tenant wall binding the owner)
// passes there and fails a real release (S135: 0054's first release).
import { copyFile, mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createTestDatabase, LogCapture, type TestClient, type TestDatabase } from '@agentx/testing';
import { afterEach, beforeEach, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { runMigrations } from './migrate.ts';

const REPO_MIGRATIONS = fileURLToPath(new URL('../../../../db/migrations', import.meta.url));
const ORG = '0199a000-0000-7000-8000-0000000000a1';
const AGENT = '0199a000-0000-7000-8000-0000000000b1';

const server = inject('postgres');
let database: TestDatabase;
let folder: string;

beforeEach(async () => {
  database = await createTestDatabase(server, { schema: 'empty' });
  folder = await mkdtemp(path.join(tmpdir(), 'agentx-upgrades-'));
});

afterEach(async () => {
  await database.drop();
  await rm(folder, { recursive: true, force: true });
});

/** The repository's migrations up to and including `last`, copied into the test's folder, then run as the owner. */
async function migratedTo(last: string): Promise<void> {
  for (const name of (await readdir(REPO_MIGRATIONS)).filter((file) => file.endsWith('.sql')).sort()) {
    if (name > last) break;
    await copyFile(path.join(REPO_MIGRATIONS, name), path.join(folder, name));
  }
  await runMigrations({
    connection: database.connection('owner'),
    directory: folder,
    logger: createLogger({
      service: 'migrate',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: new LogCapture(),
    }),
  });
}

describe('migrations that fill rows already there', () => {
  it("0054 gives every organisation's kept zone its agent's ID, whatever organisation the owner names", async () => {
    await migratedTo('0053_activity_exports.sql');
    const owner = database.as('owner');
    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [ORG]);
    await owner.query(
      "insert into limit_reservations.agent_zones (org_id, agent_id, time_zone, created_at) values ($1, $2, 'Asia/Dubai', now())",
      [ORG, AGENT],
    );
    await owner.query("select pg_catalog.set_config('app.org_id', '', false)");

    await migratedTo('0054_agent_zones_signed.sql');

    await owner.query("select pg_catalog.set_config('app.org_id', $1, false)", [ORG]);
    expect(
      await owner.query('select id::text, state_version, state_event_id from limit_reservations.agent_zones'),
    ).toEqual([{ id: AGENT, state_version: 1, state_event_id: null }]);
    // The wall is back on the owner too.
    expect(
      await owner.query(
        "select relforcerowsecurity from pg_catalog.pg_class where oid = 'limit_reservations.agent_zones'::regclass",
      ),
    ).toEqual([{ relforcerowsecurity: true }]);
  });

  describe('0067 re-keys every request and claim by the full case fold (PL-39)', () => {
    const OTHER_ORG = '0199a000-0000-7000-8000-0000000000a2';
    const SUPPLIER = '0199a000-0000-7000-8000-0000000000c1';
    const ID = (n: number) => `0199a000-0000-7000-8000-0000000001${String(n).padStart(2, '0')}`;

    /** A request and its claim as they stood under 0039's key, planted past their parents: only they matter here. */
    async function plant(
      plain: TestClient,
      row: { org: string; n: number; reference: string; supplier?: string; released?: boolean },
    ): Promise<void> {
      await plain.query(
        `insert into spend_requests.requests (org_id, id, agent_id, agent_key_id, mandate_id, mandate_version_id, supplier_id,
           supplier_version_id, funding_source_id, amount_minor, currency, purpose, order_reference, idempotency_key,
           input_hash, input_hash_key_version, decision, status, created_at)
         values ($1, $2::uuid, $2::uuid, $2::uuid, $2::uuid, $2::uuid, $3, $2::uuid, $2::uuid, 100, 'AED', 'a purpose', $4, $2::text,
           repeat('a', 64), 1, 'ALLOW', 'APPROVED', now())`,
        [row.org, ID(row.n), row.supplier ?? SUPPLIER, row.reference],
      );
      await plain.query(
        `insert into spend_requests.order_claims (org_id, id, request_id, supplier_id, order_reference, claimed_at, released_at)
         select org_id, id, id, supplier_id, order_key, now(), case when $3::boolean then now() end
         from spend_requests.requests where org_id = $1 and id = $2`,
        [row.org, ID(row.n), row.released === true],
      );
    }

    const planted = async (rows: Parameters<typeof plant>[1][]): Promise<TestClient> => {
      await migratedTo('0066_failure_proposals.sql');
      const admin = await database.connect('admin');
      await admin.query("set session_replication_role = 'replica'");
      for (const row of rows) await plant(admin, row);
      return admin;
    };

    const claims = (admin: TestClient) =>
      admin.query(
        `select claim.request_id::text as id, request.order_reference as raw, request.order_key as key,
                claim.order_reference as claimed
         from spend_requests.order_claims as claim
         join spend_requests.requests as request on (request.org_id, request.id) = (claim.org_id, claim.request_id)
         order by 1, 2`,
      );

    it("moves every organisation's rows, leaves the sealed text and an unchanged key alone, and puts both walls back", async () => {
      const admin = await planted([
        { org: ORG, n: 1, reference: 'Straße-1' },
        { org: OTHER_ORG, n: 1, reference: 'ΣΑΣ', released: true },
        { org: ORG, n: 3, reference: 'Inv-3' },
      ]);
      expect(await claims(admin)).toEqual([
        { id: ID(1), raw: 'Straße-1', key: 'straße-1', claimed: 'straße-1' },
        { id: ID(1), raw: 'ΣΑΣ', key: 'σασ', claimed: 'σασ' },
        { id: ID(3), raw: 'Inv-3', key: 'inv-3', claimed: 'inv-3' },
      ]);

      await migratedTo('0067_order_key_full_fold.sql');

      expect(await claims(admin)).toEqual([
        { id: ID(1), raw: 'Straße-1', key: 'strasse-1', claimed: 'strasse-1' },
        { id: ID(1), raw: 'ΣΑΣ', key: 'σασ', claimed: 'σασ' },
        { id: ID(3), raw: 'Inv-3', key: 'inv-3', claimed: 'inv-3' },
      ]);
      expect(
        await admin.query(
          `select relname as table, relforcerowsecurity as forced, relrowsecurity as enabled from pg_catalog.pg_class
           where oid in ('spend_requests.requests'::regclass, 'spend_requests.order_claims'::regclass) order by 1`,
        ),
      ).toEqual([
        { table: 'order_claims', forced: true, enabled: true },
        { table: 'requests', forced: true, enabled: true },
      ]);
      await expect(plant(admin, { org: ORG, n: 9, reference: ' ' })).rejects.toMatchObject({
        constraint: 'an_order_not_blank',
      });
      // The keys are back on the new values: a claim with another key than its request's is refused again.
      await admin.query("set session_replication_role = 'origin'");
      await expect(
        admin.query(`update spend_requests.order_claims set order_reference = 'straße-1' where request_id = $1`, [
          ID(1),
        ]),
      ).rejects.toMatchObject({ constraint: 'for_its_request' });
      expect(
        await admin.query(
          `select conname as name from pg_catalog.pg_constraint
           where conrelid = 'spend_requests.requests'::regclass and conname in ('claimed_as_asked', 'an_order_not_blank')
           order by 1`,
        ),
      ).toEqual([{ name: 'an_order_not_blank' }, { name: 'claimed_as_asked' }]);
    });

    it('lets a released claim share its key with an open one', async () => {
      const admin = await planted([
        { org: ORG, n: 1, reference: 'STRASSE-1', released: true },
        { org: ORG, n: 2, reference: 'Straße-1' },
      ]);
      await migratedTo('0067_order_key_full_fold.sql');
      expect((await claims(admin)).map((row) => row.claimed)).toEqual(['strasse-1', 'strasse-1']);
    });

    it('lets one order stand open at two suppliers', async () => {
      const admin = await planted([
        { org: ORG, n: 1, reference: 'STRASSE-1' },
        { org: ORG, n: 2, reference: 'Straße-1', supplier: OTHER_ORG },
      ]);
      await migratedTo('0067_order_key_full_fold.sql');
      expect((await claims(admin)).map((row) => row.claimed)).toEqual(['strasse-1', 'strasse-1']);
    });

    it('stops, naming the two requests and no reference, in what the log keeps, and changes nothing', async () => {
      const admin = await planted([
        { org: ORG, n: 1, reference: 'STRASSE-1' },
        { org: ORG, n: 2, reference: 'Straße-1' },
      ]);

      const failure: unknown = await migratedTo('0067_order_key_full_fold.sql').catch((error: unknown) => error);

      expect(failure).toBeInstanceOf(Error);
      const { message: reason } = (failure as Error).cause as Error;
      // A long line keeps 128 characters of a cause (redact.ts): the IDs must come through whole.
      expect(reason.slice(0, 128)).toContain(`requests ${ID(1)}, ${ID(2)} are one order`);
      expect(reason).toContain('changed nothing');
      // True of a paid order too, which no cancel frees.
      expect(reason).toContain('if both are paid or unknown, nothing in the app frees them');
      const capture = new LogCapture();
      createLogger({
        service: 'migrate',
        config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
        destination: capture,
      }).error('migrate.failed', { err: failure });
      expect(capture.lines().at(-1)).toMatchObject({
        err: { cause: { message: reason } },
      });
      expect(reason.toLowerCase()).not.toContain('strasse');
      expect(reason.toLowerCase()).not.toContain('straße');
      expect((await claims(admin)).map((row) => row.claimed)).toEqual(['strasse-1', 'straße-1']);
      expect(
        await admin.query(`select count(*)::int as applied from migrations.applied where name like '0067%'`),
      ).toEqual([{ applied: 0 }]);
    });

    it('names the two when only their payee key is shared, and two other open claims are no bar', async () => {
      const admin = await planted([
        { org: ORG, n: 0, reference: 'STRASSE-1', released: true },
        { org: ORG, n: 3, reference: 'Inv-3' },
        { org: ORG, n: 1, reference: 'STRASSE-1' },
        { org: ORG, n: 2, reference: 'Straße-1', supplier: OTHER_ORG },
      ]);
      await admin.query(`update spend_requests.order_claims set payee_key = 'payee-1' where request_id in ($1, $2)`, [
        ID(1),
        ID(2),
      ]);

      const failure: unknown = await migratedTo('0067_order_key_full_fold.sql').catch((error: unknown) => error);

      expect(((failure as Error).cause as Error).message).toContain(`requests ${ID(1)}, ${ID(2)} are one order`);
    });
  });
});
