// Phase 4 C2a: a supplier's remittance setting (0061), on the real migrated
// schema, as the app role. Added with its supplier and sealed; read through
// its seal; a supplier added before 0061 reads as `on` until its first
// setting adds and seals its row; changed past the app, or deleted, it is
// refused and the organisation held; and the table holds the app to adding
// rows and moving only what the seal covers.
import { createDatabase, type Database } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createTestDatabase, FixedClock, SequentialIds, type TestDatabase, testLogger } from '@agentx/testing';
import type { Transaction } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { withSignedStates } from '../../audit/index.ts';
import { createOrganization } from '../../organizations/index.ts';
import type { SupplierDetails } from '../domain/supplier.ts';
import { type RemittanceEmail, remittanceOf, setRemittance } from './remittance.ts';
import { addSupplier, addSupplierUnset } from './suppliers.ts';
import type { SuppliersTables } from './tables.ts';

// The tables an organisation is made in, as createOrganization takes them (suppliers.db.test.ts says why).
type OrganizationTables = Parameters<typeof createOrganization>[0] extends Transaction<infer T> ? T : never;
type Tables = SuppliersTables & OrganizationTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const ids = new SequentialIds(0xc2a1_0000_0000);
const clock = new FixedClock(new Date('2026-10-23T08:00:00Z'));
const ADMIN = { type: 'user' as const, id: '0199a0f0-0000-7000-8000-0000000000d1' };

const DETAILS: SupplierDetails = {
  displayName: 'Gulf Office Supplies LLC',
  contacts: { phone: '+971501234567', email: 'accounts@gulfoffice.example', tradeLicence: null },
  source: { kind: 'registry', ref: 'DED-REG-88112' },
};

const services = () => ({ keys, ids, logger: testLogger() });

/** The owner's session named into an organisation, so its tenant wall lets it reach that organisation's rows. */
const ORG_NAMED = "select pg_catalog.set_config('app.org_id', $1, false)";

const organization = async (): Promise<string> => {
  const id = ids.next();
  await withSignedStates(app, id, services(), (tx, states) =>
    createOrganization(tx, states, { id, name: 'Acme Trading LLC', actor: ADMIN }),
  );
  return id;
};

/** A supplier added with its setting (`remittanceEmail`), or as before 0061 with none (`unset`). */
async function supplier(orgId: string, remittanceEmail: RemittanceEmail | 'unset'): Promise<string> {
  const id = ids.next();
  const added = { orgId, id, versionId: ids.next(), supplier: DETAILS, enteredBy: ids.next(), createdAt: clock.now() };
  await withSignedStates(app, orgId, services(), (tx, states) =>
    remittanceEmail === 'unset'
      ? addSupplierUnset(tx, states, keys, { ...added, actor: ADMIN })
      : addSupplier(tx, states, keys, { ...added, remittanceEmail, actor: ADMIN }),
  );
  return id;
}

const read = (orgId: string, supplierId: string) =>
  withSignedStates(app, orgId, services(), (tx, states) => remittanceOf(tx, states, { orgId, supplierId }, 'share'));

/** Sets it as an admin would, from what a read for change gives. */
const set = (orgId: string, supplierId: string, remittanceEmail: RemittanceEmail) =>
  withSignedStates(app, orgId, services(), async (tx, states) => {
    const before = await remittanceOf(tx, states, { orgId, supplierId }, 'change');
    if (before.outcome === 'tampered') throw new Error('tampered');
    await setRemittance(tx, states, before, { orgId, supplierId, remittanceEmail, at: clock.now(), actor: ADMIN });
  });

const eventsAbout = (orgId: string, supplierId: string) =>
  database
    .as('backup')
    .query<{ action: string; subject_version: number }>(
      "select action, subject_version from audit.events where org_id = $1 and subject_id = $2 and subject_type = 'supplier_remittance' order by seq",
      [orgId, supplierId],
    );

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>({ ...database.connection('app'), maxConnections: 4 }, services().logger);
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`a supplier's remittance setting (0061, Postgres ${server.version})`, () => {
  it.each(['on', 'off'] as const)(
    'is added %s with its supplier, sealed, and read through its seal',
    async (choice) => {
      const org = await organization();
      const id = await supplier(org, choice);

      expect(await read(org, id)).toMatchObject({ outcome: 'set', remittanceEmail: choice });
      expect(await eventsAbout(org, id)).toEqual([{ action: 'supplier_remittance.chosen', subject_version: 1 }]);
    },
  );

  it('reads as on for a supplier added before 0061, its first setting adding and sealing its row', async () => {
    const org = await organization();
    const id = await supplier(org, 'unset');

    expect(await read(org, id)).toEqual({ outcome: 'unset', remittanceEmail: 'on' });
    await set(org, id, 'off');
    await set(org, id, 'on');

    expect(await read(org, id)).toMatchObject({ outcome: 'set', remittanceEmail: 'on' });
    expect(await eventsAbout(org, id)).toEqual([
      { action: 'supplier_remittance.chosen', subject_version: 1 },
      { action: 'supplier_remittance.changed', subject_version: 2 },
    ]);
  });

  it('is no other organisation’s: read there, it has none', async () => {
    const org = await organization();
    const id = await supplier(org, 'off');

    expect(await read(await organization(), id)).toEqual({ outcome: 'unset', remittanceEmail: 'on' });
  });

  it.each(['changed', 'deleted'] as const)('%s past the app, is tampered with: its alarm raised', async (how) => {
    const org = await organization();
    const id = await supplier(org, 'off');

    await database.as('owner').query(ORG_NAMED, [org]);
    if (how === 'changed') {
      await database
        .as('owner')
        .query("update suppliers.remittance_settings set remittance_email = 'on' where id = $1", [id]);
    } else {
      await database.as('owner').query('delete from suppliers.remittance_settings where id = $1', [id]);
    }

    expect(await read(org, id)).toMatchObject({ outcome: 'tampered' });
  });

  it('put back to its older, validly signed setting past the app, is tampered with (FX-TAMPER rollback, S205)', async () => {
    const org = await organization();
    const id = await supplier(org, 'on');
    const owner = database.as('owner');
    await owner.query(ORG_NAMED, [org]);
    const [saved] = await owner.query<{ row: string }>(
      'select pg_catalog.to_jsonb(t)::text as row from suppliers.remittance_settings t where t.id = $1',
      [id],
    );
    await set(org, id, 'off');
    await owner.query(
      `update suppliers.remittance_settings t set remittance_email = old.remittance_email
         from pg_catalog.jsonb_populate_record(null::suppliers.remittance_settings, $2::jsonb) old where t.id = $1`,
      [id, saved?.row],
    );

    expect(await read(org, id)).toMatchObject({ outcome: 'tampered' });
  });

  describe('SEC-DB-10 R-15 as the database owner, holding none of the app keys (S207, GM-2)', () => {
    /** A supplier of a fresh organisation, set as asked, the owner's session named into that organisation. */
    async function ownersSupplier(remittanceEmail: RemittanceEmail | 'unset') {
      const org = await organization();
      const id = await supplier(org, remittanceEmail);
      const owner = database.as('owner');
      await owner.query(ORG_NAMED, [org]);
      return { org, id, owner };
    }

    it('control: a setting the owner reads, and writes back as it was, is still believed', async () => {
      const { org, id, owner } = await ownersSupplier('on');
      await owner.query('update suppliers.remittance_settings set remittance_email = remittance_email where id = $1', [
        id,
      ]);

      expect(await read(org, id)).toMatchObject({ outcome: 'set', remittanceEmail: 'on' });
    });

    it('switched from on to off, so a payment goes unannounced, is tampered with', async () => {
      const { org, id, owner } = await ownersSupplier('on');
      await owner.query("update suppliers.remittance_settings set remittance_email = 'off' where id = $1", [id]);

      expect(await read(org, id)).toMatchObject({ outcome: 'tampered' });
    });

    it.each([
      [
        'its signed version moved on',
        'update suppliers.remittance_settings set state_version = state_version + 1 where id = $1',
      ],
      [
        'its signed event pointed at another supplier’s',
        'update suppliers.remittance_settings set state_event_id = (select state_event_id from suppliers.remittance_settings where id = $2) where id = $1',
      ],
    ])('with %s, is tampered with', async (_, statement) => {
      const { org, id, owner } = await ownersSupplier('on');
      const other = await supplier(org, 'on');
      // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text from the table above; every value is bound.
      await owner.query(statement, statement.includes('$2') ? [id, other] : [id]);

      expect(await read(org, id)).toMatchObject({ outcome: 'tampered' });
      // The other supplier's own setting, untouched, still holds.
      expect(await read(org, other)).toMatchObject({ outcome: 'set', remittanceEmail: 'on' });
    });

    it('put back whole to its older signed version, its version and event with it, is tampered with', async () => {
      const { org, id, owner } = await ownersSupplier('on');
      const [saved] = await owner.query<{ row: string }>(
        'select pg_catalog.to_jsonb(t)::text as row from suppliers.remittance_settings t where t.id = $1',
        [id],
      );
      await set(org, id, 'off');
      await owner.query(
        `update suppliers.remittance_settings t
           set remittance_email = old.remittance_email, state_version = old.state_version, state_event_id = old.state_event_id
           from pg_catalog.jsonb_populate_record(null::suppliers.remittance_settings, $2::jsonb) old where t.id = $1`,
        [id, saved?.row],
      );

      expect(await read(org, id)).toMatchObject({ outcome: 'tampered' });
    });

    it('planted for a supplier added before 0061, set to off, is tampered with, never read as off', async () => {
      const { org, id, owner } = await ownersSupplier('unset');
      await owner.query(
        `insert into suppliers.remittance_settings (org_id, id, remittance_email, created_at) values ($1, $2, 'off', now())`,
        [org, id],
      );

      expect(await read(org, id)).toMatchObject({ outcome: 'tampered' });
    });
  });

  it('lets the app neither delete a row, nor move its supplier or when it was made', async () => {
    const as = database.as('app');
    await expect(as.query('delete from suppliers.remittance_settings')).rejects.toThrow('permission denied');
    await expect(as.query('update suppliers.remittance_settings set id = id')).rejects.toThrow('permission denied');
    await expect(as.query('update suppliers.remittance_settings set created_at = created_at')).rejects.toThrow(
      'permission denied',
    );
  });

  it('holds the setting to on or off', async () => {
    const org = await organization();
    const id = await supplier(org, 'on');
    await database.as('owner').query(ORG_NAMED, [org]);

    await expect(
      database
        .as('owner')
        .query("update suppliers.remittance_settings set remittance_email = 'maybe' where id = $1", [id]),
    ).rejects.toThrow('remittance_settings_remittance_email_check');
  });
});
