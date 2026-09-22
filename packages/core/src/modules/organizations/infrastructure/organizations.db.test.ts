// B1a: an organisation's row and its directory entry (0007, 0008), on the
// real migrated schema, as the app role. What the owner can do past the app
// is owner-tamper.db.test.ts.
import { createTestDatabase, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
import { createKeyProvider, type KeyMaterial, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, type AuditTrail, createAuditTrail, createSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import { OrganizationRefused } from '../domain/organization.ts';
import { createOrganization, ORGANIZATIONS, type OrganizationsTransaction } from './organizations.ts';
import type { OrganizationsTables } from './tables.ts';

type Tables = OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ) as unknown as KeyMaterial,
);
const trail: AuditTrail = createAuditTrail({ keys, ids: new SequentialIds(0x400) });

let capture: LogCapture;
const statesFor = () =>
  createSignedStates({
    keys,
    trail,
    logger: createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: capture,
    }),
  });

let number = 0;
/** A new UUID, so no two tests share an organisation. */
const newId = (): string => {
  number += 1;
  return `0199a0f0-0000-7000-8000-${(0x4000 + number).toString(16).padStart(12, '0')}`;
};

const OPERATOR = { type: 'system' as const, id: 'test-operator' };

const create = (id: string, name = 'Acme Trading LLC') =>
  withTenant(app, id, (tx: OrganizationsTransaction) =>
    createOrganization(tx, statesFor(), { id, name, actor: OPERATOR }),
  );

const verified = (orgId: string, id = orgId) =>
  withTenant(app, orgId, (tx) => statesFor().verifiedState(tx, ORGANIZATIONS, { orgId, id }, 'share'));

const listed = async (id: string): Promise<boolean> => {
  const rows = await app.selectFrom('directory.orgs').select('org_id').where('org_id', '=', id).execute();
  return rows.length === 1;
};

const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(
    { ...database.connection('app'), maxConnections: 4 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe(`creating an organisation (B1a, Postgres ${server.version})`, () => {
  it('creates it ACTIVE and listed in the directory, its first signed state starting its audit chain', async () => {
    const id = newId();

    const recorded = await create(id);

    expect(recorded).toMatchObject({ version: 1, seq: 1n });
    expect(await verified(id)).toEqual({
      outcome: 'verified',
      version: 1,
      eventId: recorded.eventId.toLowerCase(),
      fields: new Map([['status', 'ACTIVE']]),
    });
    expect(await listed(id)).toBe(true);
    const { row, events, chain } = await withTenant(app, id, async (tx) => ({
      row: await tx.selectFrom('organizations.organizations').selectAll().executeTakeFirstOrThrow(),
      events: await tx
        .selectFrom('audit.events')
        .select(['seq', 'actor_type', 'actor_id', 'action', 'subject_type', 'subject_id', 'subject_version'])
        .execute(),
      chain: await trail.verify(tx, id, undefined),
    }));
    expect(row).toEqual({
      org_id: id,
      id,
      name: 'Acme Trading LLC',
      status: 'ACTIVE',
      state_version: 1,
      state_event_id: recorded.eventId.toLowerCase(),
    });
    expect(events).toEqual([
      {
        seq: 1n,
        actor_type: 'system',
        actor_id: 'test-operator',
        action: 'organization.created',
        subject_type: 'organization',
        subject_id: id,
        subject_version: 1,
      },
    ]);
    expect(chain).toMatchObject({ ok: true, seq: 1n });
    expect(alarms()).toEqual([]);
  });

  it('keeps a name in any script, stored exactly as given', async () => {
    const id = newId();
    const name = String.fromCodePoint(0x634, 0x631, 0x643, 0x629, 0x20, 0x1d49c);

    await create(id, name);

    const row = await withTenant(app, id, (tx) =>
      tx.selectFrom('organizations.organizations').select('name').executeTakeFirstOrThrow(),
    );
    expect(row.name).toBe(name);
  });

  it('refuses a name it cannot have before anything is written', async () => {
    const id = newId();

    await expect(create(id, ' Acme')).rejects.toBeInstanceOf(OrganizationRefused);

    expect(await listed(id)).toBe(false);
    expect(await verified(id)).toEqual({ outcome: 'missing' });
  });

  it('refuses an organisation that exists already, leaving the first as it was', async () => {
    const id = newId();
    const first = await create(id);

    await expect(create(id, 'Another Name')).rejects.toMatchObject({ code: '23505', constraint: 'orgs_pkey' });

    expect(await verified(id)).toMatchObject({ outcome: 'verified', version: 1, eventId: first.eventId.toLowerCase() });
    const chain = await withTenant(app, id, (tx) => trail.verify(tx, id, undefined));
    expect(chain).toMatchObject({ ok: true, seq: 1n });
  });

  it("refuses a transaction that isn't withTenant's for the organisation, writing nothing for either", async () => {
    const id = newId();
    const other = newId();

    await expect(
      withTenant(app, other, (tx) => createOrganization(tx, statesFor(), { id, name: 'Acme', actor: OPERATOR })),
    ).rejects.toBeInstanceOf(TenantContextError);

    expect(await listed(id)).toBe(false);
    expect(await listed(other)).toBe(false);
  });
});

describe('the walls round an organisation’s row', () => {
  it('SEC-TEN-02 another organisation’s row is out of sight with no filter at all: row security alone', async () => {
    const mine = newId();
    const theirs = newId();
    await create(mine);
    await create(theirs, 'Their Company');

    const seen = await withTenant(app, mine, (tx) =>
      tx.selectFrom('organizations.organizations').select(['org_id', 'id', 'name']).execute(),
    );
    expect(seen).toEqual([{ org_id: mine, id: mine, name: 'Acme Trading LLC' }]);
    // With no tenant at all, nothing.
    expect(await app.selectFrom('organizations.organizations').select('id').execute()).toEqual([]);
    // Asked for by its key from inside another organisation, it doesn't exist.
    expect(await verified(mine, theirs)).toEqual({ outcome: 'missing' });
    // The directory is the one list of every organisation, and it holds IDs alone.
    expect(await listed(mine)).toBe(true);
    expect(await listed(theirs)).toBe(true);
  });

  it('a row written for another organisation is refused by the policy’s check', async () => {
    const mine = newId();
    const theirs = newId();
    await create(mine);
    await create(theirs);

    await expect(
      withTenant(app, mine, (tx) =>
        tx
          .insertInto('organizations.organizations')
          .values({ org_id: theirs, id: theirs, name: 'Planted', status: 'ACTIVE' })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('the app can’t delete an organisation or rename it, nor take it off the directory or change its entry', async () => {
    const id = newId();
    await create(id);

    const attempts: ((tx: OrganizationsTransaction) => Promise<unknown>)[] = [
      (tx) => tx.deleteFrom('organizations.organizations').where('id', '=', id).execute(),
      (tx) => tx.updateTable('organizations.organizations').set({ name: 'Renamed' }).where('id', '=', id).execute(),
      (tx) => tx.deleteFrom('directory.orgs').where('org_id', '=', id).execute(),
      (tx) => tx.updateTable('directory.orgs').set({ org_id: newId() }).where('org_id', '=', id).execute(),
    ];
    for (const attempt of attempts) {
      await expect(withTenant(app, id, attempt)).rejects.toMatchObject({ code: '42501' });
    }

    expect(await verified(id)).toMatchObject({ outcome: 'verified', version: 1 });
    expect(await listed(id)).toBe(true);
  });

  it('a row with no directory entry is refused by its foreign key, so the list can’t leave an organisation out', async () => {
    const id = newId();

    await expect(
      withTenant(app, id, (tx) =>
        tx
          .insertInto('organizations.organizations')
          .values({ org_id: id, id, name: 'Unlisted', status: 'ACTIVE' })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23503', constraint: 'organizations_org_id_fkey' });
  });

  it('a second row in the same organisation is refused: an organisation is its own row', async () => {
    const id = newId();
    await create(id);

    await expect(
      withTenant(app, id, (tx) =>
        tx
          .insertInto('organizations.organizations')
          .values({ org_id: id, id: newId(), name: 'Second', status: 'ACTIVE' })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23514', constraint: 'one_row_per_organization' });
  });

  it('a name past the module’s own check is held to the same length by the table, counted the same way', async () => {
    /** Writes a row with this name past the module, in a transaction that is then rolled back. */
    const writtenPastTheModule = (name: string) => {
      const id = newId();
      return withTenant(app, id, async (tx) => {
        await tx.insertInto('directory.orgs').values({ org_id: id }).execute();
        await tx.insertInto('organizations.organizations').values({ org_id: id, id, name, status: 'ACTIVE' }).execute();
        throw new Error('rolled back');
      });
    };
    const wide = String.fromCodePoint(0x1d49c);

    for (const name of ['', 'a'.repeat(201), wide.repeat(201)]) {
      await expect(writtenPastTheModule(name)).rejects.toMatchObject({
        code: '23514',
        constraint: 'organizations_name_check',
      });
    }
    await expect(writtenPastTheModule(wide.repeat(200))).rejects.toThrow('rolled back');
  });

  it('the backup role reads both tables, every organisation’s rows, as a logical backup must', async () => {
    const id = newId();
    await create(id);
    const backup = database.as('backup');

    expect(await backup.query('select org_id from directory.orgs where org_id = $1', [id])).toEqual([{ org_id: id }]);
    expect(await backup.query('select id, status from organizations.organizations where id = $1', [id])).toEqual([
      { id, status: 'ACTIVE' },
    ]);
  });
});

describe('an organisation’s status', () => {
  const change = (action: string) => ({ actor: { type: 'user' as const, id: newId() }, action, details: {} });
  const move = (id: string, event: 'freeze' | 'unfreeze') =>
    withTenant(app, id, (tx) =>
      statesFor().changeStatus(tx, ORGANIZATIONS, { orgId: id, id }, event, change(`organization.${event}`)),
    );

  it('moves by freeze and unfreeze, each a new signed state', async () => {
    const id = newId();
    await create(id);

    expect(await move(id, 'freeze')).toMatchObject({ outcome: 'changed', from: 'ACTIVE', to: 'FROZEN', version: 2 });
    expect(await verified(id)).toMatchObject({ version: 2, fields: new Map([['status', 'FROZEN']]) });
    expect(await move(id, 'freeze')).toEqual({ outcome: 'refused', from: 'FROZEN' });
    expect(await move(id, 'unfreeze')).toMatchObject({ outcome: 'changed', from: 'FROZEN', to: 'ACTIVE', version: 3 });
    expect(await verified(id)).toMatchObject({ version: 3, fields: new Map([['status', 'ACTIVE']]) });
    expect(alarms()).toEqual([]);
  });

  it('starts ACTIVE whatever the insert says: the status guard refuses any other', async () => {
    const id = newId();

    await expect(
      withTenant(app, id, async (tx) => {
        await tx.insertInto('directory.orgs').values({ org_id: id }).execute();
        await tx
          .insertInto('organizations.organizations')
          .values({ org_id: id, id, name: 'Born Frozen', status: 'FROZEN' })
          .execute();
      }),
    ).rejects.toMatchObject({ code: '23514', constraint: 'status_guard' });
  });
});
