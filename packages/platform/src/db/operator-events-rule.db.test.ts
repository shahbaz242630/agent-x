// PL-57: the operator's events added by its role alone (and the owner, for
// E10's repair, who could drop the rule anyway). The readers already
// refuse an operator's event without its signature; this is the database's own
// rule beside them, so the API's role can't even add one, on either chain. A
// trigger on a table already built, so it came in two releases (the guard's
// header): 0079's image knew it as coming, and 0080 writes it.
import { createTestDatabase, type TestClient, type TestDatabase } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import BUILT_CHECKS from './built-checks.json' with { type: 'json' };
import BUILT_TABLES from './built-tables.json' with { type: 'json' };
import { BUILT_TRIGGERS, liveSchemaDrift, MARK_TRIGGERS, OPERATOR_EVENT_TRIGGERS } from './schema-guard.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

const ORG = '0199a0f0-0000-7000-8000-0000000000b1';

/** An event on the organisation's chain (`$2`) in `$1`'s name; only its actor matters here, the rest only fits the table. */
const ORG_EVENT = `insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type,
    subject_id, subject_version, details, prev_hash, hash, mac, mac_key_version)
  values ($2, 1, '0199a0f0-0000-7000-8000-0000000000b2', pg_catalog.now(), 'system', $1, 'organization.freeze',
    'organization', $2, 1, '{}', pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
    pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.decode('00', 'hex'), 1)`;

/** The same on the platform chain, of no organisation. */
const PLATFORM_EVENT = `insert into platform_controls.audit_events (seq, id, recorded_at, actor_type, actor_id, action,
    details, prev_hash, hash, mac, mac_key_version)
  values (1, '0199a0f0-0000-7000-8000-0000000000b3', pg_catalog.now(), 'system', $1, 'operator.handoff_paused', '{}',
    pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
    pg_catalog.decode('00', 'hex'), 1)`;

/** Whether `role` may add the event in the name `values` begins with: tried in a transaction always rolled back. */
async function added(
  role: 'app' | 'operator' | 'owner',
  statement: string,
  values: readonly string[],
): Promise<unknown> {
  const client: TestClient = await database.connect(role);
  try {
    await client.query('begin');
    await client.query("select pg_catalog.set_config('app.org_id', $1, true)", [ORG]);
    // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text, written above.
    await client.query(statement, values);
    return 'added';
  } catch (error) {
    return { code: (error as { code?: unknown }).code, message: (error as Error).message };
  } finally {
    await client.query('rollback');
    await client.end();
  }
}

const REFUSED = { code: '42501', message: "only the operator's role records an event in its name" };

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase(
    { ...database.connection('app'), tls: 'disable' },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'error', eventCapPerMinute: 1000 } },
      destination: { write: () => undefined },
    }),
  );
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the operator's events added by its role alone (PL-57, Postgres ${server.version})`, () => {
  it('reads to this image as built: nothing at all', async () => {
    expect(BUILT_TRIGGERS).toEqual(expect.arrayContaining([...OPERATOR_EVENT_TRIGGERS]));
    expect(await liveSchemaDrift(app, ROLES)).toEqual({ atOnce: [], releaseShaped: [] });
  });

  // The image before 0080 knew the marks' triggers as written and these two as coming.
  const imageBefore = { ...ROLES, built: { triggers: MARK_TRIGGERS, tables: BUILT_TABLES, checks: BUILT_CHECKS } };

  it('reads to the image before as release-shaped alone, so 0080 raises no alarm as it ends', async () => {
    expect(await liveSchemaDrift(app, { ...imageBefore, comingTriggers: OPERATOR_EVENT_TRIGGERS })).toEqual({
      atOnce: [],
      releaseShaped: [
        'audit.events carries "operator_events_by_operator", a coming trigger',
        'platform_controls.audit_events carries "operator_events_by_operator", a coming trigger',
      ],
    });
  });

  it('is the alarm at once to an image that never knew it: why 0079 had to reach a release first', async () => {
    const { atOnce } = await liveSchemaDrift(app, { ...imageBefore, comingTriggers: [] });
    expect(atOnce).toEqual([
      'audit.events carries the trigger "operator_events_by_operator"',
      'platform_controls.audit_events carries the trigger "operator_events_by_operator"',
    ]);
  });

  it.each([
    ["an organisation's chain", ORG_EVENT, [ORG]],
    ['the platform chain', PLATFORM_EVENT, []],
  ])("refuses the API's role an event in the operator's name on %s", async (_chain, statement, rest) => {
    expect(await added('app', statement, ['operator', ...rest])).toEqual(REFUSED);
    // Its own events, and the operator's by the operator's role or by the owner (E10's repair), pass.
    expect(await added('app', statement, ['api', ...rest])).toBe('added');
    expect(await added('operator', statement, ['operator', ...rest])).toBe('added');
    expect(await added('owner', statement, ['operator', ...rest])).toBe('added');
  });
});
