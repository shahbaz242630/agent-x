// PL-57: the operator's events added by its role alone (and the owner, for
// E10's repair, who could drop the rule anyway). The readers already
// refuse an operator's event without its signature; this is the database's own
// rule beside them, so the API's role can't even add one, on either chain. A
// trigger on a table already built, so it comes in two releases (the guard's
// header): this image knows it (COMING_TRIGGERS), and the migration below runs
// in the next. RULE is that migration's text, word for word: applied here as
// the owner, it must read to this image as exactly the coming trigger, no more.
import { createTestDatabase, type TestClient, type TestDatabase, type TestSession } from '@agentx/testing';
import type { Kysely } from 'kysely';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { createLogger } from '../observability/index.ts';
import { createDatabase } from './database.ts';
import { liveSchemaDrift } from './schema-guard.ts';

const server = inject('postgres');
let database: TestDatabase;
let app: Kysely<unknown>;
let owner: TestSession;

const ROLES = { appRole: 'agentx_app', ownerRole: 'agentx_owner' } as const;

/**
 * The coming migration, as it will be written: the function, then its trigger on each chain's events. It refuses
 * every role but the operator's and the owner's: E10's repair puts a chain's original rows back (an operator's event
 * among them) as the owner, and the owner could drop the trigger anyway. The threat it closes is the API's role.
 */
const RULE = `
CREATE FUNCTION audit.operator_events_by_operator() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
begin
  if current_user not in ('agentx_operator', 'agentx_owner') then
    raise exception 'only the operator''s role records an event in its name' using errcode = 'insufficient_privilege';
  end if;
  return new;
end
$$;

CREATE TRIGGER operator_events_by_operator BEFORE INSERT ON audit.events
  FOR EACH ROW WHEN (new.actor_id = 'operator') EXECUTE FUNCTION audit.operator_events_by_operator();

CREATE TRIGGER operator_events_by_operator BEFORE INSERT ON platform_controls.audit_events
  FOR EACH ROW WHEN (new.actor_id = 'operator') EXECUTE FUNCTION audit.operator_events_by_operator();
`;

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
  owner = database.as('owner');
  app = createDatabase(
    { ...database.connection('app'), tls: 'disable' },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'error', eventCapPerMinute: 1000 } },
      destination: { write: () => undefined },
    }),
  );
  await owner.query(RULE);
}, 60_000);

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

describe(`the operator's events added by its role alone (PL-57, Postgres ${server.version})`, () => {
  it('reads to this image as exactly the coming triggers, and nothing at once', async () => {
    expect(await liveSchemaDrift(app, ROLES)).toEqual({
      atOnce: [],
      releaseShaped: [
        'audit.events carries "operator_events_by_operator", a coming trigger',
        'platform_controls.audit_events carries "operator_events_by_operator", a coming trigger',
      ],
    });
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
