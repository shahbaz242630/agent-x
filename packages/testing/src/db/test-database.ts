// A database of its own for each test file (Rule Book §6: real Postgres, no
// mocks), so files run in parallel without seeing each other's rows. It is a
// copy of the migrated template, or an empty database for the migration
// runner's own tests, with the same connect rights db/bootstrap/database.sql
// gives the real one.
import { randomUUID } from 'node:crypto';

import pg from 'pg';

import type { TestLogin, TestPostgresServer } from './test-server.ts';

/** Who a test connects as. `admin` is the server's superuser, for setup and for playing the attacker. */
export type TestRole = 'admin' | 'owner' | 'app' | 'backup';

/** Connection settings in the shape @agentx/platform/db takes. */
export interface TestConnection {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly password: string;
  readonly tls: 'disable';
}

/** Runs SQL as one role. The text is fixed; values go in `values`, as bound parameters. */
export interface TestSession {
  query<Row extends object = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<Row[]>;
}

/**
 * One connection of its own, for work that must stay on a single connection:
 * a transaction, a lock, a party in a race (FX-RACE). Every query runs on it.
 */
export interface TestClient extends TestSession {
  /** The connection's server process ID, which pg_blocking_pids reports. */
  readonly pid: number;
  /** Closes the connection; a transaction still open on it rolls back. */
  end(): Promise<void>;
}

export interface TestDatabase {
  readonly name: string;
  readonly server: TestPostgresServer;
  connection(role: TestRole): TestConnection;
  /** A session for the role, opened on first use and closed by `drop()`. */
  as(role: TestRole): TestSession;
  /** Opens a connection of its own for the role. `drop()` closes it if the test hasn't. */
  connect(role: TestRole): Promise<TestClient>;
  /** Closes every session and connection, and deletes the database. */
  drop(): Promise<void>;
}

function loginFor(server: TestPostgresServer, role: TestRole): TestLogin {
  return role === 'admin' ? server.admin : server.roles[role];
}

function connectionFor(server: TestPostgresServer, role: TestRole, database: string): TestConnection {
  const login = loginFor(server, role);
  return { host: server.host, port: server.port, database, user: login.user, password: login.password, tls: 'disable' };
}

function poolFor(connection: TestConnection): pg.Pool {
  return new pg.Pool({ ...connection, ssl: false, max: 4 });
}

/** Runs statements that name the database itself, as the superuser, from the server's maintenance database. */
async function onServer(server: TestPostgresServer, statements: readonly string[]): Promise<void> {
  const client = new pg.Client({ ...connectionFor(server, 'admin', 'postgres'), ssl: false });
  await client.connect();
  try {
    for (const statement of statements) {
      // eslint-disable-next-line agentx/no-string-built-sql -- CREATE and DROP DATABASE can't take names as parameters; every name here is generated or configured, and quoted with escapeIdentifier.
      await client.query(statement);
    }
  } finally {
    await client.end();
  }
}

/**
 * Creates a database for one test file: a copy of the migrated template, or
 * an empty one owned by agentx_owner with no migrations applied.
 */
export async function createTestDatabase(
  server: TestPostgresServer,
  options: { readonly schema: 'migrated' | 'empty' },
): Promise<TestDatabase> {
  const name = `t_${randomUUID().replaceAll('-', '')}`;
  const quoted = pg.escapeIdentifier(name);
  const template = options.schema === 'migrated' ? pg.escapeIdentifier(server.templateDatabase) : 'template0';

  await onServer(server, [
    `CREATE DATABASE ${quoted} TEMPLATE ${template} OWNER ${pg.escapeIdentifier(server.roles.owner.user)}`,
    `REVOKE ALL ON DATABASE ${quoted} FROM PUBLIC`,
    `GRANT CONNECT ON DATABASE ${quoted} TO ${pg.escapeIdentifier(server.roles.app.user)}, ${pg.escapeIdentifier(server.roles.backup.user)}`,
  ]);

  const pools = new Map<TestRole, pg.Pool>();
  const poolOf = (role: TestRole): pg.Pool => {
    let pool = pools.get(role);
    if (pool === undefined) {
      pool = poolFor(connectionFor(server, role, name));
      pools.set(role, pool);
    }
    return pool;
  };
  const clients: TestClient[] = [];

  return {
    name,
    server,
    connection: (role) => connectionFor(server, role, name),
    as: (role) => ({
      query: async <Row extends object>(text: string, values: readonly unknown[] = []) => {
        // eslint-disable-next-line agentx/no-string-built-sql -- This passes on the caller's text; the rule checks it where the caller writes `.query(...)`.
        const result = await poolOf(role).query<Row>(text, [...values]);
        return result.rows;
      },
    }),
    connect: async (role) => {
      const client = await openClient(connectionFor(server, role, name));
      clients.push(client);
      return client;
    },
    drop: async () => {
      // pg's end() does nothing for a connection that is already closed, such as one the test closed itself.
      await Promise.all(clients.map((client) => client.end()));
      await Promise.all([...pools.values()].map((pool) => pool.end()));
      pools.clear();
      await onServer(server, [`DROP DATABASE IF EXISTS ${quoted} WITH (FORCE)`]);
    },
  };
}

/** Opens a connection of its own. */
async function openClient(connection: TestConnection): Promise<TestClient> {
  const client = new pg.Client({ ...connection, ssl: false });
  // A connection the server ends reports it as an 'error' event, which would
  // stop the test process if nothing listened. The next query then fails with
  // pg's own error, so nothing is hidden.
  client.on('error', () => undefined);
  await client.connect();
  const { rows } = await client.query<{ pid: number }>('select pg_catalog.pg_backend_pid() as pid');
  const pid = rows[0]?.pid;
  if (pid === undefined) throw new Error('The new test connection reported no server process ID');
  return {
    pid,
    query: async <Row extends object>(text: string, values: readonly unknown[] = []) => {
      // eslint-disable-next-line agentx/no-string-built-sql -- This passes on the caller's text; the rule checks it where the caller writes `.query(...)`.
      const result = await client.query<Row>(text, [...values]);
      return result.rows;
    },
    end: () => client.end(),
  };
}
