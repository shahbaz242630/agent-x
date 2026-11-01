// ADR-005 §2, §4: tenant data is reached only inside withTenant. Every tenant
// table has forced row-level security with one policy, which lets a query see
// or write a row only when the row's org_id equals the `app.org_id` setting:
//
//   org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid
//
// withTenant opens a transaction and sets `app.org_id` for that transaction
// only (set_config's third argument). The setting is gone at commit or
// rollback, so a pooled connection doesn't carry it to the next caller. With
// no setting, or an empty one, the policy matches no rows: it fails closed.
//
// SEC-TEN-06: a setting made for the whole session (by a bug or injected SQL
// inside the work, or before a connection was opened) would outlive the
// transaction. So every connection is checked when it is opened, and again
// each time it is taken from the pool, before its first statement. This is the
// only product file that names the setting (lint), and pg_catalog is named
// explicitly, so no other function called set_config can stand in.
//
// 4D2d P11: the checks travel with the statements they guard, a round trip
// fewer each. A transaction's start carries the connection's check and the
// organisation's setting with its read-back; its commit carries the read-back
// before commit, which refuses the commit in the database itself.
import { AsyncLocalStorage } from 'node:async_hooks';

import {
  type CompiledQuery,
  type DatabaseConnection,
  type Driver,
  type Kysely,
  PostgresDialect,
  type QueryExecutorProvider,
  type QueryResult,
  type RawBuilder,
  sql,
  type Transaction,
  type TransactionSettings,
} from 'kysely';
import type pg from 'pg';

import type { Logger } from '../observability/index.ts';
import {
  createOrganisationShares,
  isAgentTraffic,
  OrganisationBusy,
  type OrganisationShares,
} from './organisation-shares.ts';
import { UUID } from './patterns.ts';
import { PINNED_SEARCH_PATH_VALUE } from './search-path.ts';
import { timedPoolWait, timedTrip } from './statement-times.ts';

/**
 * The tenant policy's expression as `pg_get_expr` prints it back, which the
 * live schema guard (A3e-1b) compares every tenant table's policy with.
 *
 * It lives here because this is the one product file allowed to name the
 * setting (lint), and the policy is the other half of what withTenant sets:
 * the two have to say the same thing or the walls don't hold. How Postgres
 * prints it can differ between major versions, so schema-guard.db.test.ts
 * proves this is what the server really says on each version we support — a
 * future major that words it differently fails there, never silently.
 */
export const TENANT_POLICY_EXPRESSION =
  "(org_id = (NULLIF(current_setting('app.org_id'::text, true), ''::text))::uuid)";

export class TenantContextError extends Error {
  constructor(problem: string) {
    super(`Tenant context refused: ${problem}`);
    this.name = 'TenantContextError';
  }
}

/**
 * Open while withTenant's transaction runs, to refuse a second withTenant
 * inside it. Callbacks the work starts (a timer, say) inherit the scope, so it
 * is closed when the transaction ends: after that they may use withTenant.
 */
const insideTenant = new AsyncLocalStorage<{ open: boolean }>();

/**
 * The organisation withTenant set, in lower case, for each transaction it has
 * open (4D2d P1, decision 41). assertTenant compares with this instead of
 * asking the database each time; a transaction withTenant didn't open (or a
 * handle made from one, a different object) is still asked the database.
 */
const tenantOf = new WeakMap<object, string>();

/**
 * A transaction withTenant or limitedTransaction is about to open, which the
 * driver opens with its settings in the start's own round trip (4D2d P11). The
 * first transaction begun in its scope takes it, so one begun inside the work
 * (another connection's) opens as a plain one.
 */
interface Opening {
  /** The organisation, in lower case; none for a plain limited transaction, which is `limited`: an opening sets one or both. */
  readonly tenant: string | undefined;
  readonly limited: boolean;
  /** Outside the organisation's share of the connections, though an agent's request: its integrity hold and its activity row must not queue. */
  readonly unshared: boolean;
  taken: boolean;
}

const opening = new AsyncLocalStorage<Opening>();

/**
 * Runs `work` in one READ COMMITTED transaction scoped to the organisation.
 * The orgId must come from the server (the authenticated principal or the
 * directory), never from the request (ADR-005 §5). It commits when `work`
 * resolves and rolls back when it throws. It can't be nested: a second
 * withTenant inside `work` would open another transaction on another
 * connection, committed separately, and under load every connection could
 * end up waiting on another. `limited`: every statement is limited as
 * limitStatements limits them, set with the organisation in one round trip
 * (4D2d P4). `unshared`: outside the organisation's share of the connections
 * (organisation-shares.ts) though an agent's request: for its integrity hold and activity row.
 */
export async function withTenant<Schema, Result>(
  db: Kysely<Schema>,
  orgId: string,
  work: (tx: Transaction<Schema>) => Promise<Result>,
  { limited = false, unshared = false }: { readonly limited?: boolean; readonly unshared?: boolean } = {},
): Promise<Result> {
  // Checked before the transaction opens; the ID itself is never echoed.
  if (!UUID.test(orgId)) throw new TenantContextError('the organisation ID is not a UUID');
  if (insideTenant.getStore()?.open === true) {
    throw new TenantContextError('withTenant was called inside another withTenant; pass the transaction on instead');
  }
  const scope = { open: true };
  const tenant = orgId.toLowerCase();
  const asked: Opening = { tenant, limited, unshared, taken: false };
  try {
    return await insideTenant.run(scope, () =>
      openedWith(db, asked, async (tx) => {
        // The driver set the organisation and read it back with the start (decision 41), and reads
        // it back again with the commit. Only createDatabase's driver does: with any other, nothing
        // would be walled to the organisation, so nothing runs.
        if (!asked.taken) throw new TenantContextError("this database can't set an organisation");
        tenantOf.set(tx, tenant);
        try {
          return await work(tx);
        } finally {
          tenantOf.delete(tx);
        }
      }),
    );
  } finally {
    scope.open = false;
  }
}

/**
 * Runs `work` in one READ COMMITTED transaction with no organisation, each
 * statement limited as limitStatements limits them, set with the start in one
 * round trip (4D2d P11): a read across organisations, such as the directory's.
 */
export function limitedTransaction<Schema, Result>(
  db: Kysely<Schema>,
  work: (tx: Transaction<Schema>) => Promise<Result>,
): Promise<Result> {
  const asked: Opening = { tenant: undefined, limited: true, unshared: true, taken: false };
  return openedWith(db, asked, async (tx) => {
    // Another driver: the limit in a round trip of its own.
    if (!asked.taken) await limitStatements(tx);
    return work(tx);
  });
}

/**
 * One READ COMMITTED transaction, opened with `asked`. READ COMMITTED is
 * Postgres's default, but the default can be changed per server, database or
 * role; the locking rules in ADR-006 rely on it.
 */
function openedWith<Schema, Result>(
  db: Kysely<Schema>,
  asked: Opening,
  work: (tx: Transaction<Schema>) => Promise<Result>,
): Promise<Result> {
  return opening.run(asked, () => db.transaction().setIsolationLevel('read committed').execute(work));
}

/**
 * Refuses unless the transaction carries this organisation as its tenant,
 * which only withTenant sets (lint keeps the setting's name in this file).
 * Row security shows another tenant's rows as no rows at all, so work that
 * only reads, such as checking an audit chain, would take a wrong tenant's
 * view for an empty record.
 *
 * Inside a transaction withTenant opened, it compares with what withTenant
 * set, with no round trip: withTenant reads the setting back at the start and
 * again before commit (decision 41), so a setting changed and put back in
 * between goes unseen here. Any other transaction is asked.
 */
export async function assertTenant<Schema>(tx: Transaction<Schema>, orgId: string): Promise<void> {
  const tenant = tenantOf.get(tx) ?? (await settingOf(tx));
  if (!UUID.test(orgId) || !sameTenant(tenant, orgId.toLowerCase())) {
    throw new TenantContextError("the transaction isn't withTenant's for this organisation");
  }
}

/** The transaction's organisation setting as the database holds it, or '' for none. */
async function settingOf<Schema>(tx: Transaction<Schema>): Promise<string> {
  const { rows } = await sql<{ org_id: string | null }>`
    select pg_catalog.current_setting('app.org_id', true) as org_id
  `.execute(tx);
  return rows[0]?.org_id ?? '';
}

/** Whether a setting names the organisation, given in lower case. */
function sameTenant(setting: string | null | undefined, tenant: string): boolean {
  return (setting ?? '').toLowerCase() === tenant;
}

/** The longest a request's statement runs: a hung read gives its connection back, and the request fails rather than hangs. */
export const STATEMENT_SECONDS = 10;
const STATEMENT_TIMEOUT = `${String(STATEMENT_SECONDS)}s`;

/**
 * Limits every later statement of the transaction to STATEMENT_SECONDS, a wait
 * for a lock included, until the transaction ends: what a request's work sets
 * first, so the app layer needs no SQL of its own. withTenant's `limited`
 * sets the same with the organisation, and limitedTransaction with the start.
 */
export async function limitStatements<Schema>(tx: Transaction<Schema>): Promise<void> {
  await sql`select pg_catalog.set_config('statement_timeout', ${STATEMENT_TIMEOUT}, true)`.execute(tx);
}

/**
 * An expression that bounds how long the rest of the transaction waits for a
 * lock to 5 seconds, unless a shorter limit is set already, which is kept
 * (Postgres's `0` is no limit at all): set for the transaction alone, as SET
 * LOCAL sets it, inside a statement of the caller's (an idempotency claim's,
 * 4D2d P8). Its own value is never read.
 */
export function lockWaitBounded(): RawBuilder<unknown> {
  return sql`case when (pg_catalog.current_setting('lock_timeout')::interval = interval '0'
      or pg_catalog.current_setting('lock_timeout')::interval > interval '5 seconds') is not false
    then pg_catalog.set_config('lock_timeout', '5s', true) end`;
}

/** A lock's name, `agentx.<scope>:<id>…` with the IDs in lower case, so every taker of one lock names it alike. */
export const lockName = (scope: string, ...ids: readonly string[]): string =>
  `agentx.${scope}:${ids.map((id) => id.toLowerCase()).join(':')}`;

/**
 * Takes the lock lockName names until the transaction ends, waiting while
 * another transaction holds it: what serialises work no one row stands for,
 * such as two adds taking the last of a day's budget (ADR-006 §6).
 */
export async function holdTransactionLock<Schema>(
  tx: Transaction<Schema>,
  scope: string,
  ...ids: readonly string[]
): Promise<void> {
  const name = lockName(scope, ...ids);
  await sql`select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(${name}, 0))`.execute(tx);
}

/**
 * What a connection must carry before any work runs on it: no tenant, and the
 * `search_path` the startup packet pinned. Both come back from one statement,
 * so checking the second costs no extra round trip on a pooled connection.
 */
interface ConnectionState {
  /** Its `app.org_id` setting, or '' for none. */
  readonly tenant: string;
  /** Its `search_path`, which the startup packet pins to PINNED_SEARCH_PATH_VALUE. */
  readonly searchPath: string;
}

/** Both settings in one statement, so the search_path costs no extra round trip. */
const CONNECTION_STATE =
  "select pg_catalog.current_setting('app.org_id', true) as org_id, pg_catalog.current_setting('search_path', true) as search_path";

/** A state row as the database gave it. */
type StateRow = { org_id?: string | null; search_path?: string | null } | undefined;

function stateFrom(row: StateRow): ConnectionState {
  return { tenant: row?.org_id ?? '', searchPath: row?.search_path ?? '' };
}

async function stateOf(client: pg.ClientBase): Promise<ConnectionState> {
  const { rows } = await client.query<{ org_id: string | null; search_path: string | null }>(CONNECTION_STATE);
  return stateFrom(rows[0]);
}

/**
 * The reason a connection can't be used, or undefined when it is sound.
 *
 * A connection must start with no tenant. One could arrive with a tenant
 * already set, by PGOPTIONS in the environment or by ALTER ROLE or ALTER
 * DATABASE … SET, which points at tampering or a bad setting.
 *
 * Its search_path must be the pinned one, exactly (A3e). The startup packet's
 * setting beats a setting on the database or the role, so this holds unless the
 * pin was dropped from poolConfig or something in the session changed it — and
 * with any other schema in front of pg_catalog, a planted function or operator
 * could stand in for one of Postgres's own, which is how canonical text (and
 * so a state seal) could be made to read alike for two different values.
 *
 * Compared whole rather than by parts: a path that merely *contains* pg_catalog
 * would pass while another schema sat in front of it, and `pg_temp` must keep
 * its place at the end (search-path.ts says why).
 */
function unusable({ tenant, searchPath }: ConnectionState): string | undefined {
  if (tenant !== '') {
    return 'it already carries an organisation (from PGOPTIONS, or ALTER ROLE or ALTER DATABASE ... SET)';
  }
  if (searchPath !== PINNED_SEARCH_PATH_VALUE) {
    // The path itself is not echoed: it names schemas, and the line is enough to find it.
    return `its search_path is not the pinned ${PINNED_SEARCH_PATH_VALUE}`;
  }
  return undefined;
}

/**
 * A new connection must be sound before anything runs on it. The pool runs
 * this on each new connection and closes the connection if it throws.
 */
export async function refuseTenantPreset(client: pg.ClientBase): Promise<void> {
  const problem = unusable(await stateOf(client));
  if (problem !== undefined) {
    throw new TenantContextError(`a new database connection is refused: ${problem}, so it is closed unused`);
  }
}

/**
 * The SQLSTATE the commit's read-back raises (division_by_zero), so the
 * driver knows its refusal: nothing else in the commit's round trip divides.
 */
const TENANT_CHANGED = '22012';

/**
 * The read-back before commit, in the commit's own round trip: it raises when
 * the setting no longer names the organisation, so the commit after it never
 * runs and the transaction is rolled back. The ID is written into the text
 * (a round trip of several statements takes no parameters). A plain select,
 * not a DO block: pg_stat_statements folds its constants into one entry,
 * where a DO block would keep one an organisation (P11 review). The setting
 * is read at run time, so the planner can't divide early.
 */
function stillTenant(tenant: string): string {
  return `select 1 / (case when pg_catalog.lower(pg_catalog.current_setting('app.org_id', true)) is distinct from '${written(tenant)}' then 0 else 1 end) as unchanged`;
}

/** What the start sets with it, in a statement of its own: the organisation, the statements' limit, or both. */
function startSettings({ tenant, limited }: Opening): string {
  const settings = [
    ...(tenant === undefined ? [] : [`pg_catalog.set_config('app.org_id', '${written(tenant)}', true) as org_id`]),
    ...(limited
      ? [`pg_catalog.set_config('statement_timeout', '${STATEMENT_TIMEOUT}', true) as statement_timeout`]
      : []),
  ];
  return `select ${settings.join(', ')}`;
}

/**
 * The organisation's ID to write into a statement's text: a UUID in lower
 * case, which nothing can break out of. Only withTenant's checked ID reaches
 * here; checked again, as text is no parameter.
 */
function written(tenant: string): string {
  if (!UUID.test(tenant) || tenant !== tenant.toLowerCase()) throw new TenantContextError('not a UUID in lower case');
  return tenant;
}

/** A transaction's start, as Kysely's own driver writes it. */
function startOf({ isolationLevel, accessMode }: TransactionSettings): string {
  if (isolationLevel === undefined && accessMode === undefined) return 'begin';
  return [
    'start transaction',
    ...(isolationLevel === undefined ? [] : [`isolation level ${isolationLevel}`]),
    ...(accessMode === undefined ? [] : [accessMode]),
  ].join(' ');
}

/** What a query answered, as Kysely's own driver gives it back. */
function resultOf<R>(result: pg.QueryResult): QueryResult<R> {
  const rows = result.rows as R[];
  return ['INSERT', 'UPDATE', 'DELETE', 'MERGE'].includes(result.command)
    ? { numAffectedRows: BigInt(result.rowCount ?? 0), rows }
    : { rows };
}

/** The opening the first transaction begun in its scope takes, or none. */
function taken(): Opening | undefined {
  const asked = opening.getStore();
  if (asked === undefined || asked.taken) return undefined;
  asked.taken = true;
  return asked;
}

/**
 * A pool connection that is checked before its first statement: with the
 * start, when that is a transaction's. One that carries a tenant or a changed
 * search_path was given a session-wide setting by an earlier caller, which is
 * a bug or an attack: it is closed (so any other session settings go with
 * it), the event is logged, and another connection is taken. New connections
 * are checked on opening, so after at most `attempts` tries one is sound, or
 * the pool is failing and the error says so.
 */
class CheckedConnection implements DatabaseConnection {
  readonly #pool: pg.Pool;
  readonly #logger: Logger;
  readonly #attempts: number;
  #client: pg.PoolClient | undefined;
  #checked = false;
  /** Closed rather than given back at release: a check failed on it, or its start did. */
  #broken = false;
  /** The organisation of the transaction open on it, to read back with the commit. */
  #tenant: string | undefined;
  /** Gives back the organisation's share of the connections this one came from, if it did. */
  readonly #leaveShare: () => void;

  constructor(pool: pg.Pool, logger: Logger, attempts: number, client: pg.PoolClient, leaveShare: () => void) {
    this.#pool = pool;
    this.#logger = logger;
    this.#attempts = attempts;
    this.#client = client;
    this.#leaveShare = leaveShare;
  }

  async executeQuery<R>(query: CompiledQuery): Promise<QueryResult<R>> {
    if (!this.#checked) await this.#sound(async (client) => ({ problem: unusable(await stateOf(client)) }));
    return resultOf<R>(await timedTrip(() => this.#written(query)));
  }

  /**
   * The statements in order, on one trip: each is written before any answer is
   * read. One that fails fails those behind it, and its failure is what comes back:
   * so in a transaction only, whose start checked this connection. Outside one, a
   * failure would leave those before it kept and those behind it still to answer.
   */
  async executeTogether(queries: readonly CompiledQuery[]): Promise<QueryResult<unknown>[]> {
    if (!this.#checked) throw new TenantContextError('statements go together only inside a transaction');
    const answers = await timedTrip(() => Promise.all(queries.map((query) => this.#written(query))));
    return answers.map((answer) => resultOf<unknown>(answer));
  }

  streamQuery<R>(): AsyncIterableIterator<QueryResult<R>> {
    throw new Error('streaming is not used');
  }

  /** The start, with the connection's check and the opening's settings, in one round trip. */
  async begin(settings: TransactionSettings, asked: Opening | undefined): Promise<void> {
    const statements = [startOf(settings), CONNECTION_STATE, ...(asked === undefined ? [] : [startSettings(asked)])];
    const set = await this.#sound(async (client) => {
      // Several statements take the simple protocol, which answers each in turn.
      // eslint-disable-next-line agentx/no-string-built-sql -- partner S162: fixed text but for the organisation's ID, a lower-case UUID checked by written().
      const answers = (await client.query(statements.join('; '))) as unknown as pg.QueryResult[];
      // A connection closed for its state ends the transaction just begun on it.
      return { problem: unusable(stateFrom(answers[1]?.rows[0] as StateRow)), value: answers[2]?.rows[0] as StateRow };
    });
    if (asked?.tenant === undefined) return;
    // The read-back at the start (decision 41). It can't differ today (the setting has no check hook).
    if (!sameTenant(set?.org_id, asked.tenant)) {
      this.#broken = true;
      throw new TenantContextError("the organisation setting didn't take");
    }
    this.#tenant = asked.tenant;
  }

  /** The commit, after the read-back before it when an organisation was set, in one round trip. */
  async commit(): Promise<void> {
    const tenant = this.#tenant;
    this.#tenant = undefined;
    if (tenant === undefined) {
      await timedTrip(() => this.#taken().query('commit'), 'commit');
      return;
    }
    try {
      // eslint-disable-next-line agentx/no-string-built-sql -- partner S162: fixed text but for the organisation's ID, a lower-case UUID checked by written().
      await timedTrip(() => this.#taken().query(`${stillTenant(tenant)}; commit`), 'commit');
    } catch (error) {
      // Changed and put back in between is not seen here; row security still walls each statement to the setting it ran under.
      if (error instanceof Error && (error as { code?: unknown }).code === TENANT_CHANGED) {
        throw new TenantContextError(
          'the organisation setting changed inside the transaction, so nothing it wrote is kept',
        );
      }
      throw error;
    }
  }

  async rollback(): Promise<void> {
    this.#tenant = undefined;
    await timedTrip(() => this.#taken().query('rollback'));
  }

  release(): void {
    const client = this.#client;
    this.#client = undefined;
    try {
      client?.release(this.#broken ? true : undefined);
    } finally {
      this.#leaveShare();
    }
  }

  #written(query: CompiledQuery): Promise<pg.QueryResult> {
    // eslint-disable-next-line agentx/no-string-built-sql -- Kysely's compiled query, its values bound as parameters: what Kysely's own driver sends.
    return this.#taken().query(query.sql, [...query.parameters]);
  }

  #taken(): pg.PoolClient {
    if (this.#client === undefined) throw new TenantContextError('the connection was already given back');
    return this.#client;
  }

  /**
   * Runs `trip`, which checks the connection, until one is sound: one that
   * isn't is closed, logged and replaced. A trip that fails closes it too.
   */
  async #sound<T>(
    trip: (client: pg.PoolClient) => Promise<{ problem: string | undefined; value?: T }>,
  ): Promise<T | undefined> {
    for (let attempt = 1; attempt <= this.#attempts; attempt += 1) {
      let answer: { problem: string | undefined; value?: T };
      try {
        answer = await timedTrip(() => trip(this.#taken()));
      } catch (error) {
        this.#broken = true;
        throw error;
      }
      if (answer.problem === undefined) {
        this.#checked = true;
        return answer.value;
      }
      this.#taken().release(true);
      this.#client = undefined;
      this.#logger.error('db.tenant.leftover_discarded', { attempt, problem: answer.problem });
      if (attempt < this.#attempts) this.#client = await timedPoolWait(() => this.#pool.connect());
    }
    throw new TenantContextError(`no sound connection after ${String(this.#attempts)} tries`);
  }
}

function checked(connection: DatabaseConnection): CheckedConnection {
  if (!(connection instanceof CheckedConnection)) throw new TenantContextError('not a checked connection');
  return connection;
}

/**
 * The statements on one trip of the transaction's connection, in the order
 * given (4D2d P16). Kysely holds each of a transaction's statements back for
 * the answer before it, so they go together only through here. For statements
 * none of whose text needs an answer to one before it. An answer checked in
 * code is checked after the trip, so a commit never goes on one.
 */
export function sendTogether<
  Schema,
  const Statements extends readonly { compile(executorProvider: QueryExecutorProvider): CompiledQuery }[],
>(
  tx: Transaction<Schema>,
  statements: Statements,
): Promise<{ -readonly [At in keyof Statements]: QueryResult<unknown> }> {
  const queries = statements.map((statement) => statement.compile(tx));
  return tx.getExecutor().provideConnection((connection) => checked(connection).executeTogether(queries)) as Promise<{
    -readonly [At in keyof Statements]: QueryResult<unknown>;
  }>;
}

/** Kysely's driver for the pool, each connection checked and each transaction opened and closed as above. */
class CheckedDriver implements Driver {
  readonly #pool: pg.Pool;
  readonly #logger: Logger;
  readonly #attempts: number;
  readonly #shares: OrganisationShares | undefined;

  constructor(pool: pg.Pool, logger: Logger, attempts: number, shares: OrganisationShares | undefined) {
    this.#pool = pool;
    this.#logger = logger;
    this.#attempts = attempts;
    this.#shares = shares;
  }

  async init(): Promise<void> {
    // The pool is made by the caller.
  }

  async acquireConnection(): Promise<DatabaseConnection> {
    const leaveShare = await this.#enteredShare();
    try {
      const client = await timedPoolWait(() => this.#pool.connect());
      return new CheckedConnection(this.#pool, this.#logger, this.#attempts, client, leaveShare);
    } catch (error) {
      leaveShare();
      throw error;
    }
  }

  /**
   * The share of the organisation whose transaction this connection is for, when
   * an agent's request opens it: waited for holding no connection, past its bound
   * answered busy. Only the transaction withTenant is opening: one begun inside its
   * work has no share to wait for, so nothing holding a share can wait on its own.
   */
  async #enteredShare(): Promise<() => void> {
    const asked = opening.getStore();
    const shares = this.#shares;
    const organisation = asked?.tenant;
    if (
      shares === undefined ||
      organisation === undefined ||
      asked?.taken === true ||
      asked?.unshared === true ||
      !isAgentTraffic()
    ) {
      return () => undefined;
    }
    try {
      await timedPoolWait(() => shares.enter(organisation));
    } catch (error) {
      if (error instanceof OrganisationBusy) {
        this.#logger.child({ orgId: organisation }).warn('db.organisation_busy', { waitedMs: error.waitedMs });
      }
      throw error;
    }
    return () => {
      shares.leave(organisation);
    };
  }

  beginTransaction(connection: DatabaseConnection, settings: TransactionSettings): Promise<void> {
    return checked(connection).begin(settings, taken());
  }

  commitTransaction(connection: DatabaseConnection): Promise<void> {
    return checked(connection).commit();
  }

  rollbackTransaction(connection: DatabaseConnection): Promise<void> {
    return checked(connection).rollback();
  }

  releaseConnection(connection: DatabaseConnection): Promise<void> {
    checked(connection).release();
    return Promise.resolve();
  }

  async destroy(): Promise<void> {
    await this.#pool.end();
  }
}

/**
 * Postgres for Kysely, through the pool, with every connection checked before
 * its first statement and every transaction opened and committed with the
 * checks that guard it (4D2d P11). `attempts`: how many connections to try
 * before giving up, every idle one and then a new one. `organisationShare`: the
 * most an organisation's transactions may hold at once; none, no limit.
 */
export function tenantCheckedDialect(
  pool: pg.Pool,
  logger: Logger,
  attempts: number,
  organisationShare?: number,
): PostgresDialect {
  const shares = organisationShare === undefined ? undefined : createOrganisationShares(organisationShare);
  return new (class extends PostgresDialect {
    override createDriver(): Driver {
      return new CheckedDriver(pool, logger, attempts, shares);
    }
  })({ pool });
}
