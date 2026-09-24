// API idempotency (ADR-007 §4, PRD §7.2): a write that carries an idempotency
// key is done once. The key belongs to one organisation, one client (a user or
// an agent) and one operation. The first request with it claims a row in
// idempotency.keys (db/migrations/0006), does its write in the same
// transaction, and records the write's result on the row. A later request with
// the key gets that result back if it asks for the same thing, and a conflict
// if it asks for anything else.
//
// A request that arrives while the first is still running waits on the row's
// primary key until the first claim ends. Its insert then finds the row
// committed (the stored result, or a conflict), or gone with a rollback, and
// then it goes ahead as the first. So there is no in-progress state: the
// database's own waiting makes one unnecessary (ADR-007 §4). The wait is
// bounded (B2b-3a): from the claim on, the transaction waits at most 5 seconds
// for a lock (a shorter limit the caller set is kept), and a request still
// waiting on the key then is answered `busy`, with nothing left of its claim,
// so it can be sent again.
//
// "The same thing" is a keyed hash (HMAC, the `request-hash` key) of the
// request's normalized payload, stored with its key's version (ADR-014 §3): a
// request can carry bank details, and a plain hash of them could be guessed
// offline from a copy of the table. A retry during a key rotation is checked
// with the version its row was made with, so it still matches (SEC-DATA-07).
// The organisation, client, operation and key go into the hash as well, each
// as its own part, so a hash says which request it is about.
//
// The row is claimed first in its transaction (ADR-006 §6, lock order 0): a
// transaction that has already written or row-locked anything, or claimed a
// key before, is refused, so two requests with one key never hold other row
// locks while one waits for the other. (An advisory or table lock taken
// before the claim isn't seen; tenant code takes neither.)
//
// The claim and the write run inside a savepoint. A write refused along the
// way (a temporary refusal such as ORG_FROZEN, or any error) rolls back to it
// and throws: the claim goes with the write, so the key stays unused and
// works once the refusal is lifted (ADR-007 §4), even when the caller catches
// the refusal and commits the rest of its transaction (an audit event, say).
// A request waiting on the key goes ahead as the first as soon as the claim
// is rolled back.
//
// A key is kept for its retention, 30 days from its claim (ADR-014 §3), and
// then swept (B1e): sweepIdempotencyKeys deletes an organisation's keys past
// it, in that organisation's withTenant. The database holds the same line
// (0009's restrictive `retention` policy), so no DELETE the app sends reaches
// a younger key. A key swept after a claim met it but before the claim read it
// is claimed again, once (B1e-2): a key past its retention is a new request.
import { type Kysely, sql, type Transaction } from 'kysely';

import type { KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import type { Logger } from '../observability/index.ts';
import { assertTenant, withTenant } from './tenant.ts';

/**
 * Who sent the request: a signed-in user, or an agent, each by its own ID.
 * Never a credential's ID: rotating an agent's key mid-retry would make the
 * retry another client's, and do the write again.
 */
export interface IdempotencyClient {
  readonly kind: 'user' | 'agent';
  readonly id: string;
}

export interface IdempotentRequest {
  /** The organisation, from the server (the authenticated principal), never from the request. */
  readonly orgId: string;
  readonly client: IdempotencyClient;
  /** The write, as its route names it: lower-case words joined by `.` or `-`, at most 64 characters. */
  readonly operation: string;
  /** The client's idempotency key: 1 to 255 visible ASCII characters. */
  readonly key: string;
  /** The request's normalized payload, as well-formed text: only its keyed hash is kept. */
  readonly payload: string;
}

/** A write's answer: what a retry of it gets back. */
export interface IdempotentResult {
  /** Its HTTP status, 200 to 299: a refusal throws, and is never kept. */
  readonly status: number;
  /** The resource it made or changed. */
  readonly resourceId: string;
}

/**
 * What happened: the write done now; an earlier one's result, for a retry of
 * the same request; a conflict, for a different request with the key; or busy,
 * when another request's claim of the key was still uncommitted after the
 * wait (nothing done: send it again).
 */
export type IdempotentWrite =
  | { readonly outcome: 'done'; readonly result: IdempotentResult }
  | { readonly outcome: 'replayed'; readonly result: IdempotentResult }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' };

/**
 * The write couldn't go ahead:
 * - `bad_request`: the organisation, client, operation, key or payload isn't
 *   in its form (the API refuses a bad key before it gets here)
 * - `not_first`: its transaction had already written, row-locked or claimed a
 *   key (ADR-006 §6)
 * - `bad_result`: the write's answer isn't a status from 200 to 299 and a UUID
 * - `not_applied`: the claimed row's result couldn't be recorded, because
 *   something else wrote one first
 * - `unreadable`: the key's row holds no result, or row security hides it;
 *   either way someone past this step changed the table
 * - `key_not_held`: the key's row was made with a request-hash key version
 *   this process doesn't hold: retired before the retention ran out, or the
 *   release is missing it
 * Whatever the reason, nothing of the claim or the write is left.
 */
export class IdempotencyFailed extends Error {
  readonly reason: 'bad_request' | 'not_first' | 'bad_result' | 'not_applied' | 'unreadable' | 'key_not_held';

  constructor(reason: IdempotencyFailed['reason'], message: string) {
    super(message);
    this.name = 'IdempotencyFailed';
    this.reason = reason;
  }
}

export interface IdempotentWrites {
  /**
   * Does `work` once for the request's key, in the caller's transaction, which
   * must be withTenant's for the request's organisation and must not have
   * written, row-locked or claimed a key yet. `work` runs only when this
   * request is the first with the key; it does the write in the same
   * transaction and returns its answer, which is recorded against the key
   * before this resolves. If `work` throws, the claim and everything `work`
   * wrote are rolled back, and its error is thrown on.
   */
  run<Schema>(
    tx: Transaction<Schema>,
    request: IdempotentRequest,
    work: () => Promise<IdempotentResult>,
  ): Promise<IdempotentWrite>;
}

/**
 * How long a key is kept after its claim, in whole days (ADR-014 §3's
 * default): a retry within it gets the first request's answer. The schema
 * policy and 0009's `retention` policy hold the database to the same number.
 * A request-hash key is kept at least as long, so every kept key can be
 * checked (Azure.md, "Rotating a key").
 */
export const IDEMPOTENCY_RETENTION_DAYS = 30;

/** The most keys one sweep deletes: each is a short transaction, and a caller sweeps again while it deletes this many. */
const MOST_SWEPT = 10_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Every kind of client, as a list of text: a caller the compiler can't see (a cast) could name another. */
const CLIENT_KINDS: readonly string[] = ['user', 'agent'] satisfies readonly IdempotencyClient['kind'][];
const OPERATION = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const OPERATION_MAX = 64;
/** Visible ASCII, `!` to `~`: no spaces, no control characters, nothing a log or a header could read two ways. */
const KEY = /^[!-~]{1,255}$/;

/** Whether the value is text the pattern matches: a caller the compiler can't see could pass anything. */
const matches = (pattern: RegExp, value: unknown): value is string => typeof value === 'string' && pattern.test(value);

/**
 * Whether the value names a write as the idempotency keys namespace it: lower-case
 * words joined by `.` or `-`, at most 64 characters. The API holds each write
 * route's operation to it as the route is added (B2b).
 */
export const isOperation = (value: unknown): value is string =>
  matches(OPERATION, value) && value.length <= OPERATION_MAX;

/** Whether the value is an idempotency key: 1 to 255 visible ASCII characters. The API refuses any other before the body is read (B2b-2). */
export const isIdempotencyKey = (value: unknown): value is string => matches(KEY, value);

/** Why the request can't be taken, or undefined. Never names a value: it may be anything a client sent. */
function requestProblem({ orgId, client, operation, key, payload }: IdempotentRequest): string | undefined {
  if (!matches(UUID, orgId)) return 'the organisation ID is not a UUID';
  if (!CLIENT_KINDS.includes(client.kind)) return 'the client is neither a user nor an agent';
  if (!matches(UUID, client.id)) return "the client's ID is not a UUID";
  if (!isOperation(operation)) {
    return `the operation is not lower-case words joined by . or -, at most ${OPERATION_MAX} characters`;
  }
  if (!isIdempotencyKey(key)) return 'the key is not 1 to 255 visible ASCII characters';
  // A lone surrogate is written as U+FFFD, so two different payloads could hash alike.
  if (typeof payload !== 'string' || !payload.isWellFormed()) return 'the payload is not well-formed text';
  return undefined;
}

function resultProblem({ status, resourceId }: IdempotentResult): string | undefined {
  if (!Number.isInteger(status) || status < 200 || status > 299) {
    return 'its status is not a whole number from 200 to 299';
  }
  if (!matches(UUID, resourceId)) return 'its resource ID is not a UUID';
  return undefined;
}

/** The hash's message: every part of the request's namespace, then its payload, IDs in lower case as Postgres prints them. */
function requestMessage({ orgId, client, operation, key, payload }: IdempotentRequest): Message {
  return ['idempotent-request', orgId.toLowerCase(), client.kind, client.id.toLowerCase(), operation, key, payload];
}

/**
 * A key's row as read back. The hash and its version are NOT NULL bytea and
 * integer, which pg reads as a Buffer and a number; the result is empty only
 * on a row whose claim never recorded one.
 */
interface StoredKey {
  readonly request_hash: Buffer;
  readonly request_hash_key_version: number;
  readonly result_status: number | null;
  readonly result_id: string | null;
}

/** A key's row, in lower case as Postgres prints its IDs. */
interface KeyRow {
  readonly orgId: string;
  readonly kind: string;
  readonly clientId: string;
  readonly operation: string;
  readonly key: string;
}

/**
 * Transactions that have claimed a key: one claim each, whatever the first
 * one's outcome. Matched by the transaction object; a handle made from it
 * (`withSchema`, `withPlugin`) is another object, but a second claim through
 * one after an answer from a row holds no lock the first took, so no one can
 * wait on both.
 */
const claimedIn = new WeakSet<object>();

/**
 * The claim's savepoint, a name no other step may use: a rollback goes to the
 * newest savepoint of its name, so a write's own savepoint of the same name
 * would stand in for the claim's, and a refused claim could then be committed.
 */
const CLAIM_SAVEPOINT = 'agentx_idempotency_claim';

/** Postgres's `lock_not_available`: a lock timeout ran out. */
const LOCK_NOT_AVAILABLE = '55P03';

/** The claim's wait ran out: answered `busy` once the claim is rolled back. */
class ClaimBusy extends Error {
  constructor(cause: unknown) {
    super("Another request's claim of the key was still uncommitted when the wait ran out", { cause });
    this.name = 'ClaimBusy';
  }
}

const isLockTimeout = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && error.code === LOCK_NOT_AVAILABLE;

const notFirst = (): IdempotencyFailed =>
  new IdempotencyFailed(
    'not_first',
    'An idempotency key is claimed first in its transaction (ADR-006 §6), but this one has already written, row-locked or claimed a key',
  );

/**
 * Build it from the request's logger, a child carrying its correlation ID
 * (Rule Book §8); each write adds the organisation.
 */
export function createIdempotentWrites({
  keys,
  logger,
}: {
  readonly keys: KeyProvider;
  readonly logger: Logger;
}): IdempotentWrites {
  return Object.freeze({
    async run<Schema>(
      tx: Transaction<Schema>,
      request: IdempotentRequest,
      work: () => Promise<IdempotentResult>,
    ): Promise<IdempotentWrite> {
      const problem = requestProblem(request);
      if (problem !== undefined) throw new IdempotencyFailed('bad_request', `An idempotent write refused: ${problem}`);
      if (claimedIn.has(tx)) throw notFirst();
      await assertTenant(tx, request.orgId);

      // A transaction gets its ID when it first writes or row-locks, so none
      // yet means nothing has been written or row-locked before the claim.
      const { rows: fresh } = await sql<{ first: boolean }>`
        select pg_catalog.pg_current_xact_id_if_assigned() is null as first
      `.execute(tx);
      if (fresh[0]?.first !== true) throw notFirst();
      claimedIn.add(tx);

      const row: KeyRow = {
        orgId: request.orgId.toLowerCase(),
        kind: request.client.kind,
        clientId: request.client.id.toLowerCase(),
        operation: request.operation,
        key: request.key,
      };
      const log = logger.child({ orgId: row.orgId });
      const facts = {
        operation: row.operation,
        clientKind: row.kind,
        clientId: row.clientId,
        idempotencyKey: row.key,
      };
      const message = requestMessage(request);

      const at: Claim<Schema> = { tx, row, log, facts };

      // Never released: the commit ends it with the transaction, and a release
      // would cost a round trip and change nothing.
      const savepoint = sql.id(CLAIM_SAVEPOINT);
      await sql`savepoint ${savepoint}`.execute(tx);
      try {
        // Waits, if another transaction holds the key's row uncommitted, until
        // its claim ends: then nothing is inserted if it committed, and this
        // row is if it rolled back. A wait past the bound is answered `busy`. Every statement filters by org_id too
        // (ADR-005 §7).
        const { mac, keyVersion } = keys.mac('request-hash', message);
        await boundClaimWait(tx);
        const claim = async (): Promise<boolean> => {
          let claimed;
          try {
            claimed = await sql<{ claimed: number }>`
              insert into idempotency.keys
                (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at)
              values (${row.orgId}, ${row.kind}, ${row.clientId}, ${row.operation}, ${row.key}, ${mac}, ${keyVersion},
                pg_catalog.now())
              on conflict (org_id, client_kind, client_id, operation, key) do nothing
              returning 1 as claimed
            `.execute(tx);
          } catch (error) {
            throw isLockTimeout(error) ? new ClaimBusy(error) : error;
          }
          return claimed.rows.length === 1;
        };
        const done = async (): Promise<IdempotentWrite> =>
          Object.freeze({ outcome: 'done', result: await doAndRecord(at, work) });

        if (await claim()) return await done();
        const answer = await answerFromRow(at, keys, message);
        if (answer !== undefined) return answer;
        // No row, though one stood in the claim's way: swept since (B1e-2), so
        // claimed again, once. A row still in the way and still unread is one
        // row security hides: someone past the app rewrote the table's policy.
        log.info('idempotency.claimed_again', facts);
        if (await claim()) return await done();
        const second = await answerFromRow(at, keys, message);
        if (second !== undefined) return second;
        log.error('idempotency.unreadable', { ...facts, problem: 'row_hidden' });
        throw new IdempotencyFailed(
          'unreadable',
          "The idempotency key's row stood in the way of the claim, but can't be read",
        );
      } catch (error) {
        // Whatever failed, the transaction is left as it was before the claim,
        // and usable: a caller that catches the error can still commit the rest.
        try {
          await sql`rollback to savepoint ${savepoint}`.execute(tx);
        } catch (rollbackError) {
          // The write's own error is thrown either way. The failed rollback
          // aborts the savepoint level the write left the transaction in, and a
          // lost connection ends the transaction, so the claim can't be
          // committed, unless the write itself released or replaced the
          // caller's savepoints, which no step may do.
          log.error('idempotency.rollback_failed', { ...facts, err: rollbackError });
          throw error;
        }
        if (error instanceof ClaimBusy) {
          log.warn('idempotency.busy', facts);
          return Object.freeze({ outcome: 'busy' });
        }
        throw error;
      }
    },
  });
}

/**
 * Bounds how long the transaction waits for a lock from here on, the claim's
 * wait for the key among them: 5 seconds, unless the caller has already set a
 * shorter limit, which is kept (Postgres's `0` is no limit at all). Inside the
 * claim's savepoint, so a claim that fails leaves the caller's limit as it was.
 */
async function boundClaimWait<Schema>(tx: Transaction<Schema>): Promise<void> {
  const { rows } = await sql<{ longer: boolean | null }>`
    select (limit_now = interval '0' or limit_now > interval '5 seconds') as longer
    from (select pg_catalog.current_setting('lock_timeout')::interval as limit_now) as setting
  `.execute(tx);
  if (rows[0]?.longer !== false) await sql`set local lock_timeout = '5s'`.execute(tx);
}

/** One claim's transaction, row and logging. */
interface Claim<Schema> {
  readonly tx: Transaction<Schema>;
  readonly row: KeyRow;
  readonly log: Logger;
  readonly facts: Readonly<Record<string, string>>;
}

/**
 * The answer for a key some earlier request claimed: its stored result for
 * the same request, a conflict for another, or nothing when the row can't be
 * read (the caller decides why). Throws for a row it can't trust.
 */
async function answerFromRow<Schema>(
  { tx, row, log, facts }: Claim<Schema>,
  keys: KeyProvider,
  message: Message,
): Promise<IdempotentWrite | undefined> {
  // READ COMMITTED: this statement sees the row the insert waited for.
  const { rows } = await sql<StoredKey>`
    select request_hash, request_hash_key_version, result_status, result_id from idempotency.keys
    where org_id = ${row.orgId} and client_kind = ${row.kind} and client_id = ${row.clientId}
      and operation = ${row.operation} and key = ${row.key}
  `.execute(tx);
  const [stored] = rows;
  // Swept since the claim met it, or hidden by row security: the caller tells which.
  if (stored === undefined) return undefined;
  const { request_hash: hash, request_hash_key_version: hashKeyVersion } = stored;
  if (stored.result_status === null || stored.result_id === null) {
    log.error('idempotency.unreadable', { ...facts, problem: 'no_result' });
    throw new IdempotencyFailed('unreadable', "The idempotency key's row holds no result, though its claim committed");
  }
  const result = Object.freeze({ status: stored.result_status, resourceId: stored.result_id });

  // A version retired before the retention ran out (Azure.md, "Rotating a
  // key") can't check the row: refused, never taken for a conflict.
  const held = keys
    .describe()
    .some(
      ({ purpose, versions }) =>
        purpose === 'request-hash' && versions.some(({ version }) => version === hashKeyVersion),
    );
  if (!held) {
    log.error('idempotency.key_not_held', { ...facts, keyVersion: hashKeyVersion });
    throw new IdempotencyFailed(
      'key_not_held',
      "The idempotency key's row was made with a request-hash key version this process doesn't hold",
    );
  }
  if (!keys.verifyMac('request-hash', hashKeyVersion, message, hash)) {
    log.warn('idempotency.conflict', facts);
    return Object.freeze({ outcome: 'conflict' });
  }
  log.info('idempotency.replayed', { ...facts, resultStatus: result.status });
  return Object.freeze({ outcome: 'replayed', result });
}

/**
 * Runs the write, checks its answer and records it on the claimed row. Throws
 * `bad_result` or `not_applied`, and the write's own errors, for the caller to
 * roll back.
 */
async function doAndRecord<Schema>(
  { tx, row, log, facts }: Claim<Schema>,
  work: () => Promise<IdempotentResult>,
): Promise<IdempotentResult> {
  const answer = await work();
  const bad = resultProblem(answer);
  if (bad !== undefined) throw new IdempotencyFailed('bad_result', `An idempotent write's answer refused: ${bad}`);
  const result = Object.freeze({ status: answer.status, resourceId: answer.resourceId.toLowerCase() });
  const recorded = await sql<{ recorded: number }>`
    update idempotency.keys set result_status = ${result.status}, result_id = ${result.resourceId}
    where org_id = ${row.orgId} and client_kind = ${row.kind} and client_id = ${row.clientId}
      and operation = ${row.operation} and key = ${row.key} and result_status is null
    returning 1 as recorded
  `.execute(tx);
  if (recorded.rows.length !== 1) {
    log.error('idempotency.not_applied', facts);
    throw new IdempotencyFailed(
      'not_applied',
      "The claimed idempotency key's row was given a result by something else",
    );
  }
  return result;
}

/**
 * Deletes up to `most` (at most 10,000) of the organisation's idempotency keys
 * whose retention has run out, in the caller's transaction, which must be
 * withTenant's for the organisation, and returns how many it deleted. A
 * caller sweeps again while it gets `most` back. A key being claimed again
 * meanwhile waits for the sweep's transaction, then is claimed afresh.
 */
export async function sweepIdempotencyKeys<Schema>(
  tx: Transaction<Schema>,
  orgId: string,
  most: number,
): Promise<number> {
  if (!matches(UUID, orgId))
    throw new IdempotencyFailed('bad_request', 'A sweep refused: the organisation ID is not a UUID');
  if (!Number.isInteger(most) || most < 1 || most > MOST_SWEPT) {
    throw new IdempotencyFailed(
      'bad_request',
      `A sweep refused: it deletes a whole number of keys from 1 to ${String(MOST_SWEPT)}`,
    );
  }
  await assertTenant(tx, orgId);
  const org = orgId.toLowerCase();
  // By primary key, oldest first; the retention policy holds the same line.
  const { rows } = await sql<{ swept: number }>`
    delete from idempotency.keys
    where org_id = ${org}
      and (client_kind, client_id, operation, key) in (
        select client_kind, client_id, operation, key from idempotency.keys
        where org_id = ${org} and created_at < pg_catalog.now() - pg_catalog.make_interval(days => ${IDEMPOTENCY_RETENTION_DAYS})
        order by created_at
        limit ${most}
      )
    returning 1 as swept
  `.execute(tx);
  return rows.length;
}

/**
 * Sweeps up to `most` of the organisation's keys past their retention in a
 * transaction of its own, the organisation's withTenant, each statement held
 * to 10 seconds: the retention sweep's one step (B1e-3).
 */
export function sweepExpiredKeys<Schema>(db: Kysely<Schema>, orgId: string, most: number): Promise<number> {
  return withTenant(db, orgId, async (tx) => {
    await sql`set local statement_timeout = '10s'`.execute(tx);
    return sweepIdempotencyKeys(tx, orgId, most);
  });
}
