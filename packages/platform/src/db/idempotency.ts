// API idempotency (ADR-007 §4, PRD §7.2): a write that carries an idempotency
// key is done once. The key belongs to one organisation, one client (a user or
// an agent) and one operation. The first request with it claims a row in
// idempotency.keys (db/migrations/0006), does its write in the same
// transaction, and records the write's result on the row. A later request with
// the key gets that result back if it asks for the same thing, and a conflict
// if it asks for anything else.
//
// A request that arrives while the first is still running waits on the row's
// primary key until the first transaction ends. Its insert then finds the row
// committed (the stored result, or a conflict), or gone with a rollback, and
// then it goes ahead as the first. So there is no in-progress state: the
// database's own waiting makes one unnecessary (ADR-007 §4).
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
// transaction that has already written or locked anything is refused, so two
// requests with one key never hold other locks while one waits for the other.
// A write refused along the way (a temporary refusal such as ORG_FROZEN, or
// any error) throws; the transaction rolls back with the claim, and the key
// stays unused, so it works once the refusal is lifted (ADR-007 §4).
import { sql, type Transaction } from 'kysely';

import type { KeyProvider } from '../keys/key-provider.ts';
import type { Message } from '../keys/message.ts';
import type { Logger } from '../observability/index.ts';
import { assertTenant } from './tenant.ts';

/** Who sent the request: a signed-in user, or an agent by its key. */
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
  /** The request's normalized payload, as text: only its keyed hash is kept. */
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
 * the same request; or a conflict, for a different request with the key.
 */
export type IdempotentWrite =
  | { readonly outcome: 'done'; readonly result: IdempotentResult }
  | { readonly outcome: 'replayed'; readonly result: IdempotentResult }
  | { readonly outcome: 'conflict' };

/**
 * The write couldn't go ahead:
 * - `bad_request`: the organisation, client, operation, key or payload isn't
 *   in its form (the API refuses a bad key before it gets here)
 * - `not_first`: its transaction had already written or locked something
 *   (ADR-006 §6)
 * - `bad_result`: the write's answer isn't a status from 200 to 299 and a UUID
 * - `unreadable`: the key's row holds no result, or was made with a key
 *   version this process doesn't hold; either way someone past this step
 *   changed the table, or a key was retired too early
 * The caller's transaction must roll back: throwing out of withTenant does.
 */
export class IdempotencyFailed extends Error {
  readonly reason: 'bad_request' | 'not_first' | 'bad_result' | 'unreadable';

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
   * written or locked anything yet. `work` runs only when this request is the
   * first with the key; it does the write in the same transaction and returns
   * its answer, which is recorded against the key before this resolves.
   */
  run<Schema>(
    tx: Transaction<Schema>,
    request: IdempotentRequest,
    work: () => Promise<IdempotentResult>,
  ): Promise<IdempotentWrite>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Every kind of client, as a list of text: a caller the compiler can't see (a cast) could name another. */
const CLIENT_KINDS: readonly string[] = ['user', 'agent'] satisfies readonly IdempotencyClient['kind'][];
const OPERATION = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const OPERATION_MAX = 64;
/** Visible ASCII, `!` to `~`: no spaces, no control characters, nothing a log or a header could read two ways. */
const KEY = /^[!-~]{1,255}$/;

/** Why the request can't be taken, or undefined. Never names a value: it may be anything a client sent. */
function requestProblem({ orgId, client, operation, key, payload }: IdempotentRequest): string | undefined {
  if (!UUID.test(orgId)) return 'the organisation ID is not a UUID';
  if (!CLIENT_KINDS.includes(client.kind)) return 'the client is neither a user nor an agent';
  if (!UUID.test(client.id)) return "the client's ID is not a UUID";
  if (operation.length > OPERATION_MAX || !OPERATION.test(operation)) {
    return `the operation is not lower-case words joined by . or -, at most ${OPERATION_MAX} characters`;
  }
  if (!KEY.test(key)) return 'the key is not 1 to 255 visible ASCII characters';
  if (typeof payload !== 'string') return 'the payload is not text';
  return undefined;
}

function resultProblem({ status, resourceId }: IdempotentResult): string | undefined {
  if (!Number.isInteger(status) || status < 200 || status > 299) {
    return 'its status is not a whole number from 200 to 299';
  }
  if (!UUID.test(resourceId)) return 'its resource ID is not a UUID';
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
      await assertTenant(tx, request.orgId);

      // A transaction gets its ID when it first writes or locks a row, so
      // none yet means nothing has been written or locked before the claim.
      const { rows: fresh } = await sql<{ first: boolean }>`
        select pg_catalog.pg_current_xact_id_if_assigned() is null as first
      `.execute(tx);
      if (fresh[0]?.first !== true) {
        throw new IdempotencyFailed(
          'not_first',
          'An idempotency key is claimed first in its transaction (ADR-006 §6), but this one has already written or locked something',
        );
      }

      const orgId = request.orgId.toLowerCase();
      const clientId = request.client.id.toLowerCase();
      const { kind } = request.client;
      const { operation, key } = request;
      const log = logger.child({ orgId });
      const facts = { operation, clientKind: kind, clientId, idempotencyKey: key };
      const message = requestMessage(request);

      // Waits, if another transaction holds the key uncommitted, until it
      // ends: then nothing is inserted if it committed, and this row is if it
      // rolled back. Every statement filters by org_id too (ADR-005 §7).
      const { mac, keyVersion } = keys.mac('request-hash', message);
      const claimed = await sql<{ claimed: number }>`
        insert into idempotency.keys
          (org_id, client_kind, client_id, operation, key, request_hash, request_hash_key_version, created_at)
        values (${orgId}, ${kind}, ${clientId}, ${operation}, ${key}, ${mac}, ${keyVersion}, pg_catalog.now())
        on conflict (org_id, client_kind, client_id, operation, key) do nothing
        returning 1 as claimed
      `.execute(tx);

      if (claimed.rows.length === 1) {
        const result = await work();
        const bad = resultProblem(result);
        if (bad !== undefined) {
          throw new IdempotencyFailed('bad_result', `An idempotent write's answer refused: ${bad}`);
        }
        const recorded = await sql<{ recorded: number }>`
          update idempotency.keys set result_status = ${result.status}, result_id = ${result.resourceId}
          where org_id = ${orgId} and client_kind = ${kind} and client_id = ${clientId}
            and operation = ${operation} and key = ${key} and result_status is null
          returning 1 as recorded
        `.execute(tx);
        if (recorded.rows.length !== 1) {
          log.error('idempotency.unreadable', { ...facts, problem: 'claim_lost' });
          throw new IdempotencyFailed('unreadable', "The idempotency key's claimed row could not be given its result");
        }
        return Object.freeze({
          outcome: 'done',
          result: Object.freeze({ status: result.status, resourceId: result.resourceId.toLowerCase() }),
        });
      }

      // READ COMMITTED: this statement sees the row the insert waited for.
      const { rows } = await sql<StoredKey>`
        select request_hash, request_hash_key_version, result_status, result_id from idempotency.keys
        where org_id = ${orgId} and client_kind = ${kind} and client_id = ${clientId}
          and operation = ${operation} and key = ${key}
      `.execute(tx);
      const [row] = rows;
      if (row === undefined) {
        // The primary key saw a row that row security hides from this read:
        // someone past the app rewrote the table's policy.
        log.error('idempotency.unreadable', { ...facts, problem: 'row_hidden' });
        throw new IdempotencyFailed(
          'unreadable',
          "The idempotency key's row stood in the way of the claim, but can't be read",
        );
      }
      const { request_hash: hash, request_hash_key_version: hashKeyVersion } = row;
      if (row.result_status === null || row.result_id === null) {
        log.error('idempotency.unreadable', { ...facts, problem: 'no_result' });
        throw new IdempotencyFailed(
          'unreadable',
          "The idempotency key's row holds no result, though its claim committed",
        );
      }
      const result = Object.freeze({ status: row.result_status, resourceId: row.result_id });

      // A version retired before the retention ran out (Azure.md, "Rotating a
      // key") can't check the row: refused, never taken for a conflict.
      const held = keys
        .describe()
        .some(
          ({ purpose, versions }) =>
            purpose === 'request-hash' && versions.some(({ version }) => version === hashKeyVersion),
        );
      if (!held) {
        log.error('idempotency.unreadable', { ...facts, problem: 'key_version_not_held', keyVersion: hashKeyVersion });
        throw new IdempotencyFailed(
          'unreadable',
          "The idempotency key's row was made with a request-hash key version this process doesn't hold",
        );
      }
      if (!keys.verifyMac('request-hash', hashKeyVersion, message, hash)) {
        log.warn('idempotency.conflict', facts);
        return Object.freeze({ outcome: 'conflict' });
      }
      log.info('idempotency.replayed', { ...facts, resultStatus: result.status });
      return Object.freeze({ outcome: 'replayed', result });
    },
  });
}
