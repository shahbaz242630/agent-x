// API idempotency (ADR-007 §4, PRD §7.2), B2b-3b: what a write route hands the
// idempotency store, and how it answers what the store says.
//
// A write route opens its organisation's withTenant transaction and, before
// anything else in it, runs its write through `createIdempotentWrites().run`
// with `idempotentRequest(request, orgId)`:
// - the client is the signed-in person (agents come at C2), never a credential;
// - the operation is the route's own (write-operations.ts), the key its
//   Idempotency-Key header, both checked before the body was read;
// - the payload is the request's normalized input: the canonical JSON of its
//   parsed params, query and body, so the same request sent with its fields in
//   another order, or its query's parameters in another order, is the same.
// The store answers:
// - done or replayed: the route answers from the resource, re-read by the ID
//   the result names, with the result's status;
// - conflict: 409 IDEMPOTENCY_KEY_REUSED, the key used for another request;
// - busy: 409 IDEMPOTENCY_KEY_BUSY with Retry-After, another request with the
//   key still being done.
import { isIdempotencyKey, type IdempotentRequest, type IdempotentWrite } from '@agentx/platform/db';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { sendErrorBody } from './errors.ts';
import { IDEMPOTENCY_KEY_HEADER } from './write-operations.ts';

/** How long a client is told to wait before sending a busy request again: as long as the store waited, time for most writes holding the key to end. */
export const BUSY_RETRY_SECONDS = 5;

/** Text that can't be hashed as it reads: a lone surrogate would be written as U+FFFD, so two requests could hash alike. */
class IllFormedText extends Error {
  readonly statusCode = 400;

  constructor() {
    super('The request holds text that is not well-formed Unicode');
    this.name = 'IllFormedText';
  }
}

/**
 * An object JSON could have made: its prototype Object's, none, or an empty
 * one of its own with none behind it, as Fastify makes a request's params
 * and query (found at B4-3b, the first route to hash them). A class
 * instance's prototype holds at least its constructor, so it is none of these.
 */
const isPlainObject = (value: object): boolean => {
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype === Object.prototype || prototype === null) return true;
  return (
    typeof prototype === 'object' &&
    Object.getPrototypeOf(prototype) === null &&
    Reflect.ownKeys(prototype).length === 0
  );
};

/**
 * The value as canonical JSON: object keys sorted by code unit at every depth,
 * no spaces, numbers and strings as JSON.stringify writes them. Only what JSON
 * can hold is taken; anything else (a Date, a number that isn't finite, a
 * class instance) is a failure on our side, since a route's input schemas
 * should never make one. Text that isn't well-formed Unicode is the client's
 * (400 BAD_REQUEST).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('A number that is not finite has no JSON form');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new IllFormedText();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${Array.from(value, (item) => canonicalJson(item)).join(',')}]`;
  if (typeof value === 'object' && isPlainObject(value)) {
    const entries = Object.keys(value)
      .sort()
      .map((name) => `${canonicalJson(name)}:${canonicalJson((value as Record<string, unknown>)[name])}`);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError(`A ${typeof value} has no JSON form`);
}

/**
 * The idempotency store's request for a signed-in person's write to this
 * route, in the organisation the route found for them. A route without an
 * operation, a request without its key or its person, is a failure on our
 * side: the contract and the hooks before the route make each impossible.
 */
export function idempotentRequest(request: FastifyRequest, orgId: string): IdempotentRequest {
  const { operation } = request.routeOptions.config;
  if (operation === undefined) throw new Error('an idempotent write ran on a route that names no operation');
  const key = request.headers[IDEMPOTENCY_KEY_HEADER];
  if (!isIdempotencyKey(key)) throw new Error('an idempotent write ran without a well-formed key');
  const person = request.person;
  if (person === null) throw new Error('an idempotent write ran without a signed-in person');
  return {
    orgId,
    client: { kind: 'user', id: person.userId },
    operation,
    key,
    payload: canonicalJson({ params: request.params ?? {}, query: request.query ?? {}, body: request.body ?? null }),
  };
}

/**
 * Answers a write the store refused to do (a conflict, or busy), returning the
 * reply; for a write done or replayed, returns undefined and the route answers
 * from the resource.
 */
export function answerRefusedWrite(
  outcome: IdempotentWrite,
  request: FastifyRequest,
  reply: FastifyReply,
): FastifyReply | undefined {
  if (outcome.outcome === 'conflict') return sendErrorBody(reply, 409, 'IDEMPOTENCY_KEY_REUSED', request.id);
  if (outcome.outcome === 'busy') {
    return sendErrorBody(
      reply.header('retry-after', String(BUSY_RETRY_SECONDS)),
      409,
      'IDEMPOTENCY_KEY_BUSY',
      request.id,
    );
  }
  return undefined;
}
