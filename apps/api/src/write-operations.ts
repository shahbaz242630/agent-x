// API idempotency (ADR-007 §4, PRD §7.2), B2b-1: every write route names its
// operation, in its `config.operation`. The idempotency keys are namespaced by
// organisation, client and operation (`createIdempotentWrites`), so the
// operation is what keeps one route's key from answering another's request.
// The contract refuses a write route without one, as it is added and again at
// ready, and writes it into the OpenAPI document as the operation's
// `operationId`, which OpenAPI holds unique across the document.
//
// A write is any method but GET, HEAD, OPTIONS and TRACE. A public write
// names none: it has no signed-in caller to namespace a key by, so it must be
// safe to repeat by itself (sign-out ends a session that may already be gone).
// A read names none either: it takes no key.
//
// B2b-2: a request to a route with an operation must carry an
// `Idempotency-Key` header, 1 to 255 visible ASCII characters (the
// idempotency module's own rule). Without one, or with a malformed one, it is
// refused as 400 IDEMPOTENCY_KEY_INVALID, after the caller is known and before
// the body is read. The contract shows the header on each such operation in
// the document, as a required parameter.
import { isIdempotencyKey, isOperation } from '@agentx/platform/db';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';

declare module 'fastify' {
  interface FastifyContextConfig {
    /** The write, as its idempotency keys name it. Required on every write route but a public one (contract.ts). */
    readonly operation?: string;
  }
}

/** Methods that only read: a route of these alone takes no idempotency key. */
const READ_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

/** Whether a route serves any method that can change something. */
export const isWriteRoute = (methods: readonly string[]): boolean =>
  methods.some((method) => !READ_METHODS.has(method));

/**
 * Why a route's operation can't stand, if it can't. `access` is the route's own
 * list, whose problems access.ts names: only whether it names the public alone
 * matters here.
 */
export function operationProblems(operation: unknown, methods: readonly string[], access: unknown): string[] {
  const publicOnly = Array.isArray(access) && access.length === 1 && access[0] === 'public';
  if (!isWriteRoute(methods) || publicOnly) {
    if (operation === undefined) return [];
    return [
      isWriteRoute(methods)
        ? 'it names an operation, but a public write takes no idempotency key'
        : 'it names an operation, but a read takes no idempotency key',
    ];
  }
  if (operation === undefined) return ['it writes but names no operation (config.operation)'];
  if (!isOperation(operation)) {
    return ['its operation is not lower-case words joined by . or -, at most 64 characters'];
  }
  return [];
}

/** The header a write's key comes in, as Node names it. */
export const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';

/**
 * The header as the document shows it on each write. The hook below checks it
 * before the body is read, so the route's own check of it never refuses.
 */
export const IDEMPOTENCY_KEY_SCHEMA = z
  .string()
  .regex(/^[!-~]{1,255}$/)
  .register(API_SCHEMAS, {
    description:
      'Makes the write safe to retry: 1 to 255 visible ASCII characters, new for each change. The same key with the same request answers as the first did; with another request, it is refused.',
  });

/**
 * Refuses a request to a route with an operation that carries no well-formed
 * idempotency key. After the access hook, so a caller who isn't allowed learns
 * nothing of the route; in callback style, calling done() only to let a
 * request through, as access.ts does.
 */
export function registerIdempotencyKeys(app: FastifyInstance): void {
  app.addHook('onRequest', (request, reply, done) => {
    if (request.routeOptions.config.operation === undefined) {
      done();
      return;
    }
    if (!isIdempotencyKey(request.headers[IDEMPOTENCY_KEY_HEADER])) {
      void sendErrorBody(reply, 400, 'IDEMPOTENCY_KEY_INVALID', request.id);
      return;
    }
    done();
  });
}

/** Operations named by more than one route, each once. */
export function sharedOperations(operations: readonly (string | undefined)[]): string[] {
  const named = operations.filter((operation) => operation !== undefined);
  return [...new Set(named.filter((operation, index) => named.indexOf(operation) !== index))];
}
