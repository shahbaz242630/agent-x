// ADR-011 §7: one line for each request, with its method, its route pattern
// (never the address as sent, which can hold IDs and a query), and, once it's
// answered, the status and duration. Never the client's IP address, the query
// or the headers. Fastify's own request lines log all three, so this log
// controller replaces them. Its other lines (a stream or serializer error) go
// through the framework logger, which keeps only their message and error.
//
// Each line is written under one of three events, which the logger caps per
// minute separately (SEC-AV-09), so a flood that is rate-limited, or that hangs
// up, can't crowd out the lines of the requests that were answered.
import type { EventName, Logger } from '@agentx/platform/observability';
import { type FastifyReply, type FastifyRequest, LogController } from 'fastify';

import { REQUEST_ID_BINDING } from './framework-logger.ts';

/** A request that was answered. */
export const REQUEST_COMPLETED: EventName = 'http.request_completed';
/** A request refused by the rate limit, written apart from the others. */
export const REQUEST_RATE_LIMITED: EventName = 'http.request_rate_limited';
/**
 * A request that ended without a complete answer: the client hung up, a streamed
 * answer failed partway (Fastify's own line says why), or Node's request timeout
 * cut it off (with an `http.client_error` line too).
 */
export const REQUEST_ABORTED: EventName = 'http.request_aborted';
/** A failure on our side, written with its scrubbed error besides the request's line. */
export const REQUEST_FAILED: EventName = 'http.request_failed';

const TOO_MANY_REQUESTS = 429;

/** A 404, or a malformed address, matched no route, so there's no pattern to log. */
const routeOf = (request: FastifyRequest): string | null => request.routeOptions.url ?? null;

/** Writes the request's line. A response that failed on its way out is a warning, with its error. */
export function logCompleted(logger: Logger, request: FastifyRequest, reply: FastifyReply, error?: Error | null): void {
  const fields = {
    method: request.method,
    route: routeOf(request),
    status: reply.statusCode,
    durationMs: Math.round(reply.elapsedTime),
  };
  const log = logger.child({ correlationId: request.id });
  const event = reply.statusCode === TOO_MANY_REQUESTS ? REQUEST_RATE_LIMITED : REQUEST_COMPLETED;
  if (error === null || error === undefined) {
    log.info(event, fields);
  } else {
    log.warn(event, { ...fields, err: error });
  }
}

/** The line for a request that ended without a complete answer. It has no status: the answer never arrived whole. */
export function logAborted(logger: Logger, request: FastifyRequest): void {
  logger
    .child({ correlationId: request.id })
    .info(REQUEST_ABORTED, { method: request.method, route: routeOf(request) });
}

export class RequestLog extends LogController {
  readonly #logger: Logger;

  constructor(logger: Logger) {
    super({ requestIdLogLabel: REQUEST_ID_BINDING });
    this.#logger = logger;
  }

  override incomingRequest(): void {
    // Nothing: the line written when the request ends covers it.
  }

  override requestCompleted(error: Error | null | undefined, request: FastifyRequest, reply: FastifyReply): void {
    logCompleted(this.#logger, request, reply, error);
  }
}
