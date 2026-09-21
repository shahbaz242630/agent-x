// The API's HTTP server (ADR-001: Fastify), with the protections every route
// gets. Each request, in order:
// 1. gets its correlation ID (from the caller if it's a UUID) and the security headers
// 2. is counted against its client address's rate limit (ADR-011 §4)
// 3. is refused if it can change something but didn't come from our own origin (SEC-WEB-01)
// Errors and unknown addresses get a plain body with a reason code (SEC-DATA-04),
// and each request is logged by its route pattern only (ADR-011 §7). Every route
// is checked, answered and documented through its zod schemas, and the API
// serves nothing its OpenAPI document doesn't hold (contract.ts, SEC-WEB-06).
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Config } from '@agentx/platform/config';
import type { Logger } from '@agentx/platform/observability';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';

import { answerClientError } from './client-errors.ts';
import { registerContract } from './contract.ts';
import { CORRELATION_HEADER, correlationIdFrom } from './correlation.ts';
import { errorBody, responseFor, writeErrorBody } from './errors.ts';
import { frameworkLogger } from './framework-logger.ts';
import { type HealthCheck, registerHealth } from './health.ts';
import { isForeignWrite } from './origin-check.ts';
import { countRequest, proxyTrust, RATE_LIMIT_HEADERS, registerRateLimit } from './rate-limit.ts';
import { logAborted, logCompleted, REQUEST_FAILED, RequestLog } from './request-log.ts';
import { SECURITY_HEADERS } from './security-headers.ts';

export interface ServerOptions {
  readonly config: Pick<Config, 'http' | 'log'>;
  readonly logger: Logger;
  readonly ids: IdGenerator;
  readonly healthChecks: readonly HealthCheck[];
}

/** The largest request body read. No route takes a body yet; each later route sets its own, below this. */
const BODY_LIMIT_BYTES = 64 * 1024;

/** How long a client may take to send a whole request (Fastify's advice where no proxy guards the server). */
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * The headers an error response keeps. Anything else a route set is removed:
 * a header value Node refuses would otherwise make the error response fail too,
 * and Fastify's fallback answer shows the error's message. `connection` stays:
 * while the server stops, Fastify sets `close` on it, and without it the
 * connection would stay open and hold the stop up.
 */
const ERROR_HEADERS: ReadonlySet<string> = new Set([
  ...Object.keys(SECURITY_HEADERS),
  CORRELATION_HEADER,
  ...RATE_LIMIT_HEADERS,
  'connection',
]);

export async function buildServer(options: ServerOptions): Promise<FastifyInstance> {
  const { config, logger, ids } = options;
  // SEC-AV-07: only the listed proxies' X-Forwarded-For is believed, for `request.ip` and the
  // rate limit alike. Fastify 5.12 turned off hop counts, which a client reaching the server
  // directly could fake.
  const trust = proxyTrust(config.http.trustedProxies);

  /** Sends the error's plain response, then logs a failure on our side with its detail. */
  const sendError = (error: unknown, request: FastifyRequest, reply: FastifyReply): FastifyReply => {
    const { status, code } = responseFor(error);
    for (const name of Object.keys(reply.getHeaders())) {
      if (!ERROR_HEADERS.has(name)) reply.removeHeader(name);
    }
    void reply.code(status).serializer(writeErrorBody).send(errorBody(code, request.id));
    // After sending, so a failure to log can't stop the plain answer going out.
    if (status === 500) logger.child({ correlationId: request.id }).error(REQUEST_FAILED, { err: error });
    return reply;
  };

  /**
   * A malformed address fails in the router, before any hook runs, so this does
   * what the hooks would: the headers, the count, and the line.
   */
  const answerMalformedAddress = async (error: FastifyError, request: FastifyRequest, reply: FastifyReply) => {
    void reply.headers(SECURITY_HEADERS).header(CORRELATION_HEADER, request.id);
    let answer: unknown = error;
    try {
      await countRequest(request, reply);
    } catch (limited) {
      // Over the rate limit: that's the answer, rather than the malformed address.
      answer = limited;
    }
    sendError(answer, request, reply);
    logCompleted(logger, request, reply);
  };

  const app = Fastify({
    loggerInstance: frameworkLogger(logger, config.log.level),
    logController: new RequestLog(logger),
    genReqId: (request) => correlationIdFrom(request.headers[CORRELATION_HEADER], ids),
    // So `request.ip` is the client's too, for the security events Phase 1 records.
    trustProxy: trust,
    bodyLimit: BODY_LIMIT_BYTES,
    requestTimeout: REQUEST_TIMEOUT_MS,
    // Requests arriving while the server stops are answered as usual, with our
    // headers, rather than with Fastify's bare 503: with one API replica there's
    // nowhere else for them to go.
    return503OnClosing: false,
    frameworkErrors: (error, request, reply) => {
      void answerMalformedAddress(error, request, reply);
    },
    clientErrorHandler: (error, socket) => {
      answerClientError(error, socket, logger, ids);
    },
  });

  // First, so no route escapes it.
  await registerContract(app);
  await registerRateLimit(app, config.http.rateLimitPerMinute, trust);

  app.addHook('onRequest', async (request, reply) => {
    void reply.headers(SECURITY_HEADERS).header(CORRELATION_HEADER, request.id);
    // The request log writes its line on 'finish'. A request that ends without a
    // complete answer (the client hung up, or a streamed answer failed partway) has
    // no 'finish', only 'close', so it's logged here. (A route that misuses the
    // response: a write after the end reaches the crash handler; a response it
    // destroys with an error is logged here, without the error.)
    let finished = false;
    reply.raw.once('finish', () => {
      finished = true;
    });
    reply.raw.once('close', () => {
      if (!finished) logAborted(logger, request);
    });
  });
  // Every request is counted, 404s and refusals included, before anything else can refuse it.
  app.addHook('onRequest', countRequest);
  app.addHook('onRequest', async (request, reply) => {
    if (isForeignWrite(request.method, request.headers.origin, config.http.publicOrigin)) {
      return reply.code(403).serializer(writeErrorBody).send(errorBody('ORIGIN_REFUSED', request.id));
    }
    return undefined;
  });

  app.setErrorHandler(sendError);
  app.setNotFoundHandler((request, reply) => reply.code(404).send(errorBody('NOT_FOUND', request.id)));

  registerHealth(app, options.healthChecks, logger);
  return app;
}
