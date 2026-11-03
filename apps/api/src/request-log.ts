// ADR-011 §7: one line for each request, with its method, its route pattern
// (never the address as sent, which can hold IDs and a query), and, once it's
// answered, the status and duration; an agent's, its agent and key by their
// IDs (C2-1). Never the client's IP address, the query or the headers.
// Fastify's own request lines log all three, so this log controller replaces
// them. Its other lines (a stream or serializer error) go
// through the framework logger, which keeps only their message and error.
//
// Each line is written under one of three events, which the logger caps per
// minute separately (SEC-AV-09), so a flood that is rate-limited, or that hangs
// up, can't crowd out the lines of the requests that were answered.
//
// With sampling on (log-sample.ts, 4D2e Stage F), an answered 2xx or 3xx line is
// kept 1 in N, saying `sampleOf: N`. A failure, a refusal, a request cut off and
// a sign-in are always kept, and `http.minute` counts every request exactly, a
// process a minute, sampled or capped or not. The activity row keeps each known
// caller's request and its key either way; a row that can't be written has
// `access_log.write_failed`, naming the caller, in its place.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import type { EventName, Logger, ProblemEvent } from '@agentx/platform/observability';
import { type FastifyInstance, type FastifyReply, type FastifyRequest, LogController } from 'fastify';

import { REQUEST_ID_BINDING } from './framework-logger.ts';
import { EVERY_LINE, type LogSample } from './log-sample.ts';

/** A request that was answered. */
export const REQUEST_COMPLETED: ProblemEvent = 'http.request_completed';
/** A request refused by the rate limit, written apart from the others. */
export const REQUEST_RATE_LIMITED: ProblemEvent = 'http.request_rate_limited';
/**
 * A request that ended without a complete answer: the client hung up, a streamed
 * answer failed partway (Fastify's own line says why), or Node's request timeout
 * cut it off (with an `http.client_error` line too).
 */
export const REQUEST_ABORTED: EventName = 'http.request_aborted';
/** A failure on our side, written with its scrubbed error besides the request's line. */
export const REQUEST_FAILED: ProblemEvent = 'http.request_failed';
/** A process's exact counts of its requests since the last such line. */
export const REQUEST_MINUTE: EventName = 'http.minute';

const TOO_MANY_REQUESTS = 429;
const FIRST_REFUSAL = 400;
const MINUTE_MS = 60_000;

/**
 * Every step of signing in or out: who got in, or tried, is never left to a sample.
 * `/v1/auth/session` is not one: the console reads it to show a page, like any other read.
 */
const SIGN_IN_ROUTES: ReadonlySet<string | null> = new Set([
  '/v1/auth/sign-in',
  '/v1/auth/callback',
  '/v1/auth/step-up',
  '/v1/auth/sign-out',
]);

/** A 404, or a malformed address, matched no route, so there's no pattern to log. */
const routeOf = (request: FastifyRequest): string | null => request.routeOptions.url ?? null;

/** The minute's counts, by the first digit of the status. */
const NO_REQUESTS = { requests: 0, s2xx: 0, s3xx: 0, s4xx: 0, s5xx: 0, rateLimited: 0, aborted: 0 };
type Counts = typeof NO_REQUESTS;
const STATUS_CLASSES: Readonly<Record<number, keyof Counts>> = { 2: 's2xx', 3: 's3xx', 4: 's4xx', 5: 's5xx' };

export interface RequestLines {
  /** Writes the request's line, if it is kept. A response that failed on its way out is a warning, with its error. */
  completed(request: FastifyRequest, reply: FastifyReply, error?: Error | null): void;
  /** The line for a request that ended without a complete answer. It has no status: the answer never arrived whole. */
  aborted(request: FastifyRequest): void;
  /** Writes the counts since the last time, when there are any. */
  writeMinute(): void;
}

export function createRequestLines(
  logger: Logger,
  sample: LogSample = EVERY_LINE,
  now: () => number = Date.now,
): RequestLines {
  let counts = { ...NO_REQUESTS };
  let countingSince = now();

  const count = (status: number): void => {
    counts.requests += 1;
    const statusClass = STATUS_CLASSES[Math.floor(status / 100)];
    if (statusClass !== undefined) counts[statusClass] += 1;
    if (status === TOO_MANY_REQUESTS) counts.rateLimited += 1;
  };

  return {
    completed(request, reply, error) {
      const { statusCode: status } = reply;
      count(status);
      const failed = error !== null && error !== undefined;
      const route = routeOf(request);
      const alwaysKept = failed || status >= FIRST_REFUSAL || SIGN_IN_ROUTES.has(route);
      if (!alwaysKept && !sample.keeps(request.id)) return;
      // An agent's request names its agent and the key it was sent with (ADR-011 §1): IDs, public, never the secret.
      // A request the router couldn't read (a malformed address) never had the field set up, so it may be missing.
      const { agent } = request as { readonly agent?: AcceptedKey | null };
      const fields = {
        method: request.method,
        route,
        status,
        durationMs: Math.round(reply.elapsedTime),
        ...(agent !== null && agent !== undefined && { agentId: agent.agentId, agentKeyId: agent.keyId }),
        // Each kept by the sample stands for this many in a reader's sums; off, or always kept, each is itself.
        ...(!alwaysKept && sample.oneIn > 1 && { sampleOf: sample.oneIn }),
      };
      const log = logger.child({ correlationId: request.id });
      const event = status === TOO_MANY_REQUESTS ? REQUEST_RATE_LIMITED : REQUEST_COMPLETED;
      if (failed) log.warn(event, { ...fields, err: error });
      else log.info(event, fields);
    },

    aborted(request) {
      counts.requests += 1;
      counts.aborted += 1;
      logger
        .child({ correlationId: request.id })
        .info(REQUEST_ABORTED, { method: request.method, route: routeOf(request) });
    },

    writeMinute() {
      const to = now();
      if (counts.requests > 0) {
        logger.info(REQUEST_MINUTE, {
          ...counts,
          from: new Date(countingSince).toISOString(),
          to: new Date(to).toISOString(),
        });
      }
      counts = { ...NO_REQUESTS };
      countingSince = to;
    },
  };
}

/** Writes `http.minute` each minute, and what is left of it as the server closes. */
export function registerRequestMinutes(app: FastifyInstance, lines: RequestLines, everyMs = MINUTE_MS): void {
  const timer = setInterval(() => {
    lines.writeMinute();
  }, everyMs);
  // The server keeps the process alive; this alone shouldn't.
  timer.unref();
  app.addHook('onClose', (_instance, done) => {
    clearInterval(timer);
    lines.writeMinute();
    done();
  });
}

export class RequestLog extends LogController {
  readonly #lines: RequestLines;

  constructor(lines: RequestLines) {
    super({ requestIdLogLabel: REQUEST_ID_BINDING });
    this.#lines = lines;
  }

  override incomingRequest(): void {
    // Nothing: the line written when the request ends covers it.
  }

  override requestCompleted(error: Error | null | undefined, request: FastifyRequest, reply: FastifyReply): void {
    this.#lines.completed(request, reply, error);
  }
}
