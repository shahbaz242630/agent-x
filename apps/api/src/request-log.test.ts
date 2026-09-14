import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import { logAborted, REQUEST_ABORTED, REQUEST_COMPLETED, REQUEST_RATE_LIMITED, RequestLog } from './request-log.ts';

/** `route: null` stands for a request that matched no route. */
function setup(status = 200, route: string | null = '/health') {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
    destination: capture,
  });
  // Only the fields the log reads.
  const routeOptions = route === null ? {} : { url: route };
  const request = { id: 'c-1', method: 'GET', routeOptions } as unknown as FastifyRequest;
  const reply = { statusCode: status, elapsedTime: 12.6 } as unknown as FastifyReply;
  return { logger, log: new RequestLog(logger), request, reply, lines: () => capture.lines() };
}

describe('ADR-011 §7 the request log controller', () => {
  it('writes the completed line, with the duration rounded to whole milliseconds', () => {
    const { log, request, reply, lines } = setup();
    log.requestCompleted(null, request, reply);
    expect(lines()).toEqual([
      expect.objectContaining({
        level: 'info',
        event: REQUEST_COMPLETED,
        correlationId: 'c-1',
        method: 'GET',
        route: '/health',
        status: 200,
        durationMs: 13,
      }),
    ]);
  });

  it('writes a response that failed on the way out as a warning, with its error', () => {
    const { log, request, reply, lines } = setup();
    log.requestCompleted(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }), request, reply);
    expect(lines()).toEqual([
      expect.objectContaining({
        level: 'warn',
        event: REQUEST_COMPLETED,
        err: expect.objectContaining({ type: 'Error', code: 'ECONNRESET' }) as unknown,
      }),
    ]);
  });

  it('SEC-AV-09 writes a rate-limited request under its own event, so its cap is its own', () => {
    const { log, request, reply, lines } = setup(429);
    log.requestCompleted(undefined, request, reply);
    expect(lines()).toEqual([expect.objectContaining({ event: REQUEST_RATE_LIMITED, status: 429 })]);
  });

  it('writes a request whose client hung up first, with no status and under its own event', () => {
    const { logger, request, lines } = setup(200, null);
    logAborted(logger, request);
    expect(lines()).toEqual([
      expect.objectContaining({
        level: 'info',
        event: REQUEST_ABORTED,
        correlationId: 'c-1',
        method: 'GET',
        route: null,
      }),
    ]);
    expect(lines()[0]).not.toHaveProperty('status');
  });

  it("writes nothing when a request arrives: the line when it ends covers it, and Fastify's would log the address", () => {
    const { log, lines } = setup();
    log.incomingRequest();
    expect(lines()).toEqual([]);
  });

  it('labels each request logger with the correlation ID', () => {
    expect(setup().log.requestIdLogLabel).toBe('correlationId');
  });
});
