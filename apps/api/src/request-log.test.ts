import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { EVERY_LINE, type LogSample } from './log-sample.ts';
import {
  createRequestLines,
  registerRequestMinutes,
  REQUEST_ABORTED,
  REQUEST_COMPLETED,
  REQUEST_MINUTE,
  REQUEST_RATE_LIMITED,
  RequestLog,
} from './request-log.ts';

/** Keeps nothing it is asked about: what's kept under it was never asked. */
const NOTHING: LogSample = { oneIn: 20, keeps: () => false };
const IN_THE_SAMPLE: LogSample = { oneIn: 20, keeps: () => true };

/** `route: null` stands for a request that matched no route. */
function setup(
  status = 200,
  route: string | null = '/health',
  agent: { agentId: string; keyId: string } | null = null,
  sample: LogSample = EVERY_LINE,
) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
    destination: capture,
  });
  // Only the fields the log reads.
  const routeOptions = route === null ? {} : { url: route };
  const request = { id: 'c-1', method: 'GET', routeOptions, agent } as unknown as FastifyRequest;
  const reply = { statusCode: status, elapsedTime: 12.6 } as unknown as FastifyReply;
  let at = 0;
  const lines = createRequestLines(logger, sample, () => at);
  return {
    requestLines: lines,
    log: new RequestLog(lines),
    request,
    reply,
    lines: () => capture.lines(),
    /** The clock moved to `ms`. */
    clockAt: (ms: number) => {
      at = ms;
    },
    with: (statusCode: number) => ({ statusCode, elapsedTime: 1 }) as unknown as FastifyReply,
  };
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
    expect(lines()[0]).not.toHaveProperty('sampleOf');
  });

  it("C2-1 names an agent's request's agent and key by their IDs, never the key itself", () => {
    const agent = { agentId: '0199a0f0-0000-7000-8000-0000000000a1', keyId: '0199a0f0-0000-7000-8000-0000000000b1' };
    const { log, request, reply, lines } = setup(200, '/v1/agent', agent);
    log.requestCompleted(null, request, reply);
    expect(lines()).toEqual([
      expect.objectContaining({ route: '/v1/agent', agentId: agent.agentId, agentKeyId: agent.keyId }),
    ]);
  });

  it('names no agent on a request the router never set one up for (a malformed address)', () => {
    const { log, reply, lines } = setup(400, null);
    const request = { id: 'c-1', method: 'GET', routeOptions: {} } as unknown as FastifyRequest;
    log.requestCompleted(null, request, reply);
    expect(lines()).toEqual([expect.objectContaining({ status: 400, route: null })]);
    expect(lines()[0]).not.toHaveProperty('agentId');
  });

  it('names no agent on a request that is not one', () => {
    const { log, request, reply, lines } = setup();
    log.requestCompleted(null, request, reply);
    expect(lines()[0]).not.toHaveProperty('agentId');
    expect(lines()[0]).not.toHaveProperty('agentKeyId');
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
    const { requestLines, request, lines } = setup(200, null);
    requestLines.aborted(request);
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

describe('4D2e Stage F the request log, sampled', () => {
  it.each([[200], [201], [204], [302], [304]])('leaves a %i out of the sample unwritten', (status) => {
    const { log, request, reply, lines } = setup(status, '/v1/agent', null, NOTHING);
    log.requestCompleted(null, request, reply);
    expect(lines()).toEqual([]);
  });

  it.each([[200], [304]])('writes a %i in the sample, saying how many it stands for', (status) => {
    const { log, request, reply, lines } = setup(status, '/v1/agent', null, IN_THE_SAMPLE);
    log.requestCompleted(null, request, reply);
    expect(lines()).toEqual([expect.objectContaining({ event: REQUEST_COMPLETED, status, sampleOf: 20 })]);
  });

  it.each([[400], [401], [403], [404], [409], [422], [429], [500], [503]])(
    'a failure is never sampled: a %i is written, and not marked as sampled',
    (status) => {
      const { log, request, reply, lines } = setup(status, '/v1/agent', null, NOTHING);
      log.requestCompleted(null, request, reply);
      expect(lines()).toHaveLength(1);
      expect(lines()[0]).toMatchObject({ status });
      expect(lines()[0]).not.toHaveProperty('sampleOf');
    },
  );

  it('a failure is never sampled: an answer that failed on its way out, though its status said 200', () => {
    const { log, request, reply, lines } = setup(200, '/v1/agent', null, NOTHING);
    log.requestCompleted(new Error('socket hang up'), request, reply);
    expect(lines()).toEqual([expect.objectContaining({ level: 'warn', status: 200 })]);
  });

  it('a failure is never sampled: a request cut off', () => {
    const { requestLines, request, lines } = setup(200, '/v1/agent', null, NOTHING);
    requestLines.aborted(request);
    expect(lines()).toEqual([expect.objectContaining({ event: REQUEST_ABORTED })]);
  });

  it.each([['/v1/auth/sign-in'], ['/v1/auth/callback'], ['/v1/auth/step-up'], ['/v1/auth/sign-out']])(
    'always writes a sign-in step, %s, even a redirect',
    (route) => {
      const { log, request, reply, lines } = setup(302, route, null, NOTHING);
      log.requestCompleted(null, request, reply);
      expect(lines()).toEqual([expect.objectContaining({ route, status: 302 })]);
      expect(lines()[0]).not.toHaveProperty('sampleOf');
    },
  );

  it('samples a read of the session, which the console makes for any page', () => {
    const { log, request, lines, with: reply } = setup(200, '/v1/auth/session', null, NOTHING);
    log.requestCompleted(null, request, reply(200));
    expect(lines()).toEqual([]);
  });
});

describe('4D2e Stage F http.minute', () => {
  it('counts every request exactly, whatever is sampled, with the span it covers', () => {
    const { log, requestLines, request, lines, clockAt, with: reply } = setup(200, '/v1/agent', null, NOTHING);
    clockAt(60_000);
    for (const status of [200, 200, 204, 302, 404, 429, 500]) log.requestCompleted(null, request, reply(status));
    requestLines.aborted(request);
    requestLines.writeMinute();
    expect(lines().filter(({ event }) => event === REQUEST_MINUTE)).toEqual([
      expect.objectContaining({
        level: 'info',
        requests: 8,
        s2xx: 3,
        s3xx: 1,
        s4xx: 2,
        s5xx: 1,
        rateLimited: 1,
        aborted: 1,
        from: '1970-01-01T00:00:00.000Z',
        to: '1970-01-01T00:01:00.000Z',
      }),
    ]);
  });

  it('starts again from nothing, and says nothing of a minute with no requests', () => {
    const { log, requestLines, request, reply, lines, clockAt } = setup();
    log.requestCompleted(null, request, reply);
    clockAt(60_000);
    requestLines.writeMinute();
    clockAt(120_000);
    requestLines.writeMinute();
    clockAt(180_000);
    log.requestCompleted(null, request, reply);
    clockAt(240_000);
    requestLines.writeMinute();
    expect(lines().filter(({ event }) => event === REQUEST_MINUTE)).toEqual([
      expect.objectContaining({ requests: 1, to: '1970-01-01T00:01:00.000Z' }),
      expect.objectContaining({ requests: 1, from: '1970-01-01T00:02:00.000Z', to: '1970-01-01T00:04:00.000Z' }),
    ]);
  });

  it('is written on its timer, what is left as the server closes, and no more after', async () => {
    const { log, requestLines, request, reply, lines } = setup();
    const app = Fastify();
    registerRequestMinutes(app, requestLines, 5);
    log.requestCompleted(null, request, reply);
    await vi.waitFor(() => {
      expect(lines().filter(({ event }) => event === REQUEST_MINUTE)).toHaveLength(1);
    });
    log.requestCompleted(null, request, reply);
    await app.close();
    const written = lines().filter(({ event }) => event === REQUEST_MINUTE).length;
    expect(written).toBeGreaterThanOrEqual(2);
    log.requestCompleted(null, request, reply);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(lines().filter(({ event }) => event === REQUEST_MINUTE)).toHaveLength(written);
  });
});
