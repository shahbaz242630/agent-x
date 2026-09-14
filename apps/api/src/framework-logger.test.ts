import { createLogger } from '@agentx/platform/observability';
import { findLeaks, LogCapture, SENSITIVE_SAMPLES as SAMPLES } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { FRAMEWORK_EVENT, frameworkLogger } from './framework-logger.ts';

/** A marker value that must never come out. Plain words, so secret scanners ignore it. */
const PLANTED = 'planted value that must not appear';

function setup() {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'debug', eventCapPerMinute: 1000 } },
    destination: capture,
    now: () => Date.UTC(2026, 8, 14, 10, 0, 0),
  });
  return { framework: frameworkLogger(logger, 'debug'), lines: () => capture.lines(), text: () => capture.text };
}

describe('ADR-013 Fastify logs through our logger, as one event', () => {
  it('writes a message as the detail of an http.framework_log event', () => {
    const { framework, lines } = setup();
    framework.info('Server listening');
    expect(lines()).toEqual([
      {
        time: '2026-09-14T10:00:00.000Z',
        level: 'info',
        service: 'api',
        env: 'test',
        release: 'r-1',
        event: FRAMEWORK_EVENT,
        detail: 'Server listening',
      },
    ]);
  });

  it.each([
    ['fatal', 'error'],
    ['error', 'error'],
    ['warn', 'warn'],
    ['info', 'info'],
    ['debug', 'debug'],
    ['trace', 'debug'],
  ] as const)('writes %s lines at %s', (method, level) => {
    const { framework, lines } = setup();
    framework[method]('a line');
    expect(lines()).toEqual([expect.objectContaining({ level, event: FRAMEWORK_EVENT, detail: 'a line' })]);
  });

  it('writes nothing when told to be silent', () => {
    const { framework, text } = setup();
    framework.silent('a line');
    expect(text()).toBe('');
  });

  it('keeps an error passed as the err field, cleaned like any error', () => {
    const { framework, lines } = setup();
    framework.error({ err: new TypeError(`failed for ${SAMPLES.email}`) }, 'request errored');
    expect(lines()).toEqual([
      expect.objectContaining({
        detail: 'request errored',
        err: expect.objectContaining({ type: 'TypeError', message: 'failed for [email]' }) as unknown,
      }),
    ]);
  });

  it('keeps an error passed on its own, as pino allows', () => {
    const { framework, lines } = setup();
    framework.error(new RangeError('out of range'));
    expect(lines()).toEqual([
      expect.objectContaining({ err: expect.objectContaining({ type: 'RangeError' }) as unknown }),
    ]);
    expect(lines()[0]).not.toHaveProperty('detail');
  });

  it('leaves out the request, the reply and every other field, whose addresses and headers must not be logged', () => {
    const { framework, lines, text } = setup();
    framework.info(
      {
        req: { method: 'GET', url: `/v1/x?token=${PLANTED}`, headers: { authorization: SAMPLES.bearer } },
        res: { statusCode: 200, headers: { 'set-cookie': PLANTED } },
        ip: SAMPLES.ipv4,
        url: SAMPLES.oauthCallback,
        responseTime: 12,
      },
      'request completed',
    );
    expect(Object.keys(lines()[0] ?? {}).sort()).toEqual([
      'detail',
      'env',
      'event',
      'level',
      'release',
      'service',
      'time',
    ]);
    expect(findLeaks(text(), [PLANTED])).toEqual([]);
  });

  // The logger's own reserved names would stop this too; it's here so the adapter's line is checked end to end.
  it("can't set the logger's own fields, such as another organisation's ID", () => {
    const { framework, lines } = setup();
    framework.info({ level: 'fatal', event: 'forged.event', orgId: 'org-b', service: 'other' }, 'a line');
    expect(lines()).toEqual([
      expect.objectContaining({ level: 'info', event: FRAMEWORK_EVENT, service: 'api', detail: 'a line' }),
    ]);
    expect(lines()[0]).not.toHaveProperty('orgId');
  });

  it("doesn't run a getter on the err field, so a field that throws can't break the caller", () => {
    const { framework, lines } = setup();
    const fields = {
      get err(): never {
        throw new Error('getter ran');
      },
    };
    expect(() => {
      framework.warn(fields, 'a line');
    }).not.toThrow();
    expect(lines()).toEqual([expect.objectContaining({ detail: 'a line' })]);
    expect(lines()[0]).not.toHaveProperty('err');
  });

  it.each([
    ['nothing at all', []],
    ['a number', [42]],
    ['null, then a message', [null, 'a line']],
    ['fields, then a non-text message', [{ err: 'failed' }, 42]],
  ] as const)('copes with %s', (_what, args) => {
    const { framework, lines } = setup();
    Reflect.apply(framework.info, framework, args);
    expect(lines()).toEqual([expect.objectContaining({ event: FRAMEWORK_EVENT })]);
  });

  it('cleans the message text like any other field', () => {
    const { framework, text } = setup();
    framework.info(`Route GET:${SAMPLES.relativeCallback} not found for ${SAMPLES.ipv4}`);
    expect(findLeaks(text())).toEqual([]);
  });

  it.each([
    [
      'a quoted address',
      'Reply was already sent, did you forget to "return reply" in the "/v1/items/customer-ref-private" (GET) route?',
      'Reply was already sent, did you forget to "return reply" in the "[path] (GET) route?',
    ],
    ['an address after a colon', 'Route GET:/v1/items/customer-ref-private not found', 'Route GET:[path] not found'],
    [
      'an address whose query holds a quote',
      'sent twice in "/v1/items/x?a=\'note=private-note" (GET)',
      'sent twice in "[path] (GET)',
    ],
    ['a URL, whose // is not a path', 'Server listening at http://[ip]:8080', 'Server listening at http://[ip]:8080'],
  ])('takes %s out of the message', (_what, message, expected) => {
    const { framework, lines } = setup();
    framework.warn(message);
    expect(lines()[0]).toMatchObject({ detail: expected });
  });

  it("keeps a Fastify error's code, its type and its stack, but not its message, which can quote the address", () => {
    const { framework, lines } = setup();
    const error = Object.assign(
      new Error('Reply was already sent, did you forget to "return reply" in "/v1/items/customer-ref-private" (GET)?'),
      {
        name: 'FastifyError',
        code: 'FST_ERR_REP_ALREADY_SENT',
      },
    );
    framework.warn({ err: error });
    const logged = lines()[0]?.err as Record<string, unknown>;
    expect(logged).toMatchObject({
      type: 'FastifyError',
      code: 'FST_ERR_REP_ALREADY_SENT',
      message: 'FST_ERR_REP_ALREADY_SENT',
    });
    expect(logged.stack).toEqual(expect.arrayContaining([expect.stringMatching(/^at /)]));
    expect(JSON.stringify(lines())).not.toContain('customer-ref-private');
  });

  it("keeps the message of an error that is not Fastify's own", () => {
    const { framework, lines } = setup();
    framework.error({ err: Object.assign(new Error('onClose hook failed'), { code: 'ECONNRESET' }) });
    expect(lines()[0]).toMatchObject({ err: { message: 'onClose hook failed', code: 'ECONNRESET' } });
  });
});

describe('ADR-013 a request logger carries only the correlation ID', () => {
  it("adds Fastify's correlation ID binding to each of the request's lines", () => {
    const { framework, lines } = setup();
    framework.child({ correlationId: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b' }, { level: 'trace' }).info('a line');
    expect(lines()).toEqual([
      expect.objectContaining({ correlationId: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', detail: 'a line' }),
    ]);
  });

  it('leaves out every other binding, and a correlation ID that is not text', () => {
    const { framework, lines } = setup();
    framework.child({ reqId: 'req-1', orgId: 'org-b' }).child({ correlationId: 7 }).info('a line');
    expect(lines()[0]).not.toHaveProperty('orgId');
    expect(lines()[0]).not.toHaveProperty('reqId');
    expect(lines()[0]).not.toHaveProperty('correlationId');
  });

  it('shows Fastify the configured level', () => {
    const { framework } = setup();
    expect(framework.level).toBe('debug');
    expect(framework.child({}).level).toBe('debug');
  });
});
