// Phase 4 E1b: the front door for the partner's messages over HTTP, its
// intake a stub: the raw bytes handed on as sent, no sign-in, no origin of
// ours, no idempotency key; 202 for one taken in, 401 for a signature or a
// time that doesn't hold (the same answer for both), 400 for a signed body
// that isn't a message, 413 past 64 KiB and 415 for another content type,
// each before the intake runs (SEC-PTR-01, -06). Not served without a partner.
import type { EventHeaders } from '@agentx/core/modules/providers';
import { afterEach, describe, expect, it } from 'vitest';

import { type Intake, PARTNER_EVENTS_PATH, type PartnerEventIntake } from './partner-events.ts';
import { closeServers, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';

afterEach(closeServers);

/** A stub intake answering `answer`, every call kept. */
function stub(answer: Intake = 'accepted') {
  const calls: { body: Buffer; headers: EventHeaders; ip: string | undefined }[] = [];
  const intake: PartnerEventIntake = {
    take: (body, headers, ip) => {
      calls.push({ body, headers, ip });
      return Promise.resolve(answer);
    },
  };
  return { intake, calls };
}

const BODY = '{ "Meta": { "EventType": "payment.status",  "ConsentId": "c-1" } }';

const sent = (payload: string | Buffer = BODY, headers: Record<string, string> = {}) => ({
  method: 'POST' as const,
  url: PARTNER_EVENTS_PATH,
  payload,
  headers: { 'content-type': 'application/json', 'x-fake-signature': 't=x,v1=y', ...headers },
});

describe('the partner’s messages over HTTP (E1b)', () => {
  it('hands the intake the body byte for byte, with its headers: 202, from no origin of ours and with no key', async () => {
    const { intake, calls } = stub();
    const app = await routeServer({ partnerEvents: intake });

    const reply = await app.inject(sent());

    expect(reply.statusCode).toBe(202);
    expect(reply.json()).toEqual({ status: 'accepted' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.body.toString('utf8')).toBe(BODY);
    expect(calls[0]?.headers['x-fake-signature']).toBe('t=x,v1=y');
    expect(calls[0]?.ip).toBe('127.0.0.1');
  });

  it.each([
    ['a signature that doesn’t hold', 'signature'],
    ['a time outside its window', 'stale'],
  ] as const)('answers 401 PARTNER_EVENT_REFUSED for %s, the same for both', async (_name, answer) => {
    const app = await routeServer({ partnerEvents: stub(answer).intake });

    const reply = await app.inject(sent());

    expect(reply.statusCode).toBe(401);
    expect(reply.json()).toMatchObject({ error: { code: 'PARTNER_EVENT_REFUSED' } });
  });

  it('answers 400 PARTNER_EVENT_MALFORMED for a signed body that isn’t a message', async () => {
    const app = await routeServer({ partnerEvents: stub('malformed').intake });

    const reply = await app.inject(sent());

    expect(reply.statusCode).toBe(400);
    expect(reply.json()).toMatchObject({ error: { code: 'PARTNER_EVENT_MALFORMED' } });
  });

  it('refuses a body past 64 KiB before the intake reads it (SEC-PTR-06)', async () => {
    const { intake, calls } = stub();
    const app = await routeServer({ partnerEvents: intake });

    const reply = await app.inject(sent(Buffer.alloc(64 * 1024 + 1, 0x20)));

    expect(reply.statusCode).toBe(413);
    expect(calls).toEqual([]);
  });

  it('takes a body of exactly 64 KiB', async () => {
    const { intake, calls } = stub();
    const app = await routeServer({ partnerEvents: intake });

    const reply = await app.inject(sent(Buffer.alloc(64 * 1024, 0x20)));

    expect(reply.statusCode).toBe(202);
    expect(calls[0]?.body).toHaveLength(64 * 1024);
  });

  it('refuses another content type before the intake reads it', async () => {
    const { intake, calls } = stub();
    const app = await routeServer({ partnerEvents: intake });

    const reply = await app.inject(sent(BODY, { 'content-type': 'text/plain' }));

    expect(reply.statusCode).toBe(415);
    expect(calls).toEqual([]);
  });

  it('hands on an empty body as none: the intake refuses it', async () => {
    const { intake, calls } = stub('signature');
    const app = await routeServer({ partnerEvents: intake });

    const reply = await app.inject({ method: 'POST', url: PARTNER_EVENTS_PATH });

    expect(reply.statusCode).toBe(401);
    expect(calls[0]?.body).toHaveLength(0);
  });

  it('leaves the rest of the API’s JSON as it was: only this route reads bytes', async () => {
    const app = await routeServer({ partnerEvents: stub().intake });

    // A public JSON route from our own pages: its body is still parsed as JSON, so a broken one is the usual 400.
    const reply = await app.inject({
      method: 'POST',
      url: '/v1/factor-resets/confirm',
      payload: '{"token": ',
      headers: { 'content-type': 'application/json', origin: PUBLIC_ORIGIN },
    });

    expect(reply.statusCode).toBe(400);
    expect(reply.json()).toMatchObject({ error: { code: 'BAD_REQUEST' } });
  });

  it('lets only this route past the origin check: another write from no page of ours is still refused', async () => {
    const app = await routeServer({ partnerEvents: stub().intake });

    const reply = await app.inject({
      method: 'POST',
      url: '/v1/factor-resets/confirm',
      payload: '{}',
      headers: { 'content-type': 'application/json' },
    });

    expect(reply.statusCode).toBe(403);
    expect(reply.json()).toMatchObject({ error: { code: 'ORIGIN_REFUSED' } });
  });

  it('answers 404 where there is no partner', async () => {
    const app = await routeServer({});

    const reply = await app.inject(sent());

    expect(reply.statusCode).toBe(404);
    expect(reply.json()).toMatchObject({ error: { code: 'NOT_FOUND' } });
  });
});
