// The local stack's stand-in for ACS (B6-2c) takes exactly what the API's
// notifier sends, signed with the notifier's own function, and refuses a send
// ACS would refuse.
import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { signedHeaders } from '../../packages/core/src/modules/notifications/infrastructure/acs-notifier.ts';
import { API_VERSION, checkSend, mailSink, SEND_PATH, type Send } from './mail-sink.ts';

const accessKey = randomBytes(32).toString('base64');
const HOST = 'mail:8080';
const TARGET = `${SEND_PATH}?api-version=${API_VERSION}`;

const email = (to: string): string =>
  JSON.stringify({
    senderAddress: 'DoNotReply@agentx.localhost',
    recipients: { to: [{ address: to }] },
    content: { subject: 'Your sign-in changed', plainText: 'A second factor was removed.' },
    userEngagementTrackingDisabled: true,
  });

/** A send as the notifier makes it, signed with its own function. */
function signed(body: string, key = accessKey, target = TARGET): Send {
  const headers = signedHeaders('POST', new URL(target, `http://${HOST}`), body, key, new Date());
  return { method: 'POST', target, headers: { ...headers, host: HOST, 'operation-id': 'notice-1' }, body };
}

describe('the stand-in email service checks each send as ACS does', () => {
  it('takes a send the notifier signed, naming its recipients, subject and operation', () => {
    expect(checkSend(signed(email('someone@agentx.localhost')), accessKey)).toEqual({
      status: 202,
      received: { to: ['someone@agentx.localhost'], subject: 'Your sign-in changed', operationId: 'notice-1' },
    });
  });

  it('refuses a send signed with another key, or before the suite has written one', () => {
    const send = signed(email('someone@agentx.localhost'), randomBytes(32).toString('base64'));
    expect(checkSend(send, accessKey)).toEqual({ status: 401 });
    expect(checkSend(signed(email('someone@agentx.localhost')), undefined)).toEqual({ status: 401 });
  });

  it('refuses a body changed after it was signed', () => {
    const send = signed(email('someone@agentx.localhost'));
    expect(checkSend({ ...send, body: email('else@agentx.localhost') }, accessKey)).toEqual({ status: 401 });
  });

  it('refuses a signature made for another host', () => {
    const send = signed(email('someone@agentx.localhost'));
    expect(checkSend({ ...send, headers: { ...send.headers, host: 'elsewhere:8080' } }, accessKey)).toEqual({
      status: 401,
    });
  });

  it('answers only the send, at the version the notifier asks for', () => {
    const body = email('someone@agentx.localhost');
    expect(checkSend({ ...signed(body), method: 'PUT' }, accessKey)).toEqual({ status: 404 });
    expect(checkSend(signed(body, accessKey, '/emails:other'), accessKey)).toEqual({ status: 404 });
    expect(checkSend(signed(body, accessKey, `${SEND_PATH}?api-version=2023-03-31`), accessKey)).toEqual({
      status: 400,
    });
  });

  it('refuses a signed body that is not an email', () => {
    expect(checkSend(signed('not json'), accessKey)).toEqual({ status: 400 });
    expect(checkSend(signed(JSON.stringify({ senderAddress: 'a@b.c', recipients: { to: [] } })), accessKey)).toEqual({
      status: 400,
    });
  });
});

describe('the stand-in email service as a server', () => {
  const lines: string[] = [];
  const keyFile = path.join(mkdtempSync(path.join(tmpdir(), 'mail-sink-')), 'access-key');
  const server = mailSink(keyFile, (line) => lines.push(line));
  let origin = '';

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  /** Sends as the notifier does, signed for the host the server is reached at. */
  const send = async (body: string): Promise<number> => {
    const url = new URL(TARGET, origin);
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...signedHeaders('POST', url, body, accessKey, new Date()),
        'content-type': 'application/json',
        'operation-id': 'notice-2',
      },
      body,
    });
    return response.status;
  };

  it('answers compose’s health check', async () => {
    expect((await fetch(`${origin}/health`)).status).toBe(200);
  });

  it('refuses every send until the suite writes the key, then takes them, one log line each', async () => {
    expect(await send(email('someone@agentx.localhost'))).toBe(401);
    writeFileSync(keyFile, `${accessKey}\n`);
    expect(await send(email('someone@agentx.localhost'))).toBe(202);

    expect(lines.map((line) => JSON.parse(line) as unknown)).toEqual([
      { event: 'mail.refused', status: 401 },
      {
        event: 'mail.received',
        to: ['someone@agentx.localhost'],
        subject: 'Your sign-in changed',
        operationId: 'notice-2',
      },
    ]);
  });

  it('refuses a body larger than an email', async () => {
    const response = await fetch(new URL(TARGET, origin), { method: 'POST', body: 'x'.repeat(65 * 1024) });
    expect(response.status).toBe(413);
    expect(lines.at(-1)).toBe(JSON.stringify({ event: 'mail.refused', status: 413 }));
  });
});
