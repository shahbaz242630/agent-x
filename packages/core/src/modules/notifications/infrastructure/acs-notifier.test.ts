// B5-3: the ACS notifier against a stand-in fetch: what it sends, how it signs
// it (checked against the Azure SDK's own expected signatures), and how each
// answer is counted.
import { createHash, createHmac } from 'node:crypto';

import { FixedClock } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import type { NoticeMessage } from '../domain/messages.ts';
import { createAcsNotifier, EMAIL_API_VERSION, signedHeaders } from './acs-notifier.ts';

const ENDPOINT = 'https://acs-agentx-test.uae.communication.azure.com';
const SENDER = 'DoNotReply@3d41a667.azurecomm.net';
/** A stand-in key: 32 bytes, as base64. */
const KEY = Buffer.alloc(32, 7).toString('base64');
const NOW = new Date('2026-09-26T12:00:00Z');

const MESSAGE: NoticeMessage = {
  id: '01a0f000-0000-7000-8000-000000000001',
  to: 'sara.khan@example.test',
  subject: 'Agent X: a member of your organisation is now an admin',
  text: 'A member of one of your Agent X organisations was given the admin role.',
};

interface Sent {
  readonly url: string;
  readonly init: RequestInit;
}

/** A notifier whose fetch records each call and answers with `status`, or throws. */
function notifierAnswering(status: number | 'network') {
  const sent: Sent[] = [];
  const notifier = createAcsNotifier({
    settings: { endpoint: ENDPOINT, sender: SENDER, accessKey: KEY },
    fetch: (url, init = {}) => {
      sent.push({ url: String(url), init });
      if (status === 'network') return Promise.reject(new TypeError('fetch failed'));
      return Promise.resolve(
        new Response(status === 202 ? null : '{"error":{"message":"to sara.khan@..."}}', { status }),
      );
    },
    clock: new FixedClock(NOW),
  });
  return { notifier, sent };
}

describe('SEC-HA-11 the ACS notifier', () => {
  it("signs a request exactly as the Azure SDK's own tests expect", () => {
    // Azure SDK for JS, communication-common, communicationKeyCredentialPolicy.spec.ts: a GET with no body, key "pw==".
    const at = new Date('2022-04-13T18:09:12.451Z');
    const expected: readonly (readonly [string, string])[] = [
      ['https://example.com/testPath?testQuery=test', 'DGdgwggJWnQyc6EHjR/Vbqg1ES64KpD6U2XwTDDj3tU='],
      ['https://example.com/testPath', '+6tWkg3lNKVjQHHmxkdGQcJjUgzclsWTMebnuCz1ngU='],
      ['https://example.com:8080/testPath', 'zFAbbRWjUmDbcK/DT3cYgnwMyh+kXJxBpC3qlxnPCh0='],
    ];
    for (const [url, signature] of expected) {
      expect(signedHeaders('GET', new URL(url), '', 'pw==', at)).toEqual({
        'x-ms-date': 'Wed, 13 Apr 2022 18:09:12 GMT',
        'x-ms-content-sha256': '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
        authorization: `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`,
      });
    }
  });

  it('sends one plain-text email, untracked, named by the notice, signed over its own body', async () => {
    const { notifier, sent } = notifierAnswering(202);
    await expect(notifier.send(MESSAGE)).resolves.toEqual({ outcome: 'sent' });
    expect(sent).toHaveLength(1);
    const [{ url, init }] = sent as [Sent];
    expect(url).toBe(`${ENDPOINT}/emails:send?api-version=${EMAIL_API_VERSION}`);
    expect(init.method).toBe('POST');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const body = init.body as string;
    expect(JSON.parse(body)).toEqual({
      senderAddress: SENDER,
      recipients: { to: [{ address: MESSAGE.to }] },
      content: { subject: MESSAGE.subject, plainText: MESSAGE.text },
      userEngagementTrackingDisabled: true,
    });
    const headers = init.headers as Record<string, string>;
    expect(headers['operation-id']).toBe(MESSAGE.id);
    expect(headers['content-type']).toBe('application/json');
    expect(headers['x-ms-date']).toBe('Sat, 26 Sep 2026 12:00:00 GMT');
    // The hash is the body's, and the signature covers the path, the query, the date, the host and that hash.
    const hash = createHash('sha256').update(body).digest('base64');
    expect(headers['x-ms-content-sha256']).toBe(hash);
    const toSign = `POST\n/emails:send?api-version=${EMAIL_API_VERSION}\n${headers['x-ms-date']};${new URL(ENDPOINT).host};${hash}`;
    const signature = createHmac('sha256', Buffer.from(KEY, 'base64')).update(toSign).digest('base64');
    expect(headers.authorization).toBe(
      `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`,
    );
  });

  it("counts each answer as sent, a lasting refusal, or one to try again, naming none by ACS's words", async () => {
    const cases: readonly (readonly [number | 'network', unknown])[] = [
      [202, { outcome: 'sent' }],
      [400, { outcome: 'failed', failure: 'email_refused', lasting: true }],
      [413, { outcome: 'failed', failure: 'email_refused', lasting: true }],
      [422, { outcome: 'failed', failure: 'email_refused', lasting: true }],
      [401, { outcome: 'failed', failure: 'email_unauthorized', lasting: false }],
      [403, { outcome: 'failed', failure: 'email_unauthorized', lasting: false }],
      [429, { outcome: 'failed', failure: 'email_throttled', lasting: false }],
      [408, { outcome: 'failed', failure: 'email_unavailable', lasting: false }],
      [409, { outcome: 'failed', failure: 'email_unavailable', lasting: false }],
      [500, { outcome: 'failed', failure: 'email_unavailable', lasting: false }],
      [503, { outcome: 'failed', failure: 'email_unavailable', lasting: false }],
      // Any other success is not the 202 ACS gives for an email it has taken.
      [200, { outcome: 'failed', failure: 'email_unavailable', lasting: false }],
      ['network', { outcome: 'failed', failure: 'email_unreachable', lasting: false }],
    ];
    for (const [status, outcome] of cases) {
      await expect(notifierAnswering(status).notifier.send(MESSAGE)).resolves.toEqual(outcome);
    }
  });

  it('refuses an endpoint with a path, or a key that is not base64', () => {
    const make = (endpoint: string, accessKey: string) => () =>
      createAcsNotifier({
        settings: { endpoint, sender: SENDER, accessKey },
        fetch: () => Promise.reject(new Error()),
        clock: new FixedClock(NOW),
      });
    expect(make(`${ENDPOINT}/emails`, KEY)).toThrow(RangeError);
    expect(make('not a url', KEY)).toThrow(RangeError);
    expect(make(ENDPOINT, 'not base64!')).toThrow(RangeError);
    expect(make(ENDPOINT, '')).toThrow(RangeError);
    expect(make(ENDPOINT, KEY)).not.toThrow();
  });
});
