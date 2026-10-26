// 6A1: the console's way to the API: the headers every request carries, a
// write's fresh idempotency key and body, and a refusal read by its reason code.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { api, ApiError, isSignedOut, signInAddress } from './api.ts';

let sent: { path: string; init: RequestInit }[];
let answer: () => Response;

beforeEach(() => {
  sent = [];
  answer = () => new Response('{"ok":true}', { status: 200 });
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      sent.push({ path, init });
      return Promise.resolve(answer());
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const headersOf = (index = 0) => new Headers(sent[index]?.init.headers);

describe('the console’s requests (6A1)', () => {
  it('reads with the browser’s time zone and the organisation named, from its own origin, never cached', async () => {
    expect(await api.get('/v1/members', { organization: 'org-1' })).toEqual({ ok: true });
    const headers = headersOf();
    expect(headers.get('x-time-zone')).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone);
    expect(headers.get('agentx-organization')).toBe('org-1');
    expect(headers.get('idempotency-key')).toBeNull();
    expect(sent[0]?.init).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', body: null });
  });

  it('writes with a fresh idempotency key each time, and its body as JSON', async () => {
    await api.post('/v1/organization/freeze', { organization: 'org-1', body: { pendingRequests: 'pause' } });
    await api.post('/v1/auth/sign-out');
    expect(headersOf(0).get('content-type')).toBe('application/json');
    expect(sent[0]?.init.body).toBe('{"pendingRequests":"pause"}');
    expect(headersOf(0).get('idempotency-key')).toMatch(/^[0-9a-f-]{36}$/);
    expect(headersOf(1).get('idempotency-key')).not.toBe(headersOf(0).get('idempotency-key'));
    expect(headersOf(1).get('content-type')).toBeNull();
    expect(sent[1]?.init.body).toBeNull();
  });

  it('sends no time zone when the browser can’t say', async () => {
    vi.spyOn(Intl, 'DateTimeFormat').mockImplementation(() => {
      throw new RangeError('no zone');
    });
    await api.get('/v1/auth/session');
    expect(headersOf().get('x-time-zone')).toBeNull();
  });

  it('throws a refusal with its reason code, and UNREADABLE for an answer that isn’t the error body', async () => {
    const bodies = [
      '{"error":{"code":"FORBIDDEN","message":"No.","correlationId":"c"}}',
      '<html>proxy</html>',
      '{"error":"FORBIDDEN"}',
      '{"error":{"code":7}}',
      '{"other":true}',
      'null',
    ];
    const codes: string[] = [];
    for (const body of bodies) {
      answer = () => new Response(body, { status: 403 });
      const error: unknown = await api.get('/v1/members').catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(ApiError);
      if (error instanceof ApiError) codes.push(`${String(error.status)} ${error.code}`);
    }
    expect(codes).toEqual(['403 FORBIDDEN', ...Array<string>(5).fill('403 UNREADABLE')]);
  });

  it('knows a 401 as signed out, and nothing else', () => {
    expect(isSignedOut(new ApiError(401, 'UNAUTHENTICATED'))).toBe(true);
    expect(isSignedOut(new ApiError(403, 'FORBIDDEN'))).toBe(false);
    expect(isSignedOut(new Error('401'))).toBe(false);
  });

  it('sends sign-in back to the page asked for', () => {
    expect(signInAddress('/payments?status=unknown')).toBe('/v1/auth/sign-in?returnTo=%2Fpayments%3Fstatus%3Dunknown');
  });
});
