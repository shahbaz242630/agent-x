// 6A2: the shared step-up. A change done at once is just done; one asked for
// a step-up is kept in this tab and the browser leaves to sign in again,
// coming back to the same page; its confirm sends the ask's body with the
// challenge under one idempotency key however often it is tried, and forgets
// it once the API has decided, but not after a failure on the way.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ask, confirm, forget, pendingFor, stepUpAddress, StepUpStorageBlocked } from './step-up.ts';

vi.mock('./navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('./navigate.ts');

const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const CHANGE = {
  label: 'Freeze Staging-Test-Org-1, pausing its requests',
  askPath: '/v1/organization/freeze',
  confirmPath: '/v1/organization/freeze/confirm',
  body: { pendingRequests: 'pause' },
  organization: '0199a0f0-0000-7000-8000-00000000aaaa',
};

let sent: { path: string; init: RequestInit }[];
let answer: () => Promise<Response>;

const json = (status: number, body: unknown) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));

beforeEach(() => {
  sent = [];
  sessionStorage.clear();
  vi.mocked(goTo).mockClear();
  window.history.replaceState(null, '', '/more');
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      sent.push({ path, init });
      return answer();
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('ask', () => {
  it('gives back a change done at once, keeping nothing and going nowhere', async () => {
    answer = () => json(200, { frozen: true });

    expect(await ask(CHANGE)).toEqual({ done: { frozen: true } });
    expect(sent[0]?.path).toBe('/v1/organization/freeze');
    expect(sent[0]?.init.body).toBe('{"pendingRequests":"pause"}');
    expect(sessionStorage).toHaveLength(0);
    expect(goTo).not.toHaveBeenCalled();
  });

  it('keeps a change asked for a step-up and sends the browser to sign in again, back to this page', async () => {
    answer = () => json(202, { stepUpChallengeId: CHALLENGE });

    expect(await ask(CHANGE)).toBe('stepping');
    expect(pendingFor(CHALLENGE)).toEqual({
      challenge: CHALLENGE,
      label: CHANGE.label,
      confirmPath: CHANGE.confirmPath,
      body: CHANGE.body,
      organization: CHANGE.organization,
      idempotencyKey: expect.stringMatching(/^[0-9a-f-]{36}$/) as unknown,
    });
    expect(goTo).toHaveBeenCalledWith(stepUpAddress(CHALLENGE, '/more'));
  });

  it.each([
    ['a 202 that names no challenge (a download started)', { download: { id: 'd-1' } }],
    ['a challenge that is not one', { stepUpChallengeId: 'undefined' }],
  ])('takes %s as done, keeping nothing and going nowhere', async (_what, body) => {
    answer = () => json(202, body);

    expect(await ask(CHANGE)).toEqual({ done: body });
    expect(sessionStorage).toHaveLength(0);
    expect(goTo).not.toHaveBeenCalled();
  });

  it('refuses to leave when this browser keeps no storage: the change could not be confirmed after', async () => {
    answer = () => json(202, { stepUpChallengeId: CHALLENGE });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError');
    });

    await expect(ask(CHANGE)).rejects.toBeInstanceOf(StepUpStorageBlocked);
    expect(goTo).not.toHaveBeenCalled();
  });
});

describe('stepUpAddress', () => {
  it('names the challenge and a way back to the page with it', () => {
    const address = new URL(stepUpAddress(CHALLENGE, '/approvals'), 'https://app.example');

    expect(address.pathname).toBe('/v1/auth/step-up');
    expect(address.searchParams.get('challenge')).toBe(CHALLENGE);
    expect(address.searchParams.get('returnTo')).toBe(`/approvals?stepped=${CHALLENGE}`);
  });
});

describe('pendingFor', () => {
  it('finds nothing for a challenge never kept, one forgotten, or one kept under another', async () => {
    answer = () => json(202, { stepUpChallengeId: CHALLENGE });
    await ask(CHANGE);
    sessionStorage.setItem('agentx.step-up.other', JSON.stringify({ ...pendingFor(CHALLENGE), challenge: 'x' }));
    sessionStorage.setItem('agentx.step-up.broken', '{not json');

    expect(pendingFor('0199a0f0-0000-7000-8000-000000000bad')).toBeUndefined();
    expect(pendingFor('other')).toBeUndefined();
    expect(pendingFor('broken')).toBeUndefined();
    forget(CHALLENGE);
    expect(pendingFor(CHALLENGE)).toBeUndefined();
  });
});

describe('confirm', () => {
  const pending = { challenge: CHALLENGE, ...CHANGE, idempotencyKey: '0199a0f0-0000-4000-8000-00000000c0de' };
  const keyOf = (at: number) => new Headers(sent[at]?.init.headers).get('idempotency-key');

  beforeEach(() => {
    sessionStorage.setItem(`agentx.step-up.${CHALLENGE}`, JSON.stringify(pending));
  });

  it('sends the ask’s body with the challenge, in its organisation, and forgets it once done', async () => {
    answer = () => json(200, { frozen: true });

    await confirm(pending);
    expect(sent[0]?.path).toBe('/v1/organization/freeze/confirm');
    expect(JSON.parse(sent[0]?.init.body as string)).toEqual({
      pendingRequests: 'pause',
      stepUpChallengeId: CHALLENGE,
    });
    expect(new Headers(sent[0]?.init.headers).get('agentx-organization')).toBe(CHANGE.organization);
    expect(keyOf(0)).toBe(pending.idempotencyKey);
    expect(pendingFor(CHALLENGE)).toBeUndefined();
  });

  it('forgets a change the API refused: its challenge is spent', async () => {
    answer = () => json(403, { error: { code: 'STEP_UP_REQUIRED' } });

    await expect(confirm(pending)).rejects.toMatchObject({ status: 403, code: 'STEP_UP_REQUIRED' });
    expect(pendingFor(CHALLENGE)).toBeUndefined();
  });

  it.each([
    ['a failure on our side', () => json(503, { error: { code: 'UNAVAILABLE' } })],
    ['no answer at all', () => Promise.reject(new TypeError('Failed to fetch'))],
  ])('keeps the change after %s, to be confirmed again', async (_what, failing) => {
    answer = failing;

    await expect(confirm(pending)).rejects.toBeDefined();
    expect(pendingFor(CHALLENGE)).toEqual(pending);
    answer = () => json(200, { frozen: true });
    await confirm(pending);
    // The same write again: had the first reached the API, this replays its answer.
    expect(keyOf(1)).toBe(keyOf(0));
  });
});
