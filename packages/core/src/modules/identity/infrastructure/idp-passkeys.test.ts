import type { OutboundFetch } from '@agentx/platform/outbound';
import { describe, expect, it } from 'vitest';

import { createOwnPasskeys, OWN_PASSKEY_NAME, OwnPasskeysUnavailable } from './idp-passkeys.ts';
import { LoginTokenRefused } from './zitadel-call.ts';

const ISSUER = 'https://auth.example.test';
const TOKEN = ['the', 'persons', 'token'].join('-');
const SUBJECT = '401348154160578690';
const PASSKEY = '401348157432135810';
const OPTIONS = { publicKey: { challenge: 'Y2g', rp: { id: 'auth.example.test', name: 'Agent X' } } };

function zitadel(answer: () => Response | Error) {
  const asked: { url: string; init: RequestInit }[] = [];
  const fetch: OutboundFetch = (url, init) => {
    asked.push({ url: String(url), init: init ?? {} });
    const found = answer();
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  };
  return { asked, fetch };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const passkeysWith = (fetch: OutboundFetch, internalOrigin?: string) =>
  createOwnPasskeys({ issuer: ISSUER, internalOrigin, fetch });

describe('SA6: a passkey registered at the login service as the person', () => {
  it('asks for a passkey on the login service’s own host, with the person’s token, and hands back its ID and options', async () => {
    const { asked, fetch } = zitadel(() => json({ passkeyId: PASSKEY, publicKeyCredentialCreationOptions: OPTIONS }));

    expect(await passkeysWith(fetch).register(TOKEN, SUBJECT)).toEqual({ passkeyId: PASSKEY, options: OPTIONS });

    const [call] = asked;
    expect(call?.url).toBe(`${ISSUER}/v2/users/${SUBJECT}/passkeys`);
    expect(call?.init.method).toBe('POST');
    expect(new Headers(call?.init.headers).get('authorization')).toBe(`Bearer ${TOKEN}`);
    expect(JSON.parse(call?.init.body as string)).toEqual({ domain: 'auth.example.test' });
  });

  it('goes through the internal origin, naming the issuer’s host, as sign-in does', async () => {
    const { asked, fetch } = zitadel(() => json({ passkeyId: PASSKEY, publicKeyCredentialCreationOptions: OPTIONS }));

    await passkeysWith(fetch, 'http://zitadel.internal').register(TOKEN, SUBJECT);

    expect(asked[0]?.url).toBe(`http://zitadel.internal/v2/users/${SUBJECT}/passkeys`);
  });

  it.each([
    ['no passkey ID', { publicKeyCredentialCreationOptions: OPTIONS }, 'names no passkey'],
    [
      'a passkey ID that isn’t one',
      { passkeyId: 'x;y', publicKeyCredentialCreationOptions: OPTIONS },
      'names no passkey',
    ],
    ['no options', { passkeyId: PASSKEY }, 'no options'],
    [
      'options without a key',
      { passkeyId: PASSKEY, publicKeyCredentialCreationOptions: { publicKey: [] } },
      'no options',
    ],
    ['options that are a list', { passkeyId: PASSKEY, publicKeyCredentialCreationOptions: [] }, 'no options'],
  ])('refuses an answer with %s', async (_name, answer, words) => {
    const { fetch } = zitadel(() => json(answer));

    await expect(passkeysWith(fetch).register(TOKEN, SUBJECT)).rejects.toThrow(words);
  });

  it('refuses an answer other than 200, and a subject that isn’t one, asking nothing', async () => {
    const { asked, fetch } = zitadel(() => json({}, 500));

    await expect(passkeysWith(fetch).register(TOKEN, SUBJECT)).rejects.toThrow(OwnPasskeysUnavailable);
    await expect(passkeysWith(fetch).register(TOKEN, '../admin')).rejects.toThrow(RangeError);
    expect(asked).toHaveLength(1);
  });

  it('confirms the key the browser made under the passkey’s ID, with Agent X’s name for it', async () => {
    const { asked, fetch } = zitadel(() => json({ details: {} }));
    const credential = { id: 'abc', type: 'public-key' };

    expect(await passkeysWith(fetch).confirm(TOKEN, SUBJECT, PASSKEY, credential)).toBe('confirmed');

    expect(asked[0]?.url).toBe(`${ISSUER}/v2/users/${SUBJECT}/passkeys/${PASSKEY}`);
    expect(JSON.parse(asked[0]?.init.body as string)).toEqual({
      publicKeyCredential: credential,
      passkeyName: OWN_PASSKEY_NAME,
    });
  });

  it.each([400, 404, 412])('reads a %s as the key refused', async (status) => {
    const { fetch } = zitadel(() => json({}, status));

    expect(await passkeysWith(fetch).confirm(TOKEN, SUBJECT, PASSKEY, {})).toBe('refused');
  });

  it('reads the person’s token refused as the key refused, and any other answer as the login service failing', async () => {
    expect(await passkeysWith(zitadel(() => json({}, 401)).fetch).confirm(TOKEN, SUBJECT, PASSKEY, {})).toBe('refused');
    await expect(passkeysWith(zitadel(() => json({}, 503)).fetch).confirm(TOKEN, SUBJECT, PASSKEY, {})).rejects.toThrow(
      OwnPasskeysUnavailable,
    );
    await expect(
      passkeysWith(zitadel(() => new TypeError('fetch failed')).fetch).confirm(TOKEN, SUBJECT, PASSKEY, {}),
    ).rejects.toThrow(OwnPasskeysUnavailable);
    await expect(passkeysWith(zitadel(() => json({}, 401)).fetch).register(TOKEN, SUBJECT)).rejects.toThrow(
      LoginTokenRefused,
    );
  });

  it('refuses a subject or passkey that isn’t the login service’s ID, asking nothing', async () => {
    const { asked, fetch } = zitadel(() => json({}));

    await expect(passkeysWith(fetch).confirm(TOKEN, 'x', PASSKEY, {})).rejects.toThrow(RangeError);
    await expect(passkeysWith(fetch).confirm(TOKEN, SUBJECT, '../1', {})).rejects.toThrow(RangeError);
    expect(asked).toEqual([]);
  });
});
