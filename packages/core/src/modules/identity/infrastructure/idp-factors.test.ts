// B6-3c: removing a person's second factors at the login service, against a
// stand-in for Zitadel's user API that keeps the person's factors: what is
// asked, what is removed, the check that none is left, and every way it fails.
import type { OutboundFetch } from '@agentx/platform/outbound';
import { describe, expect, it } from 'vitest';

import { createSecondFactorRemover, IdpFactorsUnavailable } from './idp-factors.ts';

const ISSUER = 'https://auth.example.test';
// Plain words, built at run time, as every stand-in for a secret here.
const WORDS = ['reset', 'removing', 'words'].join('-');
const SUBJECT = '312000000000000042';
const USER = `${ISSUER}/v2/users/${SUBJECT}`;

const READY = 'AUTH_FACTOR_STATE_READY';

interface Person {
  factors: Record<string, unknown>[];
  passkeys: Record<string, unknown>[];
  methods: string[];
}

/** Every kind of second factor, with a password: what a removal starts from. */
const everyKind = (): Person => ({
  factors: [
    { state: READY, otp: {} },
    { state: READY, otpSms: {} },
    { state: 'AUTH_FACTOR_STATE_NOT_READY', otpEmail: {} },
    { state: READY, u2f: { id: '312000000000000101', name: 'key' } },
  ],
  passkeys: [{ id: '312000000000000201', state: READY, name: 'Windows Hello' }],
  methods: [
    'AUTHENTICATION_METHOD_TYPE_PASSWORD',
    'AUTHENTICATION_METHOD_TYPE_TOTP',
    'AUTHENTICATION_METHOD_TYPE_OTP_SMS',
    'AUTHENTICATION_METHOD_TYPE_U2F',
    'AUTHENTICATION_METHOD_TYPE_PASSKEY',
    'AUTHENTICATION_METHOD_TYPE_RECOVERY_CODE',
  ],
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** The method a removal at `path` takes away. */
const METHOD_OF: Record<string, string> = {
  '/totp': 'AUTHENTICATION_METHOD_TYPE_TOTP',
  '/otp_sms': 'AUTHENTICATION_METHOD_TYPE_OTP_SMS',
  '/otp_email': 'AUTHENTICATION_METHOD_TYPE_OTP_EMAIL',
  '/recovery_codes': 'AUTHENTICATION_METHOD_TYPE_RECOVERY_CODE',
};

/**
 * A stand-in for Zitadel's user API holding one person: its lists read from
 * `person`, and each removal takes the factor away, unless `answer` says
 * otherwise for a call. Keeps what was asked.
 */
function zitadel(
  person: Person,
  answer: (method: string, path: string) => Response | Error | undefined = () => undefined,
) {
  const asked: { url: string; method: string; init: RequestInit }[] = [];
  const fetch: OutboundFetch = (url, init = {}) => {
    const method = init.method ?? 'GET';
    asked.push({ url: String(url), method, init });
    const path = new URL(String(url)).pathname.replace(`/v2/users/${SUBJECT}`, '');
    const given = answer(method, path);
    if (given instanceof Error) return Promise.reject(given);
    if (given !== undefined) return Promise.resolve(given);
    if (method === 'POST' && path === '/authentication_factors/_search')
      return Promise.resolve(json({ result: person.factors }));
    if (method === 'POST' && path === '/passkeys/_search') return Promise.resolve(json({ result: person.passkeys }));
    if (method === 'GET' && path === '/authentication_methods') {
      return Promise.resolve(json({ details: {}, authMethodTypes: person.methods }));
    }
    if (method === 'DELETE') return Promise.resolve(removeAt(person, path));
    return Promise.resolve(json({ message: 'no such route' }, 404));
  };
  return { asked, fetch };
}

/** A removal at `path` from the stand-in's person: takes the factor away, and its method once none of its kind is left. */
function removeAt(person: Person, path: string): Response {
  const u2f = /^\/u2f\/(\d+)$/.exec(path)?.[1];
  const passkey = /^\/passkeys\/(\d+)$/.exec(path)?.[1];
  const kind = { '/totp': 'otp', '/otp_sms': 'otpSms', '/otp_email': 'otpEmail' }[path];
  if (u2f !== undefined)
    person.factors = person.factors.filter((each) => (each.u2f as { id?: string } | undefined)?.id !== u2f);
  else if (passkey !== undefined) person.passkeys = person.passkeys.filter(({ id }) => id !== passkey);
  else if (kind !== undefined) person.factors = person.factors.filter((each) => each[kind] === undefined);
  else if (path !== '/recovery_codes') return json({ message: 'no such route' }, 404);
  const method = METHOD_OF[path];
  if (method !== undefined) person.methods = person.methods.filter((each) => each !== method);
  if (u2f !== undefined && !person.factors.some((each) => each.u2f !== undefined)) {
    person.methods = person.methods.filter((each) => each !== 'AUTHENTICATION_METHOD_TYPE_U2F');
  }
  if (passkey !== undefined && person.passkeys.length === 0) {
    person.methods = person.methods.filter((each) => each !== 'AUTHENTICATION_METHOD_TYPE_PASSKEY');
  }
  return json({ details: { sequence: '1' } });
}

/** The pauses a remover took between its reads after a removal, each instant here. */
let paused: number[] = [];

const removerWith = (fetch: OutboundFetch, internalOrigin?: string) => {
  paused = [];
  return createSecondFactorRemover({
    issuer: ISSUER,
    internalOrigin,
    token: WORDS,
    fetch,
    pause: (ms) => {
      paused.push(ms);
      return Promise.resolve();
    },
  });
};

/** What it throws, for an expectation. */
const failure = (step: string) => new IdpFactorsUnavailable(step);

describe('removing a person’s second factors at the login service (B6-3c)', () => {
  it('removes every kind, ready or not, each by its own call with the token, and says how many', async () => {
    const person = everyKind();
    const { asked, fetch } = zitadel(person);

    expect(await removerWith(fetch).removeAll(SUBJECT)).toBe(6);

    expect(asked.filter(({ method }) => method === 'DELETE').map(({ url }) => url)).toEqual([
      `${USER}/totp`,
      `${USER}/otp_sms`,
      `${USER}/otp_email`,
      `${USER}/u2f/312000000000000101`,
      `${USER}/passkeys/312000000000000201`,
      `${USER}/recovery_codes`,
    ]);
    expect(asked.every(({ init }) => new Headers(init.headers).get('authorization') === `Bearer ${WORDS}`)).toBe(true);
    expect(person).toEqual({ factors: [], passkeys: [], methods: ['AUTHENTICATION_METHOD_TYPE_PASSWORD'] });
  });

  it('asks for the factors not ready as well as ready, and reads everything again after', async () => {
    const { asked, fetch } = zitadel(everyKind());

    await removerWith(fetch).removeAll(SUBJECT);

    const reads = asked.filter(({ method }) => method !== 'DELETE');
    expect(reads.map(({ method, url }) => `${method} ${url}`)).toEqual([
      `POST ${USER}/authentication_factors/_search`,
      `POST ${USER}/passkeys/_search`,
      `GET ${USER}/authentication_methods`,
      `POST ${USER}/authentication_factors/_search`,
      `POST ${USER}/passkeys/_search`,
      `GET ${USER}/authentication_methods`,
    ]);
    expect(JSON.parse(reads[0]?.init.body as string)).toEqual({
      states: ['AUTH_FACTOR_STATE_NOT_READY', 'AUTH_FACTOR_STATE_READY'],
    });
    expect(new Headers(reads[0]?.init.headers).get('content-type')).toBe('application/json');
    expect(reads[2]?.init.body).toBeUndefined();
    expect(new Headers(reads[2]?.init.headers).has('content-type')).toBe(false);
  });

  it('leaves the password and a link to another login, and asks nothing to remove when there is no second factor', async () => {
    const person: Person = {
      factors: [],
      passkeys: [],
      methods: ['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_IDP'],
    };
    const { asked, fetch } = zitadel(person);

    expect(await removerWith(fetch).removeAll(SUBJECT)).toBe(0);

    expect(asked.some(({ method }) => method === 'DELETE')).toBe(false);
    expect(person.methods).toEqual(['AUTHENTICATION_METHOD_TYPE_PASSWORD', 'AUTHENTICATION_METHOD_TYPE_IDP']);
  });

  it('passes over factors and passkeys already removed, and reads a list Zitadel leaves out, or a state, as empty', async () => {
    const { asked, fetch } = zitadel(everyKind(), (method, path) => {
      if (path === '/authentication_factors/_search') return json({});
      if (path === '/passkeys/_search') {
        return json({ result: [{ id: '312000000000000201', state: 'AUTH_FACTOR_STATE_REMOVED' }] });
      }
      if (method === 'GET') return json({ details: {} });
      return undefined;
    });

    expect(await removerWith(fetch).removeAll(SUBJECT)).toBe(0);
    expect(asked.some(({ method }) => method === 'DELETE')).toBe(false);
  });

  it('removes a factor with no state named (Zitadel leaves an unspecified one out)', async () => {
    const person: Person = { factors: [{ otp: {} }], passkeys: [], methods: [] };
    const { fetch } = zitadel(person);

    expect(await removerWith(fetch).removeAll(SUBJECT)).toBe(1);
    expect(person.factors).toEqual([]);
  });

  it('takes a factor already gone (404) as removed, not counting it', async () => {
    const person = everyKind();
    const { fetch } = zitadel(person, (method, path) => {
      if (method !== 'DELETE' || path !== '/totp') return undefined;
      person.factors = person.factors.filter((each) => each.otp === undefined);
      person.methods = person.methods.filter((each) => each !== 'AUTHENTICATION_METHOD_TYPE_TOTP');
      return json({ message: 'not found' }, 404);
    });

    expect(await removerWith(fetch).removeAll(SUBJECT)).toBe(5);
  });

  it('goes through the internal origin, naming the issuer’s host, as sign-in does', async () => {
    const { asked, fetch } = zitadel(everyKind());

    await removerWith(fetch, 'http://zitadel.internal:8080').removeAll(SUBJECT);

    expect(asked[0]?.url).toBe(`http://zitadel.internal:8080/v2/users/${SUBJECT}/authentication_factors/_search`);
    expect(asked.every(({ url }) => url.startsWith('http://zitadel.internal:8080/v2/users/'))).toBe(true);
    expect(new Headers(asked[0]?.init.headers).get('x-zitadel-instance-host')).toBe('auth.example.test');
  });

  it('waits for the login service to catch up: a factor its search still shows a moment after its removal (the S67 and S70 flake)', async () => {
    const person = everyKind();
    let removedTotp = false;
    let searchesSince = 0;
    const { fetch } = zitadel(person, (method, path) => {
      if (method === 'DELETE' && path === '/totp') {
        removedTotp = true;
        return json({ details: {} });
      }
      // Its search shows the app code for two reads after its removal, then catches up.
      if (removedTotp && method === 'POST' && path === '/authentication_factors/_search' && ++searchesSince > 2) {
        person.factors = person.factors.filter((each) => each.otp === undefined);
        person.methods = person.methods.filter((each) => each !== 'AUTHENTICATION_METHOD_TYPE_TOTP');
      }
      return undefined;
    });

    expect(await removerWith(fetch).removeAll(SUBJECT)).toBe(6);
    expect(paused).toEqual([400, 400]);
  });

  describe('throws, rather than completing a reset, when a factor may be left', () => {
    it('a removal that answered yes and left the factor there, through every read after it', async () => {
      const { fetch } = zitadel(everyKind(), (method, path) =>
        method === 'DELETE' && path.startsWith('/u2f/') ? json({ details: {} }) : undefined,
      );

      await expect(removerWith(fetch).removeAll(SUBJECT)).rejects.toThrow(
        failure('a second factor is still there after its removal'),
      );
      // Read 5 times after the removals, 400 ms apart, before it is called left.
      expect(paused).toEqual([400, 400, 400, 400]);
    });

    it('a security key left, which the methods don’t list (Zitadel lists one the login pages added only with a domain)', async () => {
      const person = everyKind();
      person.methods = person.methods.filter((each) => each !== 'AUTHENTICATION_METHOD_TYPE_U2F');
      const { fetch } = zitadel(person, (method, path) =>
        method === 'DELETE' && path.startsWith('/u2f/') ? json({ details: {} }) : undefined,
      );

      await expect(removerWith(fetch).removeAll(SUBJECT)).rejects.toThrow(
        failure('a second factor is still there after its removal'),
      );
    });

    it('a method still listed after every factor was removed', async () => {
      const person = everyKind();
      const { fetch } = zitadel(person, (method, path) => {
        if (method !== 'DELETE' || path !== '/totp') return undefined;
        person.factors = person.factors.filter((each) => each.otp === undefined);
        return json({ details: {} });
      });

      await expect(removerWith(fetch).removeAll(SUBJECT)).rejects.toThrow(
        failure('a second factor is still there after its removal'),
      );
    });

    it.each([
      [403, 'refused'],
      [500, 'failed'],
    ])('a removal answered %i (%s)', async (status) => {
      const { fetch } = zitadel(everyKind(), (method) => (method === 'DELETE' ? json({}, status) : undefined));

      await expect(removerWith(fetch).removeAll(SUBJECT)).rejects.toThrow(
        failure(`removing a factor: it answered ${String(status)}`),
      );
    });

    it.each([
      ['/authentication_factors/_search', 'reading the factors'],
      ['/passkeys/_search', 'reading the passkeys'],
      ['/authentication_methods', 'reading the methods'],
    ])('a read of %s answered otherwise than 200, the person not found among them', async (path, step) => {
      const { asked, fetch } = zitadel(everyKind(), (_, asked) => (asked === path ? json({}, 404) : undefined));

      await expect(removerWith(fetch).removeAll(SUBJECT)).rejects.toThrow(failure(`${step}: it answered 404`));
      expect(asked.some(({ method }) => method === 'DELETE')).toBe(false);
    });

    it('a call that failed', async () => {
      const { fetch } = zitadel(everyKind(), () => new TypeError('fetch failed'));

      await expect(removerWith(fetch).removeAll(SUBJECT)).rejects.toThrow(
        failure('reading the factors: the call failed'),
      );
    });

    it('an answer that is not JSON, or larger than it may be', async () => {
      const notJson = zitadel(everyKind(), () => new Response('<html>', { status: 200 }));
      await expect(removerWith(notJson.fetch).removeAll(SUBJECT)).rejects.toThrow(
        failure('reading the factors: the answer is not JSON'),
      );

      const large = zitadel(everyKind(), () => json({ result: [], padding: 'x'.repeat(256 * 1024) }));
      await expect(removerWith(large.fetch).removeAll(SUBJECT)).rejects.toThrow(
        failure('reading the factors: the answer was larger than 262144 bytes'),
      );
    });

    it.each([
      ['a list that is not one', { factors: 'none' }, 'reading the factors: the answer holds no list of at most 100'],
      [
        'more factors than a removal reads',
        { factors: Array.from({ length: 101 }, () => ({ otp: {} })) },
        'reading the factors: the answer holds no list of at most 100',
      ],
      ['a factor of no kind', { factors: [{ state: READY }] }, 'a factor is not as the login service writes them'],
      [
        'a factor of two kinds',
        { factors: [{ state: READY, otp: {}, otpSms: {} }] },
        'a factor is not as the login service writes them',
      ],
      [
        'a factor of a kind we don’t know',
        { factors: [{ state: READY, webAuthn: {} }] },
        'a factor is not as the login service writes them',
      ],
      ['a state we don’t know', { factors: [{ state: 'GONE', otp: {} }] }, 'a factor has no state we know'],
      [
        'a security key with no ID',
        { factors: [{ state: READY, u2f: { name: 'key' } }] },
        "a security key's ID is not one",
      ],
      [
        'a security key’s ID that isn’t digits',
        { factors: [{ state: READY, u2f: { id: '../../1' } }] },
        "a security key's ID is not one",
      ],
      ['a passkey’s ID that isn’t digits', { passkeys: [{ id: '1/2', state: READY }] }, "a passkey's ID is not one"],
      ['a passkey’s state we don’t know', { passkeys: [{ id: '1', state: 3 }] }, 'a passkey has no state we know'],
      [
        'a method Zitadel doesn’t name',
        { methods: ['AUTHENTICATION_METHOD_TYPE_MAGIC'] },
        'a method is not one the login service names',
      ],
      ['a method that is no text', { methods: [4] }, 'a method is not one the login service names'],
    ])('%s', async (_, given: Partial<Record<keyof Person, unknown>>, step) => {
      const person = { ...everyKind(), ...given } as Person;
      const { asked, fetch } = zitadel(person);

      await expect(removerWith(fetch).removeAll(SUBJECT)).rejects.toThrow(failure(step));
      expect(asked.some(({ method }) => method === 'DELETE')).toBe(false);
    });
  });

  it('refuses a subject that isn’t the login service’s user ID, asking nothing', async () => {
    const { asked, fetch } = zitadel(everyKind());

    await expect(removerWith(fetch).removeAll('../admin')).rejects.toThrow(RangeError);
    expect(asked).toHaveLength(0);
  });

  it('refuses an issuer that isn’t an origin, and a token that isn’t one', () => {
    const { fetch } = zitadel(everyKind());
    expect(() =>
      createSecondFactorRemover({ issuer: `${ISSUER}/`, internalOrigin: undefined, token: WORDS, fetch }),
    ).toThrow(RangeError);
    expect(() =>
      createSecondFactorRemover({ issuer: ISSUER, internalOrigin: undefined, token: 'two words', fetch }),
    ).toThrow(RangeError);
  });
});

describe('counting a person’s security keys and passkeys (the S68 audit)', () => {
  it('counts the security keys and passkeys ready to use, and nothing else, reading nothing but the two lists', async () => {
    const person = everyKind();
    person.factors.push({ state: 'AUTH_FACTOR_STATE_NOT_READY', u2f: { id: '312000000000000102', name: 'new' } });
    person.passkeys.push({ id: '312000000000000202', state: 'AUTH_FACTOR_STATE_REMOVED' });
    person.passkeys.push({ id: '312000000000000203', state: READY });
    const { fetch, asked } = zitadel(person);

    expect(await removerWith(fetch).passkeysHeld(SUBJECT)).toBe(3);
    expect(asked.map(({ method, url }) => `${method} ${url}`)).toEqual([
      `POST ${USER}/authentication_factors/_search`,
      `POST ${USER}/passkeys/_search`,
    ]);
    expect(JSON.parse(asked[0]?.init.body as string)).toEqual({ states: [READY] });
    expect(new Headers(asked[0]?.init.headers).get('authorization')).toBe(`Bearer ${WORDS}`);
  });

  it('counts none for a person with an app code alone', async () => {
    const { fetch } = zitadel({ factors: [{ state: READY, otp: {} }], passkeys: [], methods: [] });

    expect(await removerWith(fetch).passkeysHeld(SUBJECT)).toBe(0);
  });

  it('counts a list of 100, the most it reads', async () => {
    const passkeys = Array.from({ length: 100 }, (_, index) => ({ id: String(index + 1), state: READY }));
    const { fetch } = zitadel({ factors: [], passkeys, methods: [] });

    expect(await removerWith(fetch).passkeysHeld(SUBJECT)).toBe(100);
  });

  it.each([
    ['an answer not 200', () => json({}, 403), failure('reading the factors: it answered 403')],
    ['a 2xx answer other than 200', () => json({ result: [] }, 201), failure('reading the factors: it answered 201')],
    ['a key of a state it doesn’t know', undefined, failure('a factor has no state we know')],
  ])('throws on %s, never a count', async (_what, answer, thrown) => {
    const person = everyKind();
    if (answer === undefined) person.factors.push({ state: 'SOMETHING_ELSE', u2f: { id: '1' } });
    const { fetch } = zitadel(person, answer === undefined ? undefined : () => answer());

    await expect(removerWith(fetch).passkeysHeld(SUBJECT)).rejects.toThrow(thrown);
  });

  it('refuses a subject that isn’t the login service’s user ID, asking nothing', async () => {
    const { fetch, asked } = zitadel(everyKind());

    await expect(removerWith(fetch).passkeysHeld('../users')).rejects.toThrow(RangeError);
    expect(asked).toEqual([]);
  });
});
