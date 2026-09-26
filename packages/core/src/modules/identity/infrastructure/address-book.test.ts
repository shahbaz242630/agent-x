// B5-3: the address book against a stand-in login service: who it asks,
// with what, and which answers give an address.
import { describe, expect, it } from 'vitest';

import type { Subject } from '../domain/sign-in.ts';
import { AddressBookUnavailable, createAddressBook } from './address-book.ts';

const ISSUER = 'https://auth.example.test';
const INTERNAL = 'http://ca-agentx-stg-zitadel';
/** Plain words, as every stand-in for a secret here. */
const READER_WORDS = ['stand', 'in', 'reader', 'words'].join('-');
const USER = '01a0f000-0000-7000-8000-00000000000a';
const SUBJECT = '338719472394810051';

interface Asked {
  readonly url: string;
  readonly init: RequestInit;
}

/** A Zitadel user answer with this email. */
const human = (email: unknown, isVerified: unknown) => ({
  user: { userId: SUBJECT, human: { email: { email, isVerified } } },
});

function bookAnswering(
  answer: { readonly status: number; readonly body?: string } | 'network',
  options: { readonly subject?: Subject | undefined; readonly internalOrigin?: string } = {},
) {
  // Said outright, so a test can give no subject at all.
  const subject = 'subject' in options ? options.subject : { issuer: ISSUER, subject: SUBJECT };
  const { internalOrigin } = options;
  const asked: Asked[] = [];
  const book = createAddressBook({
    subjectOf: (userId) => Promise.resolve(userId === USER ? subject : undefined),
    issuer: ISSUER,
    internalOrigin,
    token: READER_WORDS,
    fetch: (url, init = {}) => {
      asked.push({ url: String(url), init });
      if (answer === 'network') return Promise.reject(new TypeError('fetch failed'));
      return Promise.resolve(new Response(answer.body ?? null, { status: answer.status }));
    },
  });
  return { book, asked };
}

const answering = (body: unknown) => ({ status: 200, body: JSON.stringify(body) });

describe('SEC-HA-11 the address book', () => {
  it("asks the login service for the user's subject with its own token, and gives the verified address in lower case", async () => {
    const { book, asked } = bookAnswering(answering(human('Sara.Khan@Example.test', true)));
    await expect(book.addressOf(USER)).resolves.toBe('sara.khan@example.test');
    expect(asked).toHaveLength(1);
    const [{ url, init }] = asked as [Asked];
    expect(url).toBe(`${ISSUER}/v2/users/${SUBJECT}`);
    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBe(`Bearer ${READER_WORDS}`);
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('goes to the internal origin inside the platform, naming the issuer to Zitadel', async () => {
    const { book, asked } = bookAnswering(answering(human('sara@example.test', true)), { internalOrigin: INTERNAL });
    await expect(book.addressOf(USER)).resolves.toBe('sara@example.test');
    const [{ url, init }] = asked as [Asked];
    expect(url).toBe(`${INTERNAL}/v2/users/${SUBJECT}`);
    const headers = new Headers(init.headers);
    expect(headers.get('x-zitadel-instance-host')).toBe('auth.example.test');
    expect(headers.get('x-zitadel-public-host')).toBe('auth.example.test');
    expect(headers.get('authorization')).toBe(`Bearer ${READER_WORDS}`);
  });

  it('gives no address, and asks nobody, for a user it has no subject for, from another issuer, or with a subject not Zitadel-shaped', async () => {
    for (const subject of [
      undefined,
      { issuer: 'https://auth.elsewhere.test', subject: SUBJECT },
      { issuer: `${ISSUER}/`, subject: SUBJECT },
      { issuer: ISSUER, subject: '../admin/v1/users' },
      { issuer: ISSUER, subject: `${SUBJECT}?x=1` },
      { issuer: ISSUER, subject: '' },
    ]) {
      const { book, asked } = bookAnswering(answering(human('sara@example.test', true)), { subject });
      await expect(book.addressOf(USER)).resolves.toBeUndefined();
      expect(asked).toEqual([]);
    }
    const { book, asked } = bookAnswering(answering(human('sara@example.test', true)));
    await expect(book.addressOf('01a0f000-0000-7000-8000-0000000000ff')).resolves.toBeUndefined();
    expect(asked).toEqual([]);
  });

  it('gives no address for one not verified, a machine user, a user the login service no longer has, or an address that is not one', async () => {
    for (const answer of [
      answering(human('sara@example.test', false)),
      answering(human('sara@example.test', 'true')),
      answering(human('sara@example.test', undefined)),
      answering(human(undefined, true)),
      answering(human('not an address', true)),
      answering(human('two@at@example.test', true)),
      answering(human('Sara <sara@example.test>', true)),
      answering({ user: { userId: SUBJECT, machine: { name: 'reader' } } }),
      answering({}),
      answering(null),
      answering([]),
      { status: 404, body: '{"code":5,"message":"User could not be found"}' },
    ]) {
      await expect(bookAnswering(answer).book.addressOf(USER)).resolves.toBeUndefined();
    }
  });

  it('throws, so the notice waits, when the login service is away, refuses the token, or answers wrongly', async () => {
    for (const answer of [
      'network' as const,
      { status: 401 },
      { status: 403 },
      { status: 500 },
      { status: 503 },
      // Zitadel's refusals come as JSON: one must never read as a person with no address, given up for good.
      { status: 401, body: '{"code":16,"message":"Errors.Token.Invalid"}' },
      { status: 403, body: '{"code":7,"message":"No matching permissions found"}' },
      { status: 500, body: JSON.stringify(human('sara@example.test', true)) },
      { status: 200, body: 'not json' },
      { status: 200, body: `{"x":"${'y'.repeat(70 * 1024)}"}` },
    ]) {
      await expect(bookAnswering(answer).book.addressOf(USER)).rejects.toThrow(AddressBookUnavailable);
    }
  });

  it('refuses an issuer with a path, or a token that is not visible ASCII', () => {
    const make = (issuer: string, token: string) => () =>
      createAddressBook({
        subjectOf: () => Promise.resolve(undefined),
        issuer,
        internalOrigin: undefined,
        token,
        fetch: () => Promise.reject(new Error()),
      });
    expect(make(`${ISSUER}/oauth`, READER_WORDS)).toThrow(RangeError);
    expect(make('not a url', READER_WORDS)).toThrow(RangeError);
    expect(make(ISSUER, '')).toThrow(RangeError);
    expect(make(ISSUER, 'with space')).toThrow(RangeError);
    expect(make(ISSUER, READER_WORDS)).not.toThrow();
  });
});
