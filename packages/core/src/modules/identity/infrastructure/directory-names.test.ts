// Decision 25: the login service's names for the audit log, against a
// stand-in login service: who it asks, in calls of at most a hundred, with
// what, and which answers name whom.
import { describe, expect, it } from 'vitest';

import { createDirectoryNames, DirectoryUnavailable, MOST_A_CALL } from './directory-names.ts';
import { OutboundRefused } from '@agentx/platform/outbound';

import { LoginTokenRefused } from './zitadel-call.ts';

const ISSUER = 'https://auth.example.test';
/** Plain words, as every stand-in for a secret here. */
const READER_WORDS = ['stand', 'in', 'reader', 'words'].join('-');

interface Asked {
  readonly url: string;
  readonly init: RequestInit;
}

/** A Zitadel v2 user, human, with this profile and email. */
const user = (userId: unknown, profile: Record<string, unknown>, email?: { email: unknown; isVerified: unknown }) => ({
  userId,
  human: { profile, ...(email !== undefined && { email }) },
});

function directoryAnswering(answers: readonly ({ readonly status: number; readonly body?: unknown } | 'network')[]) {
  const asked: Asked[] = [];
  const directory = createDirectoryNames({
    issuer: ISSUER,
    internalOrigin: undefined,
    token: READER_WORDS,
    fetch: (url, init = {}) => {
      const answer = answers[asked.length] ?? answers.at(-1);
      asked.push({ url: String(url), init });
      if (answer === undefined || answer === 'network') return Promise.reject(new TypeError('fetch failed'));
      const body = answer.body === undefined ? null : JSON.stringify(answer.body);
      return Promise.resolve(new Response(body, { status: answer.status }));
    },
  });
  return { directory, asked };
}

const bodyOf = ({ init }: Asked): unknown => JSON.parse(typeof init.body === 'string' ? init.body : '');

describe('the login service’s names (decision 25)', () => {
  it('asks once for the people named, with its token, and gives each a name and verified address', async () => {
    const { directory, asked } = directoryAnswering([
      {
        status: 200,
        body: {
          result: [
            user('101', { displayName: ' Sara  Khan ' }, { email: 'Sara@Example.test', isVerified: true }),
            user('102', { givenName: 'Omar', familyName: 'Ali' }, { email: 'omar@example.test', isVerified: false }),
          ],
        },
      },
    ]);

    const entries = await directory.entriesOf(['101', '102', '101', 'not-zitadel']);

    expect(Object.fromEntries(entries)).toEqual({
      '101': { name: 'Sara Khan', email: 'sara@example.test' },
      '102': { name: 'Omar Ali', email: undefined },
    });
    expect(directory.issuer).toBe(ISSUER);
    const [call] = asked as [Asked];
    expect(call.url).toBe(`${ISSUER}/v2/users`);
    expect(call.init.method).toBe('POST');
    expect(new Headers(call.init.headers).get('authorization')).toBe(`Bearer ${READER_WORDS}`);
    expect(bodyOf(call)).toEqual({ query: { limit: 2 }, queries: [{ inUserIdsQuery: { userIds: ['101', '102'] } }] });
  });

  it('asks a hundred at a time, and nothing for no one', async () => {
    const { directory, asked } = directoryAnswering([{ status: 200, body: { result: [] } }]);
    const subjects = Array.from({ length: MOST_A_CALL + 1 }, (_, n) => String(1000 + n));

    await directory.entriesOf(subjects);
    await directory.entriesOf([]);

    expect(asked.map((call) => (bodyOf(call) as { query: { limit: number } }).query.limit)).toEqual([MOST_A_CALL, 1]);
  });

  it('leaves out anyone it wasn’t asked about, an ID that isn’t Zitadel’s, and a person with nothing to show', async () => {
    const { directory } = directoryAnswering([
      {
        status: 200,
        body: {
          result: [
            user('999', { displayName: 'Mallory' }),
            user(7, { displayName: 'Not an ID' }),
            'not a user',
            user('101', {}),
          ],
        },
      },
    ]);

    expect(Object.fromEntries(await directory.entriesOf(['101']))).toEqual({
      '101': { name: undefined, email: undefined },
    });
  });

  it('gives an empty answer as no one, and refuses one that holds no list', async () => {
    expect((await directoryAnswering([{ status: 200, body: {} }]).directory.entriesOf(['101'])).size).toBe(0);
    await expect(
      directoryAnswering([{ status: 200, body: { result: 'many' } }]).directory.entriesOf(['101']),
    ).rejects.toBeInstanceOf(DirectoryUnavailable);
  });

  it('throws, naming the step, for a login service that can’t be reached, answers otherwise, or refuses the token', async () => {
    await expect(directoryAnswering(['network']).directory.entriesOf(['101'])).rejects.toThrow(
      new DirectoryUnavailable('the call failed (TypeError)'),
    );
    await expect(directoryAnswering([{ status: 500 }]).directory.entriesOf(['101'])).rejects.toThrow(
      new DirectoryUnavailable('it answered 500'),
    );
    await expect(directoryAnswering([{ status: 403 }]).directory.entriesOf(['101'])).rejects.toBeInstanceOf(
      LoginTokenRefused,
    );
  });

  it.each<[string, unknown, string]>([
    [
      'the allowlist refused it',
      new OutboundRefused('it answered with a redirect'),
      'Outbound request refused: it answered with a redirect',
    ],
    ['it took too long', new DOMException('timed out', 'TimeoutError'), 'it took too long'],
    [
      'a network error with a code',
      new TypeError('fetch failed', { cause: Object.assign(new Error('x'), { code: 'ECONNREFUSED' }) }),
      'TypeError, ECONNREFUSED',
    ],
    ['a code not a code', new TypeError('fetch failed', { cause: { code: 'not one!' } }), 'TypeError'],
    ['something not an error', 'nope', 'not an error'],
  ])('says why a call failed when %s, never what was answered', async (_what, thrown, why) => {
    const directory = createDirectoryNames({
      issuer: ISSUER,
      internalOrigin: undefined,
      token: READER_WORDS,
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- a fetch may reject with anything: that case is tested.
      fetch: () => Promise.reject(thrown),
    });

    await expect(directory.entriesOf(['101'])).rejects.toThrow(new DirectoryUnavailable(`the call failed (${why})`));
  });
});
