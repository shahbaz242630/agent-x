// The last release GitHub recorded for staging (AZ2c): read from a stand-in of
// GitHub's REST API, never GitHub itself.
import { describe, expect, it } from 'vitest';

import { type GitHubGet, lastRelease } from './anchor.ts';

const IN_CI = { GITHUB_ACTIONS: 'true', GITHUB_TOKEN: 'token', GITHUB_REPOSITORY: 'owner/repo' } as const;
const DEPLOYMENTS = 'https://api.github.com/repos/owner/repo/deployments';
const commit = (fill: string): string => fill.repeat(40);

/** A stand-in GitHub answering each URL from a table, and keeping each URL asked with the token it was asked with. */
function github(answers: Readonly<Record<string, unknown>>): { get: GitHubGet; asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    get: (url, token) => {
      asked.push(`${token} ${url}`);
      if (!(url in answers)) return Promise.resolve({ status: 404, body: undefined });
      return Promise.resolve({ status: 200, body: answers[url] });
    },
  };
}

const page = (number: number): string => `${DEPLOYMENTS}?environment=staging&per_page=30&page=${String(number)}`;
const statuses = (id: number): string => `${DEPLOYMENTS}/${String(id)}/statuses?per_page=1`;

describe('the last release GitHub recorded for staging', () => {
  it('is the newest deployment whose latest status says it succeeded, this run’s own in progress passed over', async () => {
    const { get, asked } = github({
      [page(1)]: [
        { id: 3, sha: commit('c') },
        { id: 2, sha: commit('b') },
        { id: 1, sha: commit('a') },
      ],
      [statuses(3)]: [{ state: 'in_progress' }],
      [statuses(2)]: [{ state: 'failure' }],
      [statuses(1)]: [{ state: 'success' }],
    });
    expect(await lastRelease(IN_CI, get)).toEqual({ kind: 'release', commit: commit('a') });
    expect(asked).toEqual([page(1), statuses(3), statuses(2), statuses(1)].map((url) => `token ${url}`));
    // One a later success marked inactive succeeded too.
    const inactive = github({ [page(1)]: [{ id: 1, sha: commit('a') }], [statuses(1)]: [{ state: 'inactive' }] });
    expect(await lastRelease(IN_CI, inactive.get)).toEqual({ kind: 'release', commit: commit('a') });
  });

  it('reads on page by page, and is none when GitHub has recorded no deployment to staging', async () => {
    const later = github({
      [page(1)]: [{ id: 2, sha: commit('b') }],
      [statuses(2)]: [],
      [page(2)]: [{ id: 1, sha: commit('a') }],
      [statuses(1)]: [{ state: 'success' }],
    });
    expect(await lastRelease(IN_CI, later.get)).toEqual({ kind: 'release', commit: commit('a') });
    expect(await lastRelease(IN_CI, github({ [page(1)]: [] }).get)).toEqual({ kind: 'none' });
  });

  it('is not read outside GitHub Actions, where there is no token', async () => {
    const { get, asked } = github({});
    expect(await lastRelease({}, get)).toEqual({ kind: 'unread' });
    expect(await lastRelease({ GITHUB_ACTIONS: 'false', GITHUB_TOKEN: 'token' }, get)).toEqual({ kind: 'unread' });
    expect(asked).toEqual([]);
  });

  it('fails closed in GitHub Actions on anything it can’t read, in plain words', async () => {
    const said = (why: string): string =>
      `GitHub's record of the last release to staging couldn't be read (${why}), so a roll-back past it can't be ruled out (AZ2c), and nothing was changed.`;
    const cases: [Readonly<Record<string, string>>, GitHubGet, string][] = [
      [
        { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'owner/repo' },
        github({}).get,
        'no GITHUB_TOKEN or repository given',
      ],
      [{ ...IN_CI, GITHUB_REPOSITORY: 'owner/repo/../x' }, github({}).get, 'no GITHUB_TOKEN or repository given'],
      [IN_CI, github({}).get, 'HTTP 404'],
      [IN_CI, () => Promise.reject(new Error('offline')), 'nothing answered'],
      [IN_CI, github({ [page(1)]: { message: 'x' } }).get, 'its list of deployments was not a list'],
      [IN_CI, github({ [page(1)]: [{ id: 1, sha: 'main' }] }).get, 'a deployment named no commit'],
      [IN_CI, github({ [page(1)]: [{ id: 'x', sha: commit('a') }] }).get, 'a deployment named no commit'],
      [
        IN_CI,
        github({
          [page(1)]: [{ id: 1, sha: commit('a') }],
          [statuses(1)]: [{ state: 'failure' }],
          [page(2)]: [],
        }).get,
        'none of its last 150 deployments to staging succeeded',
      ],
    ];
    for (const [env, get, why] of cases) {
      await expect(lastRelease(env, get), why).rejects.toThrow(said(why));
    }
    // Five pages at most, then the same.
    const endless: GitHubGet = (url) =>
      Promise.resolve({
        status: 200,
        body: url.includes('/statuses') ? [{ state: 'failure' }] : [{ id: 1, sha: commit('a') }],
      });
    await expect(lastRelease(IN_CI, endless)).rejects.toThrow(
      said('none of its last 150 deployments to staging succeeded'),
    );
  });
});
