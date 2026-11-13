// The last release GitHub recorded for staging (AZ2c): read from a stand-in of
// GitHub's REST API, never GitHub itself.
import { describe, expect, it } from 'vitest';

import { type GitHubGet, lastRelease } from './anchor.ts';

const IN_CI = { GITHUB_ACTIONS: 'true', AGENTX_DEPLOYMENTS_TOKEN: 'token', GITHUB_REPOSITORY: 'owner/repo' } as const;
const DEPLOYMENTS = 'https://api.github.com/repos/owner/repo/deployments';
const commit = (fill: string): string => fill.repeat(40);

/** Main's line, newest first: c, then b, then a; anything else isn't on it. */
const LINE: ReadonlyMap<string, number> = new Map([
  [commit('c'), 0],
  [commit('b'), 1],
  [commit('a'), 2],
]);
const place = (each: string): number | undefined => LINE.get(each);

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

/** A full page of 30 deployments of `sha`, ids from `first` down, each latest status `state`. */
function fullPage(first: number, sha: string, state: string): Record<string, unknown> {
  const ids = Array.from({ length: 30 }, (_, index) => first - index);
  const entries: [string, unknown][] = [
    [page(Math.floor((1000 - first) / 30) + 1), ids.map((id) => ({ id, sha }))],
    ...ids.map((id): [string, unknown] => [statuses(id), [{ state }]]),
  ];
  return Object.fromEntries(entries);
}

describe('the last release GitHub recorded for staging', () => {
  it('is the newest on main’s line of the deployments that succeeded, this run’s own in progress passed over', async () => {
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
    expect(await lastRelease(IN_CI, place, get)).toEqual({ kind: 'release', commit: commit('a') });
    // A short page ends the listing: no page 2 is asked for.
    expect(asked).toEqual([page(1), statuses(3), statuses(2), statuses(1)].map((url) => `token ${url}`));
    // One a later success marked inactive succeeded too.
    const inactive = github({ [page(1)]: [{ id: 1, sha: commit('a') }], [statuses(1)]: [{ state: 'inactive' }] });
    expect(await lastRelease(IN_CI, place, inactive.get)).toEqual({ kind: 'release', commit: commit('a') });
  });

  it('is the newest commit, not the newest made: a re-run of an old release job records an old commit after a newer one', async () => {
    const { get } = github({
      [page(1)]: [
        { id: 3, sha: commit('a') },
        { id: 2, sha: commit('b') },
        { id: 1, sha: commit('a') },
      ],
      [statuses(3)]: [{ state: 'success' }],
      [statuses(2)]: [{ state: 'inactive' }],
      [statuses(1)]: [{ state: 'inactive' }],
    });
    expect(await lastRelease(IN_CI, place, get)).toEqual({ kind: 'release', commit: commit('b') });
    // A success of a commit off main's line is the anchor itself: it then holds nothing, red (belowAnchor).
    const offLine = github({
      [page(1)]: [
        { id: 2, sha: commit('c') },
        { id: 1, sha: commit('f') },
      ],
      [statuses(2)]: [{ state: 'success' }],
      [statuses(1)]: [{ state: 'inactive' }],
    });
    expect(await lastRelease(IN_CI, place, offLine.get)).toEqual({ kind: 'release', commit: commit('f') });
  });

  it('reads every page to the end of the listing, a success on a later page counting', async () => {
    const { get } = github({
      ...fullPage(1000, commit('a'), 'failure'),
      [page(2)]: [{ id: 970, sha: commit('b') }],
      [statuses(970)]: [{ state: 'success' }],
    });
    expect(await lastRelease(IN_CI, place, get)).toEqual({ kind: 'release', commit: commit('b') });
  });

  it('is none when the listing ends with no success: a fresh environment, or only failures so far', async () => {
    expect(await lastRelease(IN_CI, place, github({ [page(1)]: [] }).get)).toEqual({ kind: 'none' });
    // The first release: its own deployment, in progress, is all there is.
    const first = github({ [page(1)]: [{ id: 1, sha: commit('a') }], [statuses(1)]: [{ state: 'in_progress' }] });
    expect(await lastRelease(IN_CI, place, first.get)).toEqual({ kind: 'none' });
    // Only failures, then the end (hand `apps` deploys record no deployment).
    const failed = github({
      [page(1)]: [
        { id: 2, sha: commit('b') },
        { id: 1, sha: commit('a') },
      ],
      [statuses(2)]: [{ state: 'failure' }],
      [statuses(1)]: [],
    });
    expect(await lastRelease(IN_CI, place, failed.get)).toEqual({ kind: 'none' });
    // Full pages to the end, then an empty one.
    const emptyAfter = github({ ...fullPage(1000, commit('a'), 'failure'), [page(2)]: [] });
    expect(await lastRelease(IN_CI, place, emptyAfter.get)).toEqual({ kind: 'none' });
  });

  it('is not read outside GitHub Actions, where there is no token', async () => {
    const { get, asked } = github({});
    expect(await lastRelease({}, place, get)).toEqual({ kind: 'unread' });
    expect(await lastRelease({ GITHUB_ACTIONS: 'false', AGENTX_DEPLOYMENTS_TOKEN: 'token' }, place, get)).toEqual({
      kind: 'unread',
    });
    expect(asked).toEqual([]);
  });

  it('fails closed in GitHub Actions on anything it can’t read, or 150 deployments without a success', async () => {
    const said = (why: string): string =>
      `GitHub's record of the last release to staging couldn't be read (${why}), so a roll-back past it can't be ruled out (AZ2c), and nothing was changed.`;
    const noToken = 'no AGENTX_DEPLOYMENTS_TOKEN or repository given';
    const cases: [Readonly<Record<string, string>>, GitHubGet, string][] = [
      [{ GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'owner/repo' }, github({}).get, noToken],
      // GITHUB_TOKEN is never read: cosign's GitHub keychain and az would pick it up.
      [{ GITHUB_ACTIONS: 'true', GITHUB_TOKEN: 'token', GITHUB_REPOSITORY: 'owner/repo' }, github({}).get, noToken],
      [{ ...IN_CI, GITHUB_REPOSITORY: 'owner/repo/../x' }, github({}).get, noToken],
      [IN_CI, github({}).get, 'HTTP 404'],
      [IN_CI, () => Promise.reject(new Error('offline')), 'nothing answered'],
      [IN_CI, github({ [page(1)]: { message: 'x' } }).get, 'its list of deployments was not a list'],
      [IN_CI, github({ [page(1)]: [{ id: 1, sha: 'main' }] }).get, 'a deployment named no commit'],
      [IN_CI, github({ [page(1)]: [{ id: 'x', sha: commit('a') }] }).get, 'a deployment named no commit'],
    ];
    for (const [env, get, why] of cases) {
      await expect(lastRelease(env, place, get), why).rejects.toThrow(said(why));
    }
    // Five full pages, none a success: the cap, then the same.
    const endless: GitHubGet = (url) =>
      Promise.resolve({
        status: 200,
        body: url.includes('/statuses')
          ? [{ state: 'failure' }]
          : Array.from({ length: 30 }, (_, index) => ({ id: index, sha: commit('a') })),
      });
    await expect(lastRelease(IN_CI, place, endless)).rejects.toThrow(
      said('none of its last 150 deployments to staging succeeded'),
    );
  });
});
