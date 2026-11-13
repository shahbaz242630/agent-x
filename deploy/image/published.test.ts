import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { GitHubGet } from '../azure/anchor.ts';
import {
  ATTEST_JOB,
  main,
  parseCommit,
  type Request,
  requestFor,
  type Steps,
  wait,
  WAIT_MINUTES,
} from './published.ts';
import { SIGNING_WORKFLOW } from './verify.ts';

const COMMIT = 'a'.repeat(40);
const OTHER = 'b'.repeat(40);
const REQUEST: Request = { commit: COMMIT, repository: 'owner/repo', token: 'job-token' };
const ENV = { GITHUB_REPOSITORY: 'owner/repo', AGENTX_ACTIONS_TOKEN: 'job-token', GITHUB_OUTPUT: '/tmp/out' };

type Answer = Awaited<ReturnType<GitHubGet>> | Error | string;

/** CI's run for a push of the commit to main, as GitHub lists it. */
const run = (fields: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: 7,
  head_sha: COMMIT,
  event: 'push',
  head_branch: 'main',
  path: SIGNING_WORKFLOW,
  status: 'in_progress',
  conclusion: null,
  ...fields,
});
const runs = (...listed: unknown[]): Answer => ({ status: 200, body: { workflow_runs: listed } });
const jobs = (...listed: unknown[]): Answer => ({ status: 200, body: { jobs: listed } });
const attest = (status: string, conclusion: string | null = null) => ({ name: ATTEST_JOB, status, conclusion });

/** GitHub answering each GET in turn from the list; the clock moving 30 s each sleep. */
function github(answers: Answer[]) {
  const urls: string[] = [];
  const said: string[] = [];
  const outputs: string[] = [];
  let clock = 0;
  const get: GitHubGet = async (url, token) => {
    expect(token).toBe('job-token');
    urls.push(url);
    const answer = answers.shift();
    if (answer === undefined) throw new Error('asked once too often');
    if (answer instanceof Error) throw answer;
    if (typeof answer === 'string') {
      // Something thrown that isn't an Error, which the wait must not take for a missed answer.
      const thrown: unknown = answer;
      throw thrown;
    }
    return Promise.resolve(answer);
  };
  const steps: Steps = {
    get,
    sleep: (ms) => {
      clock += ms;
      return Promise.resolve();
    },
    now: () => clock,
    say: (line) => said.push(line),
    output: (line) => outputs.push(line),
  };
  return { steps, urls, said, outputs };
}

describe('the release waits for CI’s image of its commit (AZ2d)', () => {
  it('waits until CI’s attest job passed, then gives that run’s ID, reading only CI’s push runs of the commit on main', async () => {
    const { steps, urls, said, outputs } = github([
      runs(),
      runs(run({ status: 'queued' })),
      jobs(),
      runs(run()),
      jobs(attest('in_progress')),
      runs(run()),
      jobs({ name: 'Other' }, attest('completed', 'success')),
    ]);
    await expect(wait(REQUEST, steps)).resolves.toBe(0);
    expect(outputs).toEqual(['run-id=7']);
    expect(urls[0]).toBe(
      `https://api.github.com/repos/owner/repo/actions/workflows/ci.yml/runs?head_sha=${COMMIT}&event=push&branch=main&per_page=20`,
    );
    expect(urls[2]).toBe('https://api.github.com/repos/owner/repo/actions/runs/7/jobs?filter=latest&per_page=100');
    expect(said).toEqual([
      `Waiting: CI has started no run for a push of ${COMMIT} to main yet.`,
      "Waiting: CI's run 7 is queued; its image isn't attested yet.",
      "Waiting: CI's run 7 is in_progress; its image isn't attested yet.",
      `CI's run 7 published, signed and attested the image of ${COMMIT}.`,
    ]);
  });

  it('takes the newest of CI’s runs for the commit, and none of a pull request’s, another branch’s, workflow’s or commit’s', async () => {
    const { steps, urls, outputs } = github([
      runs(
        run({ id: 3 }),
        run({ id: 9 }),
        run({ id: 50, event: 'pull_request' }),
        run({ id: 51, head_branch: 'other' }),
        run({ id: 52, path: '.github/workflows/load-image.yml' }),
        run({ id: 53, head_sha: OTHER }),
        run({ id: '54' }),
        'not a run',
      ),
      jobs(attest('completed', 'success')),
    ]);
    await wait(REQUEST, steps);
    expect(outputs).toEqual(['run-id=9']);
    expect(urls[1]).toContain('/actions/runs/9/jobs');
  });

  it('refuses when the attest job ended any other way, or the run ended without it', async () => {
    for (const [answers, why] of [
      [[runs(run()), jobs(attest('completed', 'failure'))], `CI's job "${ATTEST_JOB}" ended failure`],
      [[runs(run()), jobs(attest('completed', 'skipped'))], `CI's job "${ATTEST_JOB}" ended skipped`],
      [
        [runs(run({ status: 'completed', conclusion: 'cancelled' })), jobs()],
        `CI's run ended cancelled before its job "${ATTEST_JOB}" passed`,
      ],
    ] as const) {
      const { steps, outputs } = github([...answers]);
      await expect(wait(REQUEST, steps)).rejects.toThrow(
        `${why}, so there is no checked image of ${COMMIT} to release, so nothing was released and staging is unchanged. Read CI's run for this commit; once its image jobs pass (re-run its failed jobs if they failed), re-run this workflow.`,
      );
      expect(outputs).toEqual([]);
    }
  });

  it('forgives a few missed answers in a row, and counts again after one that came', async () => {
    const missed: Answer[] = [
      new Error('reset'),
      { status: 502, body: undefined },
      { status: 200, body: [] },
      { status: 200, body: {} },
    ];
    const { steps, said, outputs } = github([
      ...missed,
      runs(run()),
      jobs(attest('queued')),
      ...missed,
      runs(run()),
      jobs(attest('completed', 'success')),
    ]);
    await wait(REQUEST, steps);
    expect(outputs).toEqual(['run-id=7']);
    expect(said).toContain("Waiting: GitHub's Actions API didn't answer (nothing answered); asking again.");
    expect(said).toContain("Waiting: GitHub's Actions API didn't answer (HTTP 502); asking again.");
    expect(said).toContain("Waiting: GitHub's Actions API didn't answer (its answer was not an object); asking again.");
    expect(said).toContain(
      "Waiting: GitHub's Actions API didn't answer (its answer held no workflow_runs); asking again.",
    );
  });

  it('gives up after five missed answers in a row, saying nothing was released', async () => {
    const { steps } = github(Array.from({ length: 5 }, () => ({ status: 500, body: undefined })));
    await expect(wait(REQUEST, steps)).rejects.toThrow(
      `GitHub's Actions API couldn't be read 5 times in a row (HTTP 500), so whether CI's image of ${COMMIT} is ready is unknown, so nothing was released and staging is unchanged. Re-run this workflow; if it repeats, check GitHub's status page.`,
    );
  });

  it('lets anything thrown that isn’t an error through as it is', async () => {
    const { steps } = github(['odd']);
    await expect(wait(REQUEST, steps)).rejects.toBe('odd');
  });

  it(`gives up after ${String(WAIT_MINUTES)} minutes, saying what it last saw`, async () => {
    // The first look at 0 s, then one every 30 s while another fits before the end.
    const polls = (WAIT_MINUTES * 60) / 30 + 1;
    const { steps, said } = github(Array.from({ length: polls }, () => runs()));
    await expect(wait(REQUEST, steps)).rejects.toThrow(
      `CI's image of ${COMMIT} wasn't ready after ${String(WAIT_MINUTES)} minutes (CI has started no run for a push of ${COMMIT} to main yet), so nothing was released and staging is unchanged.`,
    );
    // The same wait said once, not every 30 s.
    expect(said).toHaveLength(1);
  });
});

describe('its command line', () => {
  it('takes one full commit, and the token, repository and output file from the job', () => {
    expect(requestFor(parseCommit([COMMIT]), ENV)).toEqual(REQUEST);
    for (const argv of [[], ['abc'], [COMMIT, 'extra']]) {
      expect(() => parseCommit(argv)).toThrow('Give one commit, in full (40 hex).');
    }
    for (const env of [
      { ...ENV, AGENTX_ACTIONS_TOKEN: undefined },
      { ...ENV, GITHUB_REPOSITORY: 'no slash' },
      { ...ENV, GITHUB_REPOSITORY: undefined },
      { ...ENV, GITHUB_OUTPUT: undefined },
    ]) {
      expect(() => requestFor(COMMIT, env)).toThrow(
        'AGENTX_ACTIONS_TOKEN, GITHUB_REPOSITORY and GITHUB_OUTPUT must all be set',
      );
    }
  });

  it('answers 2 with the usage for a wrong commit, 1 with the reason for a refusal, 0 when ready', async () => {
    const said: string[] = [];
    const say = (line: string): void => {
      said.push(line);
    };
    await expect(main(['abc'], ENV, { say })).resolves.toBe(2);
    expect(said.at(-1)).toBe('Give one commit, in full (40 hex).\nUsage: node deploy/image/published.ts <commit>');
    await expect(main([COMMIT], {}, { say })).resolves.toBe(1);
    // Ready at the first look: the run's ID appended to the step's output file, as Actions reads it.
    const folder = mkdtempSync(path.join(tmpdir(), 'published-'));
    try {
      const output = path.join(folder, 'output');
      writeFileSync(output, 'earlier=1\n');
      const { steps } = github([runs(run()), jobs(attest('completed', 'success'))]);
      await expect(main([COMMIT], { ...ENV, GITHUB_OUTPUT: output }, { get: steps.get, say })).resolves.toBe(0);
      expect(readFileSync(output, 'utf8')).toBe('earlier=1\nrun-id=7\n');
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
  });
});
