// The release's wait for CI's image (Outstanding-Work AZ2d).
//
//   node deploy/image/published.ts <commit>
//
// The release to staging runs in a workflow of its own (RELEASE_WORKFLOW),
// started by the same push to main as CI (SIGNING_WORKFLOW): a workflow that
// runs on pull_request may name no secret (scripts/check-workflows.mjs), and
// the release reads three staging secrets, the pins of AZ2c. So it can't
// `need` CI's image jobs as it did; it waits here instead, until CI's run for
// the same commit has published, signed and attested the image and checked it
// with the deploy check (the job ATTEST_JOB passed), and then gives that run's
// ID, whose artifact DIGEST_ARTIFACT names the digest. The release checks the
// image itself again before anything is written (release.ts).
//
// Only CI's run for a push to main of this very commit counts: a pull
// request's runs, another branch's and another workflow's are never read.
// GitHub's Actions API is read as the job's own token (AGENTX_ACTIONS_TOKEN,
// `actions: read`) every 30 s for at most WAIT_MINUTES, a few missed answers in
// a row forgiven. The run's ID goes to the step's output (GITHUB_OUTPUT).
import { appendFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

import { type GitHubGet, realGitHubGet } from '../azure/anchor.ts';
import { UsageError } from '../azure/deploy.ts';
import { runCli } from '../azure/jobs.ts';
import { SIGNING_WORKFLOW } from './verify.ts';

/** The push-only workflow the release to staging runs in (release-job.test.ts). */
export const RELEASE_WORKFLOW = '.github/workflows/release.yml';

/** CI's last image job: it passed only when the image is published, signed, attested and accepted by the deploy check. */
export const ATTEST_JOB = 'Image (main) - attach the SBOM and verify';

/** The artifact ATTEST_JOB leaves for the release: one file, `digest`, the image's digest. */
export const DIGEST_ARTIFACT = 'release-digest';

/** At most this long, past CI's own longest path to its image (about 110 minutes) and some queueing. */
export const WAIT_MINUTES = 150;

/** How often GitHub is asked again. */
const POLL_MS = 30_000;

/** Missed answers in a row forgiven: a two-hour wait shouldn't fail on one hiccup of GitHub's API. */
const MISSES_FORGIVEN = 4;

const USAGE = 'Usage: node deploy/image/published.ts <commit>';

const API = 'https://api.github.com';
const COMMIT = /^[0-9a-f]{40}$/;
const NOTHING_RELEASED = 'so nothing was released and staging is unchanged';
const RERUN = 'once its image jobs pass (re-run its failed jobs if they failed), re-run this workflow';

export interface Steps {
  readonly get: GitHubGet;
  readonly sleep: (ms: number) => Promise<void>;
  readonly now: () => number;
  readonly say: (line: string) => void;
  /** Writes the step's output: `run-id=<id>`. */
  readonly output: (line: string) => void;
}

export interface Request {
  readonly commit: string;
  readonly repository: string;
  readonly token: string;
}

/** What one look found: still waiting (and why), the run whose image is ready, or a run that will never have it. */
type Seen =
  | { readonly kind: 'waiting'; readonly why: string }
  | { readonly kind: 'ready'; readonly run: number }
  | { readonly kind: 'failed'; readonly why: string };

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** A missed answer: a reason to ask again, up to MISSES_FORGIVEN in a row. */
class Missed extends Error {}

async function read(get: GitHubGet, url: string, token: string): Promise<Readonly<Record<string, unknown>>> {
  let answer: Awaited<ReturnType<GitHubGet>>;
  try {
    answer = await get(url, token);
  } catch (error) {
    if (error instanceof Error) throw new Missed('nothing answered');
    throw error;
  }
  if (answer.status !== 200) throw new Missed(`HTTP ${String(answer.status)}`);
  if (!isRecord(answer.body)) throw new Missed('its answer was not an object');
  return answer.body;
}

const listOf = (body: Readonly<Record<string, unknown>>, field: string): Readonly<Record<string, unknown>>[] => {
  const listed = body[field];
  if (!Array.isArray(listed)) throw new Missed(`its answer held no ${field}`);
  return (listed as unknown[]).filter(isRecord);
};

/** CI's run for a push to main of this commit, the newest if it was started more than once; none yet is undefined. */
function ciRun(
  runs: readonly Readonly<Record<string, unknown>>[],
  commit: string,
): Readonly<Record<string, unknown>> | undefined {
  const ours = runs.filter(
    (run) =>
      typeof run.id === 'number' &&
      run.head_sha === commit &&
      run.event === 'push' &&
      run.head_branch === 'main' &&
      run.path === SIGNING_WORKFLOW,
  );
  return ours.reduce<Readonly<Record<string, unknown>> | undefined>(
    (newest, run) => (newest === undefined || Number(run.id) > Number(newest.id) ? run : newest),
    undefined,
  );
}

async function look(request: Request, get: GitHubGet): Promise<Seen> {
  const { commit, repository, token } = request;
  const workflow = SIGNING_WORKFLOW.split('/').at(-1) ?? SIGNING_WORKFLOW;
  const runs = await read(
    get,
    `${API}/repos/${repository}/actions/workflows/${workflow}/runs?head_sha=${commit}&event=push&branch=main&per_page=20`,
    token,
  );
  const run = ciRun(listOf(runs, 'workflow_runs'), commit);
  if (run === undefined) return { kind: 'waiting', why: `CI has started no run for a push of ${commit} to main yet` };
  const id = Number(run.id);
  const jobs = await read(
    get,
    `${API}/repos/${repository}/actions/runs/${String(id)}/jobs?filter=latest&per_page=100`,
    token,
  );
  const attest = listOf(jobs, 'jobs').find((job) => job.name === ATTEST_JOB);
  if (attest?.status === 'completed') {
    return attest.conclusion === 'success'
      ? { kind: 'ready', run: id }
      : { kind: 'failed', why: `CI's job "${ATTEST_JOB}" ended ${String(attest.conclusion)}` };
  }
  if (run.status === 'completed') {
    return { kind: 'failed', why: `CI's run ended ${String(run.conclusion)} before its job "${ATTEST_JOB}" passed` };
  }
  return { kind: 'waiting', why: `CI's run ${String(id)} is ${String(run.status)}; its image isn't attested yet` };
}

/** One look, forgiving up to MISSES_FORGIVEN unanswered asks in a row (counted in `misses`) as waiting. */
async function lookForgiving(request: Request, steps: Steps, misses: { count: number }): Promise<Seen> {
  try {
    const seen = await look(request, steps.get);
    misses.count = 0;
    return seen;
  } catch (error) {
    if (!(error instanceof Missed)) throw error;
    misses.count += 1;
    if (misses.count > MISSES_FORGIVEN) {
      throw new Error(
        `GitHub's Actions API couldn't be read ${String(misses.count)} times in a row (${error.message}), so whether CI's image of ${request.commit} is ready is unknown, ${NOTHING_RELEASED}. Re-run this workflow; if it repeats, check GitHub's status page.`,
        { cause: error },
      );
    }
    return { kind: 'waiting', why: `GitHub's Actions API didn't answer (${error.message}); asking again` };
  }
}

/** Waits for CI's image of the commit: 0 with the run's ID in the output when it is ready; an error in plain words if never. */
export async function wait(request: Request, steps: Steps): Promise<number> {
  const deadline = steps.now() + WAIT_MINUTES * 60_000;
  let said = '';
  const misses = { count: 0 };
  for (;;) {
    const seen = await lookForgiving(request, steps, misses);
    if (seen.kind === 'ready') {
      steps.say(`CI's run ${String(seen.run)} published, signed and attested the image of ${request.commit}.`);
      steps.output(`run-id=${String(seen.run)}`);
      return 0;
    }
    if (seen.kind === 'failed') {
      throw new Error(
        `${seen.why}, so there is no checked image of ${request.commit} to release, ${NOTHING_RELEASED}. Read CI's run for this commit; ${RERUN}.`,
      );
    }
    if (seen.why !== said) steps.say(`Waiting: ${seen.why}.`);
    said = seen.why;
    if (steps.now() + POLL_MS > deadline) {
      throw new Error(
        `CI's image of ${request.commit} wasn't ready after ${String(WAIT_MINUTES)} minutes (${seen.why}), ${NOTHING_RELEASED}. Read CI's run for this commit; ${RERUN}.`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/** The commit from the command line: a UsageError for anything but one commit in full. */
export function parseCommit(argv: readonly string[]): string {
  const [commit = '', ...extra] = argv;
  if (!COMMIT.test(commit) || extra.length > 0) throw new UsageError('Give one commit, in full (40 hex).');
  return commit;
}

/** The request, with the token and repository the job gives; an error in plain words when the job gave too little. */
export function requestFor(commit: string, env: Readonly<Record<string, string | undefined>>): Request {
  const repository = env.GITHUB_REPOSITORY ?? '';
  const token = env.AGENTX_ACTIONS_TOKEN ?? '';
  if (token === '' || !/^[\w.-]+\/[\w.-]+$/.test(repository) || (env.GITHUB_OUTPUT ?? '') === '') {
    throw new Error(
      `AGENTX_ACTIONS_TOKEN, GITHUB_REPOSITORY and GITHUB_OUTPUT must all be set (the release workflow sets them), ${NOTHING_RELEASED}. Run this only as the release workflow's step.`,
    );
  }
  return { commit, repository, token };
}

export function main(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env,
  steps: Partial<Steps> = {},
): Promise<number> {
  const say = steps.say ?? console.log;
  return runCli(
    USAGE,
    say,
    () => parseCommit(argv),
    (commit) =>
      wait(requestFor(commit, env), {
        get: steps.get ?? realGitHubGet,
        sleep: steps.sleep ?? ((ms) => sleep(ms)),
        now: steps.now ?? Date.now,
        say,
        output:
          steps.output ??
          ((line) => {
            appendFileSync(env.GITHUB_OUTPUT ?? '', `${line}\n`);
          }),
      }),
  );
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
