// The last release GitHub recorded for staging (AZ2c), an anchor outside Azure.
// CI's write to the API could lower how many revisions Azure keeps, roll the API
// back, and restore the setting: Azure's own record of what ran is then purged.
// GitHub records a deployment for every job that uses the `staging` environment
// (the release job does), and a stolen Azure sign-in can't write that record. So
// in CI the release and the job-start watch read the newest deployment to
// staging that succeeded, and hold both workloads to be at least that new on
// main's line. A hand `apps` deploy isn't a GitHub deployment; a newer one is
// fine. Outside GitHub Actions there is no token: said in one line, not red. In
// GitHub Actions, a record that can't be read is red: fail closed.

/** What GitHub says of the last release to staging: its commit, none ever, or not read (not a GitHub Actions run). */
export type Anchor =
  { readonly kind: 'release'; readonly commit: string } | { readonly kind: 'none' } | { readonly kind: 'unread' };

/** A GET of GitHub's REST API: its status and its JSON, or an error when nothing answered. */
export type GitHubGet = (url: string, token: string) => Promise<{ readonly status: number; readonly body: unknown }>;

const API = 'https://api.github.com';

/** A commit, as git writes it in full. */
const COMMIT = /^[0-9a-f]{40}$/;

/** How many deployments are read, newest first, for one that succeeded: five pages of 30. */
const PAGES = 5;
const PER_PAGE = 30;

/** A deployment's states that say its release succeeded: `success`, and `inactive` once a later one succeeded too. */
const SUCCEEDED: ReadonlySet<string> = new Set(['success', 'inactive']);

/** Why the record couldn't be read, in plain words: what broke and what next. */
const unreadable = (why: string): Error =>
  new Error(
    `GitHub's record of the last release to staging couldn't be read (${why}), so a roll-back past it can't be ruled out (AZ2c), and nothing was changed. The job needs \`deployments: read\` and its GITHUB_TOKEN; run it again, and if it repeats, read the staging environment's deployments on GitHub.`,
  );

const real: GitHubGet = async (url, token) => {
  const answer = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(30_000),
  });
  const body: unknown = answer.ok ? await answer.json() : undefined;
  return { status: answer.status, body };
};

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** A GET of GitHub's API answered 200, its body; an error in plain words for anything else. */
async function readOrRefuse(get: GitHubGet, url: string, token: string): Promise<unknown> {
  let answer: Awaited<ReturnType<GitHubGet>>;
  try {
    answer = await get(url, token);
  } catch (error) {
    if (error instanceof Error) throw unreadable('nothing answered');
    throw error;
  }
  if (answer.status !== 200) throw unreadable(`HTTP ${String(answer.status)}`);
  return answer.body;
}

/** The commit a deployment was made for, if its latest status says it succeeded; nothing otherwise. */
async function succeeded(
  deployment: unknown,
  base: string,
  read: (url: string) => Promise<unknown>,
): Promise<string | undefined> {
  const { id, sha } = isRecord(deployment) ? deployment : {};
  if (typeof id !== 'number' || typeof sha !== 'string' || !COMMIT.test(sha)) {
    throw unreadable('a deployment named no commit');
  }
  const statuses = await read(`${base}/${String(id)}/statuses?per_page=1`);
  const [latest] = Array.isArray(statuses) ? (statuses as unknown[]) : [];
  const state = isRecord(latest) ? latest.state : undefined;
  return typeof state === 'string' && SUCCEEDED.has(state) ? sha : undefined;
}

/**
 * The last release GitHub recorded for staging: the newest deployment to it whose latest status says it succeeded
 * (this run's own, still in progress, never does). Not read outside GitHub Actions; an error in it when it can't be.
 */
export async function lastRelease(
  env: Readonly<Record<string, string | undefined>>,
  get: GitHubGet = real,
): Promise<Anchor> {
  if (env.GITHUB_ACTIONS !== 'true') return { kind: 'unread' };
  const token = env.GITHUB_TOKEN ?? '';
  const repository = env.GITHUB_REPOSITORY ?? '';
  if (token === '' || !/^[\w.-]+\/[\w.-]+$/.test(repository)) throw unreadable('no GITHUB_TOKEN or repository given');
  const base = `${API}/repos/${repository}/deployments`;
  const read = (url: string): Promise<unknown> => readOrRefuse(get, url, token);
  for (let page = 1; page <= PAGES; page += 1) {
    const listed = await read(`${base}?environment=staging&per_page=${String(PER_PAGE)}&page=${String(page)}`);
    if (!Array.isArray(listed)) throw unreadable('its list of deployments was not a list');
    if (listed.length === 0) return page === 1 ? { kind: 'none' } : failedAll();
    for (const deployment of listed as unknown[]) {
      const commit = await succeeded(deployment, base, read);
      if (commit !== undefined) return { kind: 'release', commit };
    }
  }
  return failedAll();
}

/** Deployments on record, and none of those read succeeded: never taken as "none". */
const failedAll = (): never => {
  throw unreadable(`none of its last ${String(PAGES * PER_PAGE)} deployments to staging succeeded`);
};

/** What to do after a roll-back: forward only, past the newest build on record. */
export const forwardPast = (newest: string): string =>
  `If a person rolled it back on purpose, deploy by hand a commit at least as new as ${newest}; otherwise a suspected breach`;

/** The one line said when GitHub's record wasn't held to, or nothing when it was. */
export function anchorSaid(anchor: Anchor): string | undefined {
  if (anchor.kind === 'unread') {
    return "GitHub's record of the last release wasn't read (not a GitHub Actions run): roll-backs are held to Azure's own record alone.";
  }
  if (anchor.kind === 'none') {
    return "GitHub has recorded no release to staging yet: roll-backs are held to Azure's own record alone.";
  }
  return undefined;
}

/**
 * Each workload older than the last release GitHub recorded, as a reason: a roll-back Azure's own record may no
 * longer show. `place` is a build's place on main's line (git.ts mainline), newest 0; a build not on it is said
 * elsewhere. The anchor not on the line is a reason of its own.
 */
export function belowAnchor(
  anchor: Anchor,
  builds: Readonly<Record<string, string>>,
  place: (build: string) => number | undefined,
): string[] {
  if (anchor.kind !== 'release') return [];
  const at = place(anchor.commit);
  if (at === undefined) {
    return [
      `the last release GitHub recorded (${anchor.commit}) isn't on main's line here, so nothing can be held to it: check out main's whole history (fetch-depth 0) and run this again`,
    ];
  }
  return Object.entries(builds)
    .filter(([, build]) => (place(build) ?? -1) > at)
    .map(
      ([workload, build]) =>
        `${workload}: it runs ${build}, older than the last release GitHub recorded (${anchor.commit}): rolled back. ${forwardPast(anchor.commit)}`,
    );
}
