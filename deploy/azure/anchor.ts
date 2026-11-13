// The last release GitHub recorded for staging (AZ2c), an anchor outside Azure.
// CI's write to the API could lower how many revisions Azure keeps, roll the API
// back, and restore the setting: Azure's own record of what ran is then purged.
// GitHub records a deployment for every job that uses the `staging` environment
// (the release job does), and a stolen Azure sign-in can't write that record. So
// in CI the release and the job-start watch read the deployments to staging
// that succeeded, take the newest of their commits on main's line, and hold
// both workloads to be at least that new. A hand `apps` deploy isn't a GitHub
// deployment; a newer one is fine. Outside GitHub Actions there is no token: said in one line, not red. In
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
    `GitHub's record of the last release to staging couldn't be read (${why}), so a roll-back past it can't be ruled out (AZ2c), and nothing was changed. The job needs \`deployments: read\` and its token in AGENTX_DEPLOYMENTS_TOKEN; run it again, and if it repeats, read the staging environment's deployments on GitHub.`,
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

/** A deployment as listed: its id and commit, or an error when it names no commit. */
function deploymentOf(deployment: unknown): { readonly id: number; readonly sha: string } {
  const { id, sha } = isRecord(deployment) ? deployment : {};
  if (typeof id !== 'number' || typeof sha !== 'string' || !COMMIT.test(sha)) {
    throw unreadable('a deployment named no commit');
  }
  return { id, sha };
}

/** Whether a deployment's latest status says it succeeded. */
async function succeeded(id: number, base: string, read: (url: string) => Promise<unknown>): Promise<boolean> {
  const statuses = await read(`${base}/${String(id)}/statuses?per_page=1`);
  const [latest] = Array.isArray(statuses) ? (statuses as unknown[]) : [];
  const state = isRecord(latest) ? latest.state : undefined;
  return typeof state === 'string' && SUCCEEDED.has(state);
}

/** The token the release and the watch are given to read deployments with: not GITHUB_TOKEN, which cosign and az would pick up. */
export const TOKEN_VARIABLE = 'AGENTX_DEPLOYMENTS_TOKEN';

/**
 * The commits of the deployments to staging that succeeded and could be the anchor, reading every page to the end of
 * the listing or the cap (each deployment's latest status: this run's own, still in progress, never succeeded). A
 * status is read only for a commit newer on main's line than the newest success found so far, or one off the line:
 * no other could be the anchor, and one status call each was most of the cost (155 calls on staging, S188). `ended`
 * is false only when the cap was reached first.
 */
async function successes(
  read: (url: string) => Promise<unknown>,
  base: string,
  place: (commit: string) => number | undefined,
): Promise<{ commits: string[]; ended: boolean }> {
  const commits: string[] = [];
  let best: number | undefined;
  for (let page = 1; page <= PAGES; page += 1) {
    const listed = await read(`${base}?environment=staging&per_page=${String(PER_PAGE)}&page=${String(page)}`);
    if (!Array.isArray(listed)) throw unreadable('its list of deployments was not a list');
    for (const { id, sha } of (listed as unknown[]).map(deploymentOf)) {
      const at = place(sha);
      const couldBeNewer = at === undefined || best === undefined || at < best;
      if (couldBeNewer && (await succeeded(id, base, read))) {
        commits.push(sha);
        if (at !== undefined) best = at;
      }
    }
    if (listed.length < PER_PAGE) return { commits, ended: true };
  }
  return { commits, ended: false };
}

/**
 * The last release GitHub recorded for staging: of the deployments to it that succeeded, the one whose commit is
 * newest on main's line (`place`, git.ts mainline: newest 0), never merely the newest created, since a re-run of an
 * old release job records a new deployment of an old commit. A success whose commit isn't on main's line is the
 * anchor itself, which then holds nothing and is red (anchor.ts belowAnchor). None when the listing ends without a
 * success (a fresh environment: this run's own is in progress; or only failures, hand `apps` deploys recording
 * none); an error when the cap is reached without one, or in reading. Not read outside GitHub Actions.
 */
export async function lastRelease(
  env: Readonly<Record<string, string | undefined>>,
  place: (commit: string) => number | undefined,
  get: GitHubGet = real,
): Promise<Anchor> {
  if (env.GITHUB_ACTIONS !== 'true') return { kind: 'unread' };
  const token = env[TOKEN_VARIABLE] ?? '';
  const repository = env.GITHUB_REPOSITORY ?? '';
  if (token === '' || !/^[\w.-]+\/[\w.-]+$/.test(repository)) {
    throw unreadable(`no ${TOKEN_VARIABLE} or repository given`);
  }
  const base = `${API}/repos/${repository}/deployments`;
  const { commits, ended } = await successes((url) => readOrRefuse(get, url, token), base, place);
  if (commits.length === 0) {
    if (ended) return { kind: 'none' };
    throw unreadable(`none of its last ${String(PAGES * PER_PAGE)} deployments to staging succeeded`);
  }
  const offLine = commits.find((commit) => place(commit) === undefined);
  if (offLine !== undefined) return { kind: 'release', commit: offLine };
  const [first = ''] = commits;
  const newest = commits.reduce((best, each) => ((place(each) ?? 0) < (place(best) ?? 0) ? each : best), first);
  return { kind: 'release', commit: newest };
}

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
      `the last release GitHub recorded (${anchor.commit}) isn't on main's line: if this checkout is shallow, check out main's whole history (fetch-depth 0) and run again; if main's history was rewritten, or a deployment record was made by hand, that GitHub deployment must be deleted (Incident-Response-Playbook section V), a suspected breach until explained`,
    ];
  }
  return Object.entries(builds)
    .filter(([, build]) => (place(build) ?? -1) > at)
    .map(
      ([workload, build]) =>
        `${workload}: it runs ${build}, older than the last release GitHub recorded (${anchor.commit}): rolled back. ${forwardPast(anchor.commit)}`,
    );
}
