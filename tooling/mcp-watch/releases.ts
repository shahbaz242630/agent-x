// 6E4 (MCP-Guide §7, partner S201): the daily watch on what can break our
// customers' agents before they notice: MCP's specification, the official
// TypeScript SDK our server is built on (its releases and its security
// advisories), the conformance suite, and the main agents' clients that publish
// on GitHub. .github/workflows/mcp-watch.yml runs it every day; it fails red, in
// plain words, on what needs a person. Node builtins only.
//
//   node tooling/mcp-watch/releases.ts                          the watch
//   node tooling/mcp-watch/releases.ts --control-unseen         positive control: as if nothing were seen; red
//   node tooling/mcp-watch/releases.ts --server-version 2.2.0   positive control: judge the SDK's advisories
//                                                               against this version, not our pin; red
//
// What was last seen is tooling/mcp-watch/seen.json, one entry a source, each
// with a note of what the person who moved it checked. A newer release than
// seen is red (for the busiest clients, only when its notes name MCP; for VS
// Code, whose notes are a link, only a new minor) until a person reads it and
// moves seen.json, with a note; every newer release is listed in the job
// summary either way. An SDK advisory that covers the version the API runs is
// red whatever seen.json says, until the pin moves past it. A source that can't
// be read, or whose releases this watch can't read any more, is red too: a
// silent watch proves nothing.
import { readFileSync } from 'node:fs';

import { compareVersions, inRange, parseVersion } from '../image-watch/watch.ts';
import { report } from './canary-judge.ts';

export const SEEN_FILE = 'tooling/mcp-watch/seen.json';
const LOCKFILE = 'pnpm-lock.yaml';

type Version = NonNullable<ReturnType<typeof parseVersion>>;

/** When a newer release turns the watch red. */
type RedWhen =
  /** Any newer release: the specification, the SDK and the conformance suite move rarely, and each matters. */
  | 'every'
  /** A newer release whose notes name MCP: the busy clients ship most days, mostly about other things. */
  | 'mcp-notes'
  /** A newer major or minor release: VS Code's release notes are a link, and its patches fix its own bugs. */
  | 'minor';

/** One thing watched: a repository's releases, which of its tags are the line we follow, and why it matters. */
export interface Source {
  readonly key: string;
  readonly label: string;
  readonly repo: string;
  /** The tags we follow, with the version each names (`version`; `pre` when it is a candidate). */
  readonly tag: RegExp;
  /** Whether a pre-release counts: only the specification's candidates, the earliest word of a revision. */
  readonly prereleases: boolean;
  readonly red: RedWhen;
  /** What the person reading a red line checks. */
  readonly check: string;
}

const SEMVER = String.raw`\d+\.\d+\.\d+`;

export const SOURCES: readonly Source[] = [
  {
    key: 'spec',
    label: 'the MCP specification',
    repo: 'modelcontextprotocol/modelcontextprotocol',
    tag: /^(?<version>\d{4}-\d{2}-\d{2})(?:-(?<pre>RC))?$/,
    prereleases: true,
    red: 'every',
    check:
      'A new revision of MCP itself: read its changelog, check MCP-Guide.md §2 (the versions we serve) and whether ' +
      "the SDK we pin speaks it, and plan the server's move",
  },
  {
    key: 'typescript-sdk',
    label: 'the official TypeScript SDK',
    repo: 'modelcontextprotocol/typescript-sdk',
    tag: new RegExp(`^v(?<version>${SEMVER})$`),
    prereleases: false,
    red: 'every',
    check:
      'The SDK our MCP server is built on (@modelcontextprotocol/server, apps/api/package.json): read its notes, ' +
      'then move the pin by hand (with the client the canaries use), run mcp.test.ts and the conformance suite',
  },
  {
    key: 'conformance',
    label: 'the MCP conformance suite',
    repo: 'modelcontextprotocol/conformance',
    tag: new RegExp(`^v(?<version>${SEMVER})$`),
    prereleases: false,
    red: 'every',
    check: 'New checks may apply to us: move @modelcontextprotocol/conformance and run mcp-conformance.test.ts',
  },
  {
    key: 'claude-code',
    label: 'Claude Code',
    repo: 'anthropics/claude-code',
    tag: new RegExp(`^v(?<version>${SEMVER})$`),
    prereleases: false,
    red: 'mcp-notes',
    check: 'Its notes name MCP: check that nothing changes how it connects, lists or calls (docs/api/README.md §9)',
  },
  {
    key: 'codex',
    label: 'OpenAI Codex',
    repo: 'openai/codex',
    tag: new RegExp(`^rust-v(?<version>${SEMVER})$`),
    prereleases: false,
    red: 'mcp-notes',
    check: 'Its notes name MCP: check that nothing changes how it connects, lists or calls (docs/api/README.md §9)',
  },
  {
    key: 'vscode',
    label: 'VS Code',
    repo: 'microsoft/vscode',
    tag: new RegExp(`^(?<version>${SEMVER})$`),
    prereleases: false,
    red: 'minor',
    check:
      "A new VS Code release: read its release notes' MCP section (code.visualstudio.com/updates) for changes to " +
      'how Copilot connects (docs/api/README.md §9)',
  },
  {
    key: 'gemini-cli',
    label: 'Gemini CLI',
    repo: 'google-gemini/gemini-cli',
    tag: new RegExp(`^v(?<version>${SEMVER})$`),
    prereleases: false,
    red: 'mcp-notes',
    check: 'Its notes name MCP: check that nothing changes how it connects, lists or calls (docs/api/README.md §9)',
  },
  {
    key: 'hermes-agent',
    label: 'Hermes Agent',
    repo: 'NousResearch/hermes-agent',
    // Its 0.x line: the calendar tags (v2026.9.x) are from before it, and would read as newer.
    tag: /^v(?<version>(?:0|[1-9]\d{0,2})\.\d+\.\d+)$/,
    prereleases: false,
    red: 'mcp-notes',
    check: "Its notes name MCP: check MCP-Guide.md §8's Hermes column still holds (legacy initialize, its auth)",
  },
  {
    key: 'openclaw',
    label: 'OpenClaw',
    repo: 'openclaw/openclaw',
    tag: /^v(?<version>\d{4}\.\d+\.\d+)$/,
    prereleases: false,
    red: 'mcp-notes',
    check: "Its notes name MCP: check MCP-Guide.md §8's OpenClaw column still holds (its transport, legacy initialize)",
  },
];

/** The SDK packages the API runs (the server and its core, apps/api's production dependencies): an advisory is red. */
export const PRODUCTION_PACKAGES = ['@modelcontextprotocol/server', '@modelcontextprotocol/core'] as const;
const SDK_REPO = 'modelcontextprotocol/typescript-sdk';

/** A tag's version on a source's line, or undefined when the tag is not on it. */
export function versionOf(source: Source, tag: string): Version | undefined {
  const groups = source.tag.exec(tag)?.groups;
  if (groups?.version === undefined) return undefined;
  // A dated revision (2026-07-28) compares as 2026.7.28; its candidate (-RC) comes before it.
  const dotted = groups.version.replaceAll(/-0?(\d)/g, '.$1');
  return parseVersion(groups.pre === undefined ? dotted : `${dotted}-${groups.pre.toLowerCase()}`);
}

// --- seen.json --------------------------------------------------------------

/** One source's last-seen release, and what the person who moved it checked. */
export interface Seen {
  readonly version: string;
  readonly note: string;
}

/** The seen file read: each source's entry, and what is wrong with it, in plain words. */
export function parseSeen(data: unknown): { readonly seen: ReadonlyMap<string, Seen>; readonly errors: string[] } {
  const entries = (data as { seen?: unknown } | null)?.seen;
  const seen = new Map<string, Seen>();
  if (typeof entries !== 'object' || entries === null || Array.isArray(entries)) {
    return { seen, errors: [`${SEEN_FILE} has no "seen" map, so nothing can be judged new. Put it back.`] };
  }
  const errors: string[] = [];
  for (const source of SOURCES) {
    const entry = (entries as Record<string, unknown>)[source.key] as Partial<Seen> | undefined;
    const usable =
      typeof entry?.version === 'string' &&
      versionOf(source, entry.version) !== undefined &&
      typeof entry.note === 'string' &&
      entry.note.trim() !== '';
    if (usable) {
      seen.set(source.key, { version: entry.version, note: entry.note });
    } else {
      errors.push(
        `${SEEN_FILE} has no usable "${source.key}" entry (a release tag of ${source.repo} on the line this watch ` +
          `follows, and a note), so ${source.label} went unchecked today. Correct it.`,
      );
    }
  }
  const unknown = Object.keys(entries).filter((key) => !SOURCES.some((source) => source.key === key));
  if (unknown.length > 0) {
    errors.push(`${SEEN_FILE} names ${unknown.join(', ')}, which this watch doesn't follow. Remove them.`);
  }
  return { seen, errors };
}

// --- Releases ---------------------------------------------------------------

/** A GitHub release, as its API gives it: the fields read here. */
export interface Release {
  readonly tag_name?: string;
  readonly prerelease?: boolean;
  readonly draft?: boolean;
  readonly html_url?: string;
  readonly published_at?: string;
  readonly body?: string | null;
}

/** Outside text in a Markdown table cell: one line, no table or HTML breaking out. */
const cell = (text: string): string =>
  text
    .replaceAll(/[\r\n]+/g, ' ')
    .replaceAll('|', '\\|')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');

/** How many of a release's lines naming MCP the summary shows, and how long each may be. */
const MCP_LINES = 3;
const MCP_LINE_CHARACTERS = 160;
const MCP_WORD = /\bMCP\b/i;

/** The lines of a release's notes that name MCP, cut short, for the summary. */
export function mcpLines(body: string | null | undefined): string[] {
  return (body ?? '')
    .split(/\r?\n/)
    .filter((line) => MCP_WORD.test(line))
    .slice(0, MCP_LINES)
    .map((line) => {
      const trimmed = line.replace(/^[\s*#-]+/, '').trim();
      return trimmed.length > MCP_LINE_CHARACTERS ? `${trimmed.slice(0, MCP_LINE_CHARACTERS)}…` : trimmed;
    });
}

const minorMoved = (a: Version, b: Version): boolean => a.numbers[0] !== b.numbers[0] || a.numbers[1] !== b.numbers[1];

/** The positive control's floor: every real release is newer than it. */
const NOTHING_SEEN = parseVersion('0.0.0');

/**
 * One source's releases against what was seen: red, in plain words, when a person must read something new. The
 * positive control (`unseen`) judges against nothing seen, so every release on the line is newer.
 */
export function judgeSource(
  source: Source,
  seen: Seen,
  releases: readonly Release[],
  unseen = false,
): { errors: string[]; summary: string } {
  const seenVersion = unseen ? NOTHING_SEEN : versionOf(source, seen.version);
  const onLine = releases.flatMap((release) => {
    const version = versionOf(source, release.tag_name ?? '');
    const counted = release.draft !== true && (source.prereleases || release.prerelease !== true);
    return version !== undefined && counted ? [{ release, version }] : [];
  });
  const seenLine = unseen
    ? 'Positive control: judged as if nothing were seen.'
    : `Seen: ${cell(seen.version)} (${cell(seen.note)}).`;
  const heading = `### ${source.label} (${source.repo})\n\n${seenLine}\n`;
  if (seenVersion === undefined || onLine.length === 0) {
    return {
      errors: [
        `None of ${source.repo}'s latest releases is on the line this watch follows, so ${source.label} went ` +
          `unchecked today: it may have changed how it tags releases. Look at its releases, then correct this ` +
          `watch's pattern for it (tooling/mcp-watch/releases.ts).`,
      ],
      summary: `${heading}\nNo release on the followed line.\n`,
    };
  }
  const newer = onLine
    .filter(({ version }) => compareVersions(version, seenVersion) > 0)
    .sort((a, b) => compareVersions(b.version, a.version));
  const newest = newer[0];
  if (newest === undefined) return { errors: [], summary: `${heading}\nNothing newer.\n` };
  const reds = newer.filter(({ release, version }) => {
    if (source.red === 'every') return true;
    if (source.red === 'minor') return minorMoved(version, seenVersion);
    return mcpLines(release.body).length > 0;
  });
  const rows = newer.map(({ release }) => {
    const lines = mcpLines(release.body).map(cell).join('<br>');
    return (
      `| ${reds.some((red) => red.release === release) ? 'red' : 'report only'} | ` +
      `[${cell(release.tag_name ?? '')}](${release.html_url ?? ''}) | ${cell(release.published_at ?? '')} | ` +
      `${lines === '' ? '-' : lines} |`
    );
  });
  const table = `\n| Verdict | Release | Published | Notes naming MCP |\n| --- | --- | --- | --- |\n${rows.join('\n')}\n`;
  const since = unseen ? 'nothing seen (the positive control)' : `the ${seen.version} last seen`;
  const errors =
    reds.length === 0
      ? []
      : [
          `${source.label} has ${String(newer.length)} newer ${newer.length === 1 ? 'release' : 'releases'} than ` +
            `${since}, up to ${newest.release.tag_name ?? '?'} ` +
            `(${newest.release.html_url ?? source.repo}). ${source.check}. Then move "${source.key}" in ` +
            `${SEEN_FILE} to ${newest.release.tag_name ?? 'it'}, with a note of what you checked. The list is in ` +
            `this run's summary.`,
        ];
  return { errors, summary: heading + table };
}

// --- The SDK's security advisories -------------------------------------------

/** A repository security advisory, as GitHub's API gives it: the fields read here. */
export interface Advisory {
  readonly ghsa_id?: string;
  readonly summary?: string;
  readonly severity?: string | null;
  readonly html_url?: string;
  readonly withdrawn_at?: string | null;
  readonly vulnerabilities?:
    | {
        readonly package?: { readonly name?: string | null } | null;
        readonly vulnerable_version_range?: string | null;
        readonly patched_versions?: string | null;
      }[]
    | null;
}

/** Where an advisory says its fix is, for its red line. */
const fixedIn = (patched: string): string =>
  patched === '' ? 'none yet: read the advisory for a workaround' : patched + ' or later';

/** The versions the API runs, by package, read from the lockfile (every version of each, should two be locked). */
export function installedVersions(lockfile: string): ReadonlyMap<string, readonly string[]> {
  const found = new Map<string, string[]>();
  for (const name of PRODUCTION_PACKAGES) {
    const escaped = name.replaceAll('/', '\\/');
    const versions = [...lockfile.matchAll(new RegExp(`^ {2}'${escaped}@([^'(]+)'`, 'gm'))].map(
      (match) => match[1] ?? '',
    );
    found.set(name, [...new Set(versions)]);
  }
  return found;
}

/**
 * The SDK's advisories against the versions the API runs: red on any that covers one (any severity: this is the
 * door every agent's client comes through), or that can't be read; withdrawn ones are left out.
 */
export function judgeSdkAdvisories(
  advisories: readonly Advisory[],
  installed: ReadonlyMap<string, readonly string[]>,
  control: boolean,
): { errors: string[]; summary: string } {
  const pins = [...installed.entries()].flatMap(([name, versions]) => versions.map((version) => ({ name, version })));
  if (pins.length < PRODUCTION_PACKAGES.length) {
    return {
      errors: [
        `The lockfile names no version of ${PRODUCTION_PACKAGES.join(' or ')}, so the SDK's advisories went ` +
          `unchecked today. Check apps/api/package.json and ${LOCKFILE}, then this watch's reading of them.`,
      ],
      summary: "## The SDK's advisories\n\nNot checked: no pinned version found.\n",
    };
  }
  const rows = advisories
    .filter((advisory) => advisory.withdrawn_at === null || advisory.withdrawn_at === undefined)
    .flatMap((advisory) =>
      (advisory.vulnerabilities ?? []).flatMap((vulnerability) =>
        pins
          .filter(({ name }) => vulnerability.package?.name === name)
          .flatMap(({ name, version }) => {
            const parsed = parseVersion(version);
            const range = vulnerability.vulnerable_version_range ?? '';
            const hit = parsed === undefined ? undefined : inRange(range, parsed);
            return hit === false
              ? []
              : [
                  {
                    advisory,
                    name,
                    version,
                    range,
                    unread: hit === undefined,
                    patched: vulnerability.patched_versions ?? '',
                  },
                ];
          }),
      ),
    );
  const errors = rows.map(({ advisory, name, version, range, unread, patched }) => {
    const id = advisory.ghsa_id ?? 'an advisory';
    const subject = control
      ? `Positive control: ${name} ${version} (not what the API runs)`
      : `${name} ${version}, which the API's MCP server runs,`;
    return unread
      ? `The SDK's advisory ${id} (${advisory.summary ?? 'no title'}) gives an affected range this watch can't ` +
          `read for ${name} ("${range}"), so it can't tell whether ${version} is affected. Read it ` +
          `(${advisory.html_url ?? id}); if it applies, move the pin, and teach tooling/image-watch/watch.ts the form.`
      : `${subject} is covered by the SDK's ${advisory.severity ?? 'unrated'}-severity advisory ${id} ` +
          `(${advisory.summary ?? 'no title'}). Every agent's MCP call goes through it. Move ${name} to a fixed ` +
          `version (${fixedIn(patched)}) in ` +
          `apps/api/package.json, run mcp.test.ts and the conformance suite, and release. ${advisory.html_url ?? ''}`.trimEnd();
  });
  const pinned = pins.map(({ name, version }) => `${name} ${version}`).join(', ');
  const table = rows.map(
    ({ advisory, name, range, patched }) =>
      `| red | ${cell(advisory.ghsa_id ?? '?')} | ${cell(name)} | ${cell(range)} | ${patched === '' ? 'no fix yet' : cell(patched)} |`,
  );
  const summary =
    `## The SDK's advisories\n\n${control ? 'Positive control: ' : ''}${pinned} against ` +
    `${String(advisories.length)} published advisories: ${String(rows.length)} apply.\n` +
    (rows.length === 0
      ? ''
      : `\n| Verdict | Advisory | Package | Affected | Fixed in |\n| --- | --- | --- | --- | --- |\n${table.join('\n')}\n`);
  return { errors, summary };
}

// --- Reading GitHub, and the command line -------------------------------------

/** How the watch reads GitHub: real by default, a stand-in in tests. */
export type Fetch = (url: string, init: { headers: Record<string, string>; signal: AbortSignal }) => Promise<Response>;

/** One GitHub API list, or why it couldn't be read. */
async function githubList(path: string, token: string, fetcher: Fetch): Promise<unknown[] | { problem: string }> {
  try {
    const answer = await fetcher(`https://api.github.com/${path}`, {
      headers: {
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        ...(token === '' ? {} : { authorization: `Bearer ${token}` }),
      },
      signal: AbortSignal.timeout(30_000),
    });
    if (!answer.ok) return { problem: `GitHub answered ${String(answer.status)}` };
    const data: unknown = await answer.json();
    return Array.isArray(data) ? data : { problem: 'GitHub answered with no list' };
  } catch (error) {
    return { problem: error instanceof Error ? error.message : 'no answer' };
  }
}

const unread = (what: string, problem: string): string =>
  `${what} could not be read today (${problem}), so it went unchecked. Look at this step's log (GitHub's API may be ` +
  `down), then re-run this workflow.`;

/** The whole watch: every source against seen.json, and the SDK's advisories against our pin. */
export async function watch(options: {
  readonly read: (file: string) => string;
  readonly fetcher: Fetch;
  readonly token: string;
  /** Positive control: judge as if nothing were seen, so every source with a release goes red. */
  readonly unseen?: boolean;
  /** Positive control: judge the advisories against this SDK version, not the lockfile's. */
  readonly serverVersion?: string | undefined;
}): Promise<{ errors: string[]; summary: string }> {
  const { seen, errors } = parseSeen(JSON.parse(options.read(SEEN_FILE)));
  const parts: string[] = ['## MCP releases (since seen.json)\n'];
  for (const source of SOURCES) {
    const last = seen.get(source.key);
    if (last === undefined) continue;
    const releases = await githubList(`repos/${source.repo}/releases?per_page=50`, options.token, options.fetcher);
    if (!Array.isArray(releases)) {
      errors.push(unread(`${source.label}'s releases (${source.repo})`, releases.problem));
      continue;
    }
    const verdict = judgeSource(source, last, releases as Release[], options.unseen === true);
    errors.push(...verdict.errors);
    parts.push(verdict.summary);
  }
  const advisories = await githubList(
    `repos/${SDK_REPO}/security-advisories?state=published&per_page=100`,
    options.token,
    options.fetcher,
  );
  if (Array.isArray(advisories)) {
    const control = options.serverVersion !== undefined && options.serverVersion !== '';
    const installed = control
      ? new Map(PRODUCTION_PACKAGES.map((name) => [name, [options.serverVersion ?? '']]))
      : installedVersions(options.read(LOCKFILE));
    const verdict = judgeSdkAdvisories(advisories as Advisory[], installed, control);
    errors.push(...verdict.errors);
    parts.push(verdict.summary);
  } else {
    errors.push(unread("The TypeScript SDK's security advisories", advisories.problem));
  }
  return { errors, summary: parts.join('\n') };
}

export async function main(args: readonly string[], env: NodeJS.ProcessEnv, fetcher: Fetch = fetch): Promise<number> {
  const at = args.indexOf('--server-version');
  const verdict = await watch({
    read: (file) => readFileSync(file, 'utf8'),
    fetcher,
    token: env.GH_TOKEN ?? '',
    unseen: args.includes('--control-unseen'),
    serverVersion: at === -1 ? undefined : (args[at + 1] ?? '').replace(/^v/, ''),
  });
  return report(verdict, 'Nothing new needs a person today.');
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2), process.env);
