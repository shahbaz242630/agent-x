// DT5 (partner S201): a daily watch for security notices on the third-party
// images we run. In S190 six Zitadel account-takeover advisories were seen
// only at a manual weekly read; .github/workflows/image-watch.yml runs this
// every day, and it fails red, in plain words, on what needs a person.
// Node builtins only: the workflow runs it on CI's bare Node.
//
//   node tooling/image-watch/watch.ts images                prints the images to scan, as a job matrix
//   node tooling/image-watch/watch.ts accepted              checks the accepted findings (accepted.json)
//   node tooling/image-watch/watch.ts grype FILE KEY        judges Grype's JSON report on one of them
//   node tooling/image-watch/watch.ts advisories FILE [V]   judges Zitadel's advisories against its pinned
//                                                           version, or V (the positive control)
//
// The images are read where they are pinned, never copied: Zitadel and its
// login pages from staging's parameters (what staging runs;
// tooling/checks/images.test.ts keeps the compose stack's equal), Postgres
// and nginx from the compose stack (staging runs Azure's managed Postgres and
// no nginx). Red is a high or critical finding with a fix to move to (for
// Grype's, unless accepted.json accepts it until a review date); the rest goes
// to the job summary only, as the weekly image scan reports Debian's unfixed
// highs without blocking anything.
import { appendFileSync, readFileSync } from 'node:fs';

const STAGING_PARAMETERS = 'deploy/azure/staging.apps.bicepparam';
const COMPOSE_FILE = 'deploy/compose/compose.yaml';

/** `name:tag@sha256:<64 hex>`: only a pinned reference is scanned. */
const PINNED = /^(?<name>[a-z0-9][a-z0-9._/-]*):(?<tag>[A-Za-z0-9][A-Za-z0-9._-]*)@sha256:[0-9a-f]{64}$/;

/** One image the watch scans: where it runs, and what a finding in it puts at risk. */
export interface WatchedImage {
  key: string;
  label: string;
  image: string;
  runs: string;
  risk: string;
}

interface ImageSource {
  key: string;
  label: string;
  file: string;
  /** The parameter (staging's file) or the service (the compose file) that pins it. */
  read: { parameter: string } | { service: string };
  name: string;
  runs: string;
  risk: string;
}

const SOURCES: readonly ImageSource[] = [
  {
    key: 'zitadel',
    label: 'Zitadel',
    file: STAGING_PARAMETERS,
    read: { parameter: 'zitadelImage' },
    name: 'ghcr.io/zitadel/zitadel',
    runs: 'staging and the local stack run',
    risk: 'Sign-in may be at risk.',
  },
  {
    key: 'zitadel-login',
    label: "Zitadel's login pages",
    file: STAGING_PARAMETERS,
    read: { parameter: 'zitadelLoginImage' },
    name: 'ghcr.io/zitadel/zitadel-login',
    runs: 'staging and the local stack run',
    risk: 'Sign-in may be at risk.',
  },
  {
    key: 'postgres',
    label: 'Postgres',
    file: COMPOSE_FILE,
    read: { service: 'db' },
    name: 'postgres',
    runs: "the local stack and the database tests run (staging uses Azure's managed Postgres)",
    risk: "The local stack's database may be at risk.",
  },
  {
    key: 'nginx',
    label: 'nginx',
    file: COMPOSE_FILE,
    read: { service: 'edge' },
    name: 'nginx',
    runs: "the local stack runs as its front door (staging uses Azure's own)",
    risk: "The local stack's front door may be at risk.",
  },
];

/** A bicepparam's `param NAME = '...'` string, or undefined. */
export function parameterValue(text: string, parameter: string): string | undefined {
  return new RegExp(`^param ${parameter} = '([^']+)'\\s*$`, 'm').exec(text)?.[1];
}

/** A compose service's `image:`, read from its block (two-space services, four-space keys). */
export function serviceImage(text: string, service: string): string | undefined {
  const lines = text.replaceAll('\r\n', '\n').split('\n');
  const start = lines.indexOf(`  ${service}:`);
  if (start === -1) return undefined;
  for (const line of lines.slice(start + 1)) {
    if (/^ {0,2}\S/.test(line)) return undefined;
    const image = /^ {4}image:\s*(\S+)\s*$/.exec(line)?.[1];
    if (image !== undefined) return image;
  }
  return undefined;
}

/** The images to scan, read from the files that pin them; throws, in plain words, when one can't be read. */
export function watchedImages(read: (file: string) => string): WatchedImage[] {
  return SOURCES.map((source) => {
    const text = read(source.file);
    const image =
      'parameter' in source.read
        ? parameterValue(text, source.read.parameter)
        : serviceImage(text, source.read.service);
    const where = 'parameter' in source.read ? `parameter ${source.read.parameter}` : `service ${source.read.service}`;
    const name = image === undefined ? undefined : PINNED.exec(image)?.groups?.name;
    if (name !== source.name) {
      throw new Error(
        `${source.file} (${where}) no longer pins ${source.name} as name:tag@sha256:<digest>, so the daily watch ` +
          `can't tell which ${source.label} image to scan. Pin it again, or move this watch's reading ` +
          `(tooling/image-watch/watch.ts) to where it is pinned now.`,
      );
    }
    return { key: source.key, label: source.label, image: image ?? '', runs: source.runs, risk: source.risk };
  });
}

/** The pinned Zitadel version (from its image tag), without the leading v. */
export function zitadelVersion(images: readonly WatchedImage[]): string {
  const zitadel = images.find((each) => each.key === 'zitadel');
  return PINNED.exec(zitadel?.image ?? '')?.groups?.tag?.replace(/^v/, '') ?? '';
}

// --- Annotations and the job summary -------------------------------------

/** A workflow command's text, escaped so outside text can't end the line or start another command. */
export const escapeCommand = (text: string): string =>
  text.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');

/** A Markdown table cell from outside text. */
const cell = (text: string): string => text.replaceAll('|', '\\|').replaceAll(/[\r\n]+/g, ' ');

/** What a check found: the red lines (one ::error:: each) and the job summary's Markdown. */
export interface Verdict {
  errors: string[];
  summary: string;
}

const BLOCKING = new Set(['critical', 'high']);
/** How many red findings an image's one error line names. */
const NAMED_FINDINGS = 5;

// --- Accepted findings (tooling/image-watch/accepted.json) ------------------
//
// A vendor can take weeks to ship an image carrying an upstream fix, and a
// watch left red for weeks gets ignored (lead, S201). So a high or critical
// finding with a fix may be accepted, by image, finding and package, with a
// plain reason and a date (at most MOST_REVIEW_DAYS ahead) by which a person
// looks again. Zitadel's own advisories are never accepted here.

export const ACCEPTED_FILE = 'tooling/image-watch/accepted.json';
/** How far ahead an acceptance's review date may be. */
export const MOST_REVIEW_DAYS = 30;
const DAY_MS = 86_400_000;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

/** One accepted finding. */
export interface Accepted {
  image: string;
  id: string;
  package: string;
  reason: string;
  reviewBy: string;
}

const today = (now: Date): string => now.toISOString().slice(0, 10);
const expired = (entry: Accepted, now: Date): boolean => entry.reviewBy < today(now);
const findingKey = (id: string, name: string): string => `${id}\u0000${name}`;

/** Why one entry is not acceptable, or undefined when it is. */
function entryProblem(entry: unknown, keys: readonly string[], now: Date): string | undefined {
  if (typeof entry !== 'object' || entry === null) return 'is not an object';
  const fields = entry as Record<string, unknown>;
  const missing = ['image', 'id', 'package', 'reason', 'reviewBy'].filter((field) => {
    const value = fields[field];
    return typeof value !== 'string' || value.trim() === '';
  });
  if (missing.length > 0) return `has no ${missing.join(', ')}`;
  const { image, reviewBy } = entry as Accepted;
  if (!keys.includes(image)) return `names ${image}, which is not one of the watched images (${keys.join(', ')})`;
  if (!DATE.test(reviewBy) || Number.isNaN(Date.parse(`${reviewBy}T00:00:00Z`))) {
    return `has the review date ${reviewBy}, which is not a date (YYYY-MM-DD)`;
  }
  const latest = today(new Date(now.getTime() + MOST_REVIEW_DAYS * DAY_MS));
  if (reviewBy > latest) return `has the review date ${reviewBy}, more than ${String(MOST_REVIEW_DAYS)} days ahead`;
  return undefined;
}

/** The accepted file read: its usable entries, and what is wrong with it, in plain words. */
export function parseAccepted(data: unknown, keys: readonly string[], now: Date): Verdict & { entries: Accepted[] } {
  const list = (data as { accepted?: unknown } | null)?.accepted;
  if (!Array.isArray(list)) {
    const error =
      `${ACCEPTED_FILE} has no "accepted" list, so no finding can be accepted and every high or critical one with ` +
      `a fix is red. Put the list back (it may be empty).`;
    return { entries: [], errors: [error], summary: `## Accepted findings\n\nNot readable.\n` };
  }
  const entries: Accepted[] = [];
  const errors: string[] = [];
  list.forEach((entry: unknown, index) => {
    const problem = entryProblem(entry, keys, now);
    if (problem !== undefined) {
      errors.push(
        `Entry ${String(index + 1)} of ${ACCEPTED_FILE} ${problem}, so it accepts nothing and its finding stays red. ` +
          `Correct it: an image key, the finding's ID, its package, a plain reason, and a review date at most ` +
          `${String(MOST_REVIEW_DAYS)} days ahead.`,
      );
      return;
    }
    const accepted = entry as Accepted;
    entries.push(accepted);
    if (expired(accepted, now)) {
      errors.push(
        `The accepted finding ${accepted.id} (${accepted.package}) on ${accepted.image} passed its review date ` +
          `${accepted.reviewBy}, so it is red again. Check whether the vendor shipped a fixed image, then move the ` +
          `pin, or renew the entry in ${ACCEPTED_FILE} with a reason and a new date.`,
      );
    }
  });
  const summary =
    `## Accepted findings\n\n${String(entries.length)} accepted, ${String(errors.length)} needing a person ` +
    `(${ACCEPTED_FILE}).\n`;
  return { entries, errors, summary };
}

// --- Grype -----------------------------------------------------------------

export interface GrypeMatch {
  vulnerability?: { id?: string; severity?: string; fix?: { versions?: string[]; state?: string } };
  artifact?: { name?: string; version?: string; type?: string };
}

export interface GrypeReport {
  matches?: GrypeMatch[];
  source?: { type?: string; target?: { userInput?: string } };
  descriptor?: { name?: string };
}

/**
 * Zitadel's own Go module in its server image (lead, S201): Grype reads the
 * binary's module as a pseudo-version (v1.80.0-v2.20.0-...), so it matches
 * advisories Zitadel fixed long ago and never clears. Zitadel's real version is
 * judged against its advisories by the advisory job, so these findings are
 * listed, not judged: in that image and that package only.
 */
const OWN_MODULE = { image: 'zitadel', package: 'github.com/zitadel/zitadel' } as const;
const COVERED = 'covered by the advisory check';

const verdictOf = (serious: boolean, acceptedUntil: string | undefined): string => {
  if (!serious) return 'report only';
  return acceptedUntil === undefined ? 'red' : `accepted until ${acceptedUntil}`;
};

/**
 * Grype's report on one image, judged: red on a high or critical finding with
 * a fix that no in-date accepted entry covers. Accepted entries that match no
 * finding any more are listed as stale, so the file shrinks.
 */
export function judgeGrype(
  report: GrypeReport,
  image: WatchedImage,
  accepted: readonly Accepted[] = [],
  now: Date = new Date(),
): Verdict {
  if (report.descriptor?.name !== 'grype' || report.source?.target?.userInput !== image.image) {
    return {
      errors: [
        `The scan report for ${image.label} is not Grype's report on ${image.image}, so this image went unchecked ` +
          `today. Look at the scan step's log, then re-run this workflow.`,
      ],
      summary: `## ${image.label}\n\nNo usable scan report.\n`,
    };
  }
  const mine = accepted.filter((entry) => entry.image === image.key);
  const covering = new Map(
    mine.filter((entry) => !expired(entry, now)).map((entry) => [findingKey(entry.id, entry.package), entry]),
  );
  const rows = (report.matches ?? []).map((match) => {
    const severity = (match.vulnerability?.severity ?? 'Unknown').toLowerCase();
    const fixes = match.vulnerability?.fix?.state === 'fixed' ? (match.vulnerability.fix.versions ?? []) : [];
    const id = match.vulnerability?.id ?? 'an unnamed finding';
    const name = match.artifact?.name ?? '?';
    const serious = BLOCKING.has(severity) && fixes.length > 0;
    const acceptedUntil = serious ? covering.get(findingKey(id, name))?.reviewBy : undefined;
    const ownModule = image.key === OWN_MODULE.image && name === OWN_MODULE.package;
    return {
      key: findingKey(id, name),
      id,
      severity,
      what: `${name} ${match.artifact?.version ?? '?'}`,
      fixes,
      verdict: ownModule ? COVERED : verdictOf(serious, acceptedUntil),
    };
  });
  // One line an image (GitHub shows only ten annotations a step); the full list is in the summary.
  const blocking = rows.filter((row) => row.verdict === 'red');
  const named = blocking
    .slice(0, NAMED_FINDINGS)
    .map((row) => `${row.id} (${row.severity}) in ${row.what}, fixed in ${row.fixes.join(', ')}`);
  const more = blocking.length > NAMED_FINDINGS ? `; and ${String(blocking.length - NAMED_FINDINGS)} more` : '';
  const errors =
    blocking.length === 0
      ? []
      : [
          `${image.label} (${image.image}), which ${image.runs}, has ${String(blocking.length)} high or critical ` +
            `known ${blocking.length === 1 ? 'vulnerability' : 'vulnerabilities'} with a fix available that ` +
            `${ACCEPTED_FILE} does not accept: ${named.join('; ')}${more}. ${image.risk} Move the image to a ` +
            `release that carries the fixes (Dependabot's weekly bump, or by hand per ADR-003), then run the hand ` +
            `deploy where staging runs it; or, when no vendor image has the fix yet, accept it there with a ` +
            `reason and a review date. The full list is in this run's summary.`,
        ];
  const table = rows.map(
    (row) =>
      `| ${row.verdict} | ${cell(row.severity)} | ${cell(row.id)} | ${cell(row.what)} | ` +
      `${row.fixes.length > 0 ? cell(row.fixes.join(', ')) : 'no fix yet'} |`,
  );
  const found = new Set(rows.map((row) => row.key));
  const stale = mine
    .filter((entry) => !found.has(findingKey(entry.id, entry.package)))
    .map((entry) => `- ${cell(entry.id)} in ${cell(entry.package)}`);
  const acceptedCount = rows.filter((row) => row.verdict.startsWith('accepted')).length;
  const coveredCount = rows.filter((row) => row.verdict === COVERED).length;
  const head =
    `## ${image.label}\n\n\`${image.image}\`: ${String(blocking.length)} red, ${String(acceptedCount)} accepted, ` +
    `${String(coveredCount)} covered by the advisory check, ` +
    `${String(rows.length - blocking.length - acceptedCount - coveredCount)} report only.\n`;
  const body =
    rows.length === 0
      ? '\nNo known vulnerabilities.\n'
      : `\n| Verdict | Severity | Finding | Package | Fixed in |\n| --- | --- | --- | --- | --- |\n${table.join('\n')}\n`;
  const staleText =
    stale.length === 0
      ? ''
      : `\nStale: these accepted entries match no finding any more; remove them from ${ACCEPTED_FILE}:\n\n` +
        `${stale.join('\n')}\n`;
  return { errors, summary: head + body + staleText };
}

// --- Zitadel's advisories ---------------------------------------------------

interface Version {
  numbers: [number, number, number];
  pre: string[];
}

/** A semantic version, a leading v allowed; undefined when the text is not one. */
export function parseVersion(text: string): Version | undefined {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(text.trim());
  if (match === null) return undefined;
  return {
    numbers: [Number(match[1]), Number(match[2]), Number(match[3])],
    pre: match[4] === undefined ? [] : match[4].split('.'),
  };
}

function comparePre(a: readonly string[], b: readonly string[]): number {
  // A release is after its pre-releases.
  if (a.length === 0 || b.length === 0) return b.length - a.length;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const [x, y] = [a[index], b[index]];
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    if (x === y) continue;
    const numeric = /^\d+$/.test(x) && /^\d+$/.test(y);
    return numeric ? Number(x) - Number(y) : x < y ? -1 : 1;
  }
  return 0;
}

/** Below zero when a is before b, zero when equal, above zero when after. */
export function compareVersions(a: Version, b: Version): number {
  const [aMajor, aMinor, aPatch] = a.numbers;
  const [bMajor, bMinor, bPatch] = b.numbers;
  return aMajor - bMajor || aMinor - bMinor || aPatch - bPatch || comparePre(a.pre, b.pre);
}

const sameLine = (a: Version, b: Version): boolean => a.numbers[0] === b.numbers[0] && a.numbers[1] === b.numbers[1];

type Clause =
  | { kind: 'lower'; version: Version; inclusive: boolean }
  | { kind: 'upper'; version: Version; inclusive: boolean }
  | { kind: 'exact'; version: Version }
  | { kind: 'between'; low: Version; high: Version };

function parseClause(text: string): Clause | undefined {
  const spaced = /^(\S+)\s+-\s+(\S+)$/.exec(text) ?? /^(v?\d+\.\d+\.\d+)-(v?\d+\.\d+\.\d+)$/.exec(text);
  if (spaced !== null) {
    const [, lowText = '', highText = ''] = spaced;
    const [low, high] = [parseVersion(lowText), parseVersion(highText)];
    return low === undefined || high === undefined ? undefined : { kind: 'between', low, high };
  }
  const [, operator = '=', bound = text] = /^(>=|>|<=|<|=)\s*(\S+)$/.exec(text) ?? [];
  const version = parseVersion(bound);
  // A pre-release holding another version (`4.0.0-rc.1-4.7.0`) is a range written without spaces: unread.
  if (version === undefined || /\d+\.\d+\.\d+/.test(version.pre.join('.'))) return undefined;
  if (operator === '=') return { kind: 'exact', version };
  return { kind: operator.startsWith('>') ? 'lower' : 'upper', version, inclusive: operator.endsWith('=') };
}

const after = (version: Version, bound: Version, inclusive: boolean): boolean =>
  inclusive ? compareVersions(version, bound) >= 0 : compareVersions(version, bound) > 0;
const before = (version: Version, bound: Version, inclusive: boolean): boolean =>
  inclusive ? compareVersions(version, bound) <= 0 : compareVersions(version, bound) < 0;

/**
 * A list of `< X` fixes, one per release line (`<2.63.8, <2.64.5, <2.66.11`),
 * judged closed: a version on a listed line is affected below that line's fix;
 * on a line not listed it is affected when any fix is above it (2.65.0 sits
 * below 2.66.11), and clear only when it is past every fix.
 */
function belowFixes(version: Version, fixes: readonly { version: Version; inclusive: boolean }[]): boolean {
  const own = fixes.find((fix) => sameLine(version, fix.version));
  if (own !== undefined) return before(version, own.version, own.inclusive);
  return fixes.some((fix) => compareVersions(version, fix.version) < 0);
}

/**
 * Whether a version is in an advisory's affected range, or undefined when the
 * range can't be read. Zitadel writes its ranges by hand, in several forms
 * (every one published by S201 is in watch.test.ts), read so that a doubtful
 * reading leans to affected, never to clear:
 * - `A - B`: both ends included; `A` alone: that version;
 * - `>= A, <= B`: a lower bound with an upper one right after it, both applying;
 * - one bare `< X` (or `<=`): every version below it;
 * - two or more bare `< X`: fixes one per release line (belowFixes);
 * - a lone `>= A` (no upper bound right after it) below some bare fix starts
 *   the fixes (`< 2.41.6, < 2.40.10, >=2.39.0`: from 2.39.0, below the fixes);
 *   at or above every fix, or with none, it covers every version from A on.
 */
export function inRange(range: string, version: Version): boolean | undefined {
  const clauses = range
    .split(',')
    .map((text) => text.trim())
    .filter((text) => text !== '')
    .map(parseClause);
  if (clauses.length === 0 || clauses.some((clause) => clause === undefined)) return undefined;
  const parsed = clauses as Clause[];
  const paired = (index: number): boolean => parsed[index - 1]?.kind === 'lower' && parsed[index]?.kind === 'upper';
  const fixes = parsed.flatMap((clause, index) => (clause.kind === 'upper' && !paired(index) ? [clause] : []));
  const underFixes =
    fixes.length > 1 ? belowFixes(version, fixes) : fixes.some((fix) => before(version, fix.version, fix.inclusive));
  const loneLowers = parsed.flatMap((clause, index) => (clause.kind === 'lower' && !paired(index + 1) ? [clause] : []));
  // A lone lower bound below some fix starts the fixes; one at or above every
  // fix (`< 3.4.16, >= 4.0.0`) is a range of its own, open from it onwards.
  const startsFixes = (low: Clause & { kind: 'lower' }): boolean =>
    fixes.some((fix) => compareVersions(low.version, fix.version) < 0);
  const starters = loneLowers.filter(startsFixes);
  const fromLower = (lows: typeof loneLowers): boolean =>
    lows.some((low) => after(version, low.version, low.inclusive));
  if (fromLower(loneLowers.filter((low) => !startsFixes(low)))) return true;
  if (starters.length > 0 ? fromLower(starters) && underFixes : underFixes) return true;
  return parsed.some((clause, index) => {
    if (clause.kind === 'between') return before(version, clause.high, true) && after(version, clause.low, true);
    if (clause.kind === 'exact') return compareVersions(version, clause.version) === 0;
    const next = parsed[index + 1];
    return (
      clause.kind === 'lower' &&
      next?.kind === 'upper' &&
      paired(index + 1) &&
      after(version, clause.version, clause.inclusive) &&
      before(version, next.version, next.inclusive)
    );
  });
}

interface Advisory {
  ghsa_id?: string;
  summary?: string;
  severity?: string | null;
  html_url?: string;
  withdrawn_at?: string | null;
  vulnerabilities?: { vulnerable_version_range?: string | null; patched_versions?: string | null }[] | null;
}

/** The advisories `gh api --paginate --slurp` gives (pages of arrays), or a single array. */
export function flattenAdvisories(data: unknown): Advisory[] {
  if (!Array.isArray(data)) return [];
  return data.flatMap((each: unknown) => (Array.isArray(each) ? (each as Advisory[]) : [each as Advisory]));
}

/** Zitadel's advisories, judged against a version: red on a high or critical one that applies and has a fix. */
export function judgeAdvisories(advisories: readonly Advisory[], versionText: string, control: boolean): Verdict {
  const version = parseVersion(versionText);
  const subject = control
    ? `Positive control: Zitadel v${versionText} (a version chosen for this run, not what staging runs)`
    : `Zitadel v${versionText}, which staging and the local stack run (server and login pages),`;
  if (version === undefined || advisories.length === 0) {
    const why =
      version === undefined
        ? `The Zitadel version ${versionText === '' ? '(none)' : versionText} is not a version`
        : "Zitadel's advisory list came back empty";
    return {
      errors: [
        `${why}, so Zitadel's security advisories went unchecked today. Check the pinned image (or the control's input) ` +
          `and GitHub's API, then re-run this workflow.`,
      ],
      summary: `## Zitadel's advisories\n\nNot checked: ${why}.\n`,
    };
  }
  const rows = advisories
    .filter((advisory) => advisory.withdrawn_at === null || advisory.withdrawn_at === undefined)
    .flatMap((advisory) => {
      const verdicts = (advisory.vulnerabilities ?? []).map((each) => ({
        range: each.vulnerable_version_range ?? '',
        patched: (each.patched_versions ?? '').trim(),
        hit: inRange(each.vulnerable_version_range ?? '', version),
      }));
      const hit = verdicts.find((each) => each.hit === true);
      // An advisory naming no affected versions at all can't be cleared either.
      const unread =
        verdicts.length === 0
          ? { range: '(no affected versions given)', patched: '' }
          : verdicts.find((each) => each.hit === undefined);
      const found = hit ?? unread;
      if (found === undefined) return [];
      const severity = (advisory.severity ?? 'unknown').toLowerCase();
      return [{ advisory, severity, unread: hit === undefined, range: found.range, patched: found.patched }];
    });
  const errors = rows.flatMap(({ advisory, severity, unread, range, patched }) => {
    const id = advisory.ghsa_id ?? 'an advisory';
    const title = advisory.summary ?? 'no title';
    if (unread) {
      return [
        `Zitadel's advisory ${id} (${title}) gives an affected range this watch can't read ("${range}"), so it ` +
          `can't tell whether Zitadel v${versionText} is affected. Read it (${advisory.html_url ?? id}); ` +
          `if it applies, move Zitadel to a fixed version (ADR-003) and run the hand deploy, and teach ` +
          `tooling/image-watch/watch.ts the range's form.`,
      ];
    }
    if (!BLOCKING.has(severity) || patched === '') return [];
    const line =
      `${subject} has a published ${severity}-severity advisory ${id} (${title}). Sign-in may be at risk. ` +
      `Move Zitadel and its login image to a fixed version (${patched} or later; ADR-003) in ` +
      `deploy/compose/compose.yaml and deploy/azure/staging.apps.bicepparam, then run the hand deploy. ` +
      (advisory.html_url ?? '');
    return [line.trimEnd()];
  });
  const table = rows.map(
    ({ advisory, severity, unread, range, patched }) =>
      `| ${unread || (BLOCKING.has(severity) && patched !== '') ? 'red' : 'report only'} | ${cell(severity)} | ` +
      `${cell(advisory.ghsa_id ?? '?')} | ${cell(advisory.summary ?? '')} | ${cell(range)} | ${patched === '' ? 'no fix yet' : cell(patched)} |`,
  );
  const head =
    `## Zitadel's advisories\n\n${control ? 'Positive control: ' : ''}v${versionText} against ` +
    `${String(advisories.length)} published advisories: ${String(rows.length)} apply, ${String(errors.length)} red.\n`;
  const body =
    rows.length === 0
      ? '\nNone applies.\n'
      : `\n| Verdict | Severity | Advisory | Title | Affected | Fixed in |\n| --- | --- | --- | --- | --- | --- |\n${table.join('\n')}\n`;
  return { errors, summary: head + body };
}

// --- The command line --------------------------------------------------------

function report(verdict: Verdict): number {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile !== undefined && summaryFile !== '') appendFileSync(summaryFile, `${verdict.summary}\n`);
  for (const error of verdict.errors) process.stdout.write(`::error::${escapeCommand(error)}\n`);
  if (verdict.errors.length === 0) process.stdout.write('Nothing needs a person today.\n');
  return verdict.errors.length === 0 ? 0 : 1;
}

export function main(args: readonly string[], read: (file: string) => string, now: Date = new Date()): number {
  const [command, file = '', extra = ''] = args;
  const images = watchedImages(read);
  if (command === 'images') {
    process.stdout.write(JSON.stringify({ include: images.map(({ key, image }) => ({ key, image })) }));
    return 0;
  }
  const accepted = (): ReturnType<typeof parseAccepted> =>
    parseAccepted(
      JSON.parse(read(ACCEPTED_FILE)),
      images.map((each) => each.key),
      now,
    );
  if (command === 'accepted') return report(accepted());
  if (command === 'grype') {
    const image = images.find((each) => each.key === extra);
    if (image === undefined) throw new Error(`${extra} is not one of the watched images`);
    return report(judgeGrype(JSON.parse(read(file)) as GrypeReport, image, accepted().entries, now));
  }
  if (command === 'advisories') {
    const advisories = flattenAdvisories(JSON.parse(read(file)));
    return report(
      judgeAdvisories(advisories, extra === '' ? zitadelVersion(images) : extra.replace(/^v/, ''), extra !== ''),
    );
  }
  process.stderr.write(
    'usage: watch.ts images | accepted | grype <report.json> <key> | advisories <advisories.json> [version]\n',
  );
  return 2;
}

if (import.meta.main) process.exitCode = main(process.argv.slice(2), (file) => readFileSync(file, 'utf8'));
