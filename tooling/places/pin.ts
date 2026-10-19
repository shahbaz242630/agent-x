// The place file's pin in the Dockerfile (Phase 3 L4b; partner, S127: the
// file goes stale): which DB-IP month the image takes, moved each month by
// .github/workflows/places-refresh.yml and watched by the weekly sweep. Node
// builtins only: the refresh's writing job and the weekly sweep run it on
// CI's bare Node, with no packages installed.
//
//   node tooling/places/pin.ts due          prints the month to fetch, or nothing when the pin is this month's
//   node tooling/places/pin.ts pin M SHA    pins month M (YYYY-MM) and the .gz's SHA-256
//   node tooling/places/pin.ts age          fails, in plain words, when the pinned file is over MOST_AGE_DAYS old
import { readFileSync, writeFileSync } from 'node:fs';

/** The API's PLACES_STALE_DAYS, copied (bare Node): past it the weekly sweep fails and the API warns at start. */
export const MOST_AGE_DAYS = 45;

// The shared kernel's, copied: this runs on CI's bare Node.
const DAY_MS = 86_400_000;

const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MONTH_NAMES = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

const RELEASE_URL =
  /(\/releases\/download\/geoip-dbip-city-lite-)\d{4}-\d{2}(\/dbip-city-lite-)\d{4}-\d{2}(\.mmdb\.gz)/;
const CHECKSUM = /(ADD --checksum=sha256:)[0-9a-f]{64}/;
const COMMENT_MONTH = /(City Lite, )[A-Z][a-z]+ \d{4}/;

/** The month the Dockerfile's place file is, or undefined when it pins none. */
export function pinnedMonth(dockerfile: string): string | undefined {
  return /\/releases\/download\/geoip-dbip-city-lite-(\d{4}-\d{2})\//.exec(dockerfile)?.[1];
}

/** The month in UTC on a date, as DB-IP names its files. */
export const monthOf = (now: Date): string => now.toISOString().slice(0, 7);

/** The month to fetch, or undefined when the Dockerfile already pins this month's. */
export function monthDue(dockerfile: string, now: Date): string | undefined {
  const month = monthOf(now);
  return pinnedMonth(dockerfile) === month ? undefined : month;
}

/** The Dockerfile pinning another month's file: its release URL, checksum and the comment naming the month. */
export function pinned(dockerfile: string, month: string, sha256: string): string {
  if (!MONTH.test(month)) throw new RangeError(`${month} is not a month (YYYY-MM)`);
  if (!SHA256.test(sha256)) throw new RangeError('the checksum is not a SHA-256 in lower-case hex');
  for (const [what, pattern] of [
    ['release URL', RELEASE_URL],
    ['checksum', CHECKSUM],
    ['comment naming the month', COMMENT_MONTH],
  ] as const) {
    if (!pattern.test(dockerfile)) throw new RangeError(`the Dockerfile has no ${what} to move`);
  }
  const name = `${MONTH_NAMES[Number(month.slice(5)) - 1] ?? ''} ${month.slice(0, 4)}`;
  return dockerfile
    .replace(RELEASE_URL, `$1${month}$2${month}$3`)
    .replace(CHECKSUM, `$1${sha256}`)
    .replace(COMMENT_MONTH, `$1${name}`);
}

/** What's wrong with the pinned file's age, in plain words, or undefined when it is fresh enough. */
export function ageProblem(dockerfile: string, now: Date): string | undefined {
  const month = pinnedMonth(dockerfile);
  if (month === undefined) return 'The Dockerfile pins no place file, so the API would not start: put the pin back.';
  const days = Math.floor((now.getTime() - Date.parse(`${month}-01T00:00:00Z`)) / DAY_MS);
  if (days <= MOST_AGE_DAYS) return undefined;
  return (
    `The place file is ${String(days)} days old (DB-IP's ${month}): the activity log's countries and cities are going ` +
    `out of date. The monthly refresh (places-refresh.yml) has not moved it: look at its last run, or run it by hand.`
  );
}

function main(args: readonly string[], now: Date): number {
  const [command, month = '', sha256 = ''] = args;
  const dockerfile = readFileSync('Dockerfile', 'utf8');
  if (command === 'due') {
    process.stdout.write(monthDue(dockerfile, now) ?? '');
    return 0;
  }
  if (command === 'pin') {
    writeFileSync('Dockerfile', pinned(dockerfile, month, sha256));
    return 0;
  }
  if (command === 'age') {
    const problem = ageProblem(dockerfile, now);
    const fresh = `The place file is DB-IP's ${pinnedMonth(dockerfile) ?? ''}: fresh enough.`;
    process.stdout.write(`${problem ?? fresh}\n`);
    return problem === undefined ? 0 : 1;
  }
  process.stderr.write('usage: pin.ts due | pin <YYYY-MM> <sha256> | age\n');
  return 2;
}

if (import.meta.main) process.exitCode = main(process.argv.slice(2), new Date());
