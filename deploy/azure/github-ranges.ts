/**
 * GitHub's published address ranges, which the apps subnet is allowed out to
 * (network.bicep, G2d-3). Everything else the apps need is an Azure service
 * tag, which Azure keeps current by itself; GitHub has no service tag, so the
 * ranges are pinned in github-ranges.json and refreshed by hand.
 *
 * **Pulling one image takes two hosts, not one**, which is why there are two
 * groups: `ghcr.io` answers for the registry API (the token and the manifest)
 * and is published under the `packages` key of https://api.github.com/meta,
 * but every layer download is a 307 to `pkg-containers.githubusercontent.com`,
 * whose addresses are **not** under `packages` — they sit in the 185.199.108.0/22
 * that meta publishes under `web`, `api` and `git`. Allowing `packages` alone
 * leaves a pull that reads the manifest and then hangs on the first layer.
 * Proved against our own image before the rules were written (S18).
 *
 * **Refreshing:** `node deploy/azure/github-ranges.ts` fetches meta, resolves
 * both hosts and reports any drift; `--write` updates the file. Only drift that
 * can break a pull refuses (exit 1): a range GitHub publishes that the file
 * doesn't hold, a field gone, or a host answering from outside the file. A
 * range GitHub merely stopped listing is printed as a note and passes (exit 0):
 * keeping one more address allowed for a few days breaks nothing, and GitHub
 * drops one every few days (S185). A meta or DNS read that fails still refuses.
 * The foundation deploy runs it first; a daily workflow
 * (github-ranges-refresh.yml) runs `--write` and pushes a
 * `data/github-ranges-<day>` branch whenever the file would change. It is never
 * run in CI: it needs the network, and a GitHub outage must not fail our build.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

/** One host the apps reach, and the addresses GitHub publishes for it. */
interface RangeGroup {
  /** What the apps use it for, in a sentence. */
  readonly what: string;
  /** The host these addresses answer for. */
  readonly host: string;
  /**
   * The field of https://api.github.com/meta these prefixes are copied from, or
   * null when meta publishes no field for this host and they are pinned by hand.
   */
  readonly publishedUnder: string | null;
  readonly prefixes: readonly string[];
}

export interface GithubRanges {
  /** The day the prefixes below were last checked against `META`, as YYYY-MM-DD. */
  readonly refreshed: string;
  /** The registry API: the token and the manifest. */
  readonly registry: RangeGroup;
  /** Where the registry redirects every layer download. */
  readonly downloads: RangeGroup;
}

/**
 * What GitHub says today: meta as it answers, and the addresses each host
 * resolves to. Meta's fields are not all lists of prefixes — it also holds a
 * boolean, key fingerprints and an object of domains — so every field is read
 * through `prefixList` rather than assumed.
 */
export interface LiveRanges {
  readonly meta: Readonly<Record<string, unknown>>;
  readonly addresses: Readonly<Record<string, readonly string[]>>;
}

/** A field of meta as the list of prefixes it should be, or nothing if it is anything else. */
const prefixList = (value: unknown): string[] | undefined =>
  Array.isArray(value) && value.every((entry) => typeof entry === 'string') ? [...value] : undefined;

/**
 * Where the ranges are published. A constant, never a field of the file: the
 * file says what came back, the code says who to ask. CodeQL reads a request
 * whose address comes from a file as a finding, and it is right to — a data
 * file that could redirect an outbound call is a different thing from one that
 * holds addresses (alert 5, PR #33).
 */
export const META = 'https://api.github.com/meta';

const RANGES_FILE = path.join(import.meta.dirname, 'github-ranges.json');

export const readRanges = (): GithubRanges => JSON.parse(readFileSync(RANGES_FILE, 'utf8')) as GithubRanges;

/** The two groups, in the order the rules use them. */
const groupsOf = (ranges: GithubRanges): readonly (readonly [string, RangeGroup])[] => [
  ['registry', ranges.registry],
  ['downloads', ranges.downloads],
];

/** An IPv4 address as a number, or undefined for anything that isn't one. */
function addressValue(address: string): number | undefined {
  const parts = address.split('.');
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    value = value * 256 + octet;
  }
  return value;
}

/** Whether an IPv4 address falls inside a `a.b.c.d/len` prefix. Anything unparseable is outside. */
export function covers(prefix: string, address: string): boolean {
  const [network, length] = prefix.split('/');
  const start = network === undefined ? undefined : addressValue(network);
  const bits = Number(length);
  const value = addressValue(address);
  if (start === undefined || value === undefined || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  // A /0 would shift by 32, which JavaScript reads as no shift at all.
  const size = bits === 0 ? 2 ** 32 : 2 ** (32 - bits);
  return Math.floor(start / size) === Math.floor(value / size);
}

const sorted = (prefixes: readonly string[]): string[] => [...prefixes].sort();

/** Every prefix meta publishes anywhere, so a hand-pinned group can be held to addresses GitHub owns. */
const everyPublished = (meta: LiveRanges['meta']): ReadonlySet<string> =>
  new Set(Object.values(meta).flatMap((value) => prefixList(value) ?? []));

/**
 * How the pinned ranges differ from GitHub, a line each. `refusals` can break a
 * pull, so a deploy stops on any: a published field that now holds a prefix
 * the file doesn't, or is gone; or a host answering from an address no pinned
 * prefix covers. `notes` can't: a prefix GitHub stopped listing is still
 * allowed, one address more than needed until the file is refreshed.
 */
export interface RangeDrift {
  readonly refusals: readonly string[];
  readonly notes: readonly string[];
}

const KEPT = 'it stays allowed until the file is refreshed; refresh it at the next weekly read';

/** How one group's prefixes differ from what meta publishes for them. */
function listingDrift(name: string, group: RangeGroup, meta: LiveRanges['meta']): RangeDrift {
  if (group.publishedUnder === null) {
    const published = everyPublished(meta);
    return {
      refusals: [],
      notes: group.prefixes
        .filter((prefix) => !published.has(prefix))
        .map(
          (prefix) =>
            `${name}: GitHub no longer lists ${prefix}, pinned by hand; it stays allowed until it is taken out by hand`,
        ),
    };
  }
  const field = group.publishedUnder;
  const current = prefixList(meta[field]);
  if (current === undefined)
    return { refusals: [`${name}: ${META} no longer publishes a "${field}" field`], notes: [] };
  return {
    refusals: sorted(current.filter((prefix) => !group.prefixes.includes(prefix))).map(
      (prefix) =>
        `${name}: GitHub now publishes ${prefix} under "${field}", which the file doesn't allow yet; run with --write to take it`,
    ),
    notes: sorted(group.prefixes.filter((prefix) => !current.includes(prefix))).map(
      (prefix) => `${name}: GitHub no longer lists ${prefix}; ${KEPT}`,
    ),
  };
}

/** Why a group's host can't be reached through its prefixes: no address, or one outside them all. */
function addressRefusals(name: string, group: RangeGroup, live: LiveRanges): string[] {
  const addresses = live.addresses[group.host] ?? [];
  if (addresses.length === 0) return [`${name}: ${group.host} resolved to no address`];
  return addresses
    .filter((address) => !group.prefixes.some((prefix) => covers(prefix, address)))
    .map((address) => `${name}: ${group.host} answers from ${address}, which no allowed prefix covers`);
}

export function rangeDrift(pinned: GithubRanges, live: LiveRanges): RangeDrift {
  const refusals: string[] = [];
  const notes: string[] = [];
  for (const [name, group] of groupsOf(pinned)) {
    const listing = listingDrift(name, group, live.meta);
    refusals.push(...listing.refusals, ...addressRefusals(name, group, live));
    notes.push(...listing.notes);
  }
  return { refusals, notes };
}

/** The pinned ranges brought up to date: every published group takes its meta field, and the day is today's. */
export function refreshed(pinned: GithubRanges, live: LiveRanges, today: string): GithubRanges {
  const take = (group: RangeGroup): RangeGroup =>
    group.publishedUnder === null
      ? group
      : { ...group, prefixes: sorted(prefixList(live.meta[group.publishedUnder]) ?? group.prefixes) };
  return {
    ...pinned,
    refreshed: today,
    registry: take(pinned.registry),
    downloads: take(pinned.downloads),
  };
}

/** The file as it is written: JSON with a trailing newline, the shape Prettier leaves it in. */
export const rangesText = (ranges: GithubRanges): string => `${JSON.stringify(ranges, null, 2)}\n`;

async function live(ranges: GithubRanges): Promise<LiveRanges> {
  const { resolve4 } = await import('node:dns/promises');
  const response = await fetch(META, { headers: { accept: 'application/vnd.github+json' } });
  if (!response.ok) throw new Error(`${META} answered ${String(response.status)}`);
  const meta = (await response.json()) as LiveRanges['meta'];
  const addresses: Record<string, readonly string[]> = {};
  for (const [, group] of groupsOf(ranges)) {
    addresses[group.host] = await resolve4(group.host);
  }
  return { meta, addresses };
}

/** Whether two files hold different prefixes, whatever day each says it was checked. */
const prefixesDiffer = (one: GithubRanges, other: GithubRanges): boolean =>
  rangesText({ ...one, refreshed: '' }) !== rangesText({ ...other, refreshed: '' });

/**
 * Exit 0 when nothing can break a pull (notes alone pass), 1 when something
 * can. A read of GitHub that fails rejects, which exits non-zero: the deploy
 * refuses on it, as it always has. `--write` writes only when a prefix moves,
 * so a day with nothing new leaves the file, and the daily branch, alone.
 */
export async function main(
  argv: readonly string[],
  readLive: (ranges: GithubRanges) => Promise<LiveRanges> = live,
  save: (text: string) => void = (text) => {
    writeFileSync(RANGES_FILE, text, 'utf8');
  },
): Promise<number> {
  const write = argv.includes('--write');
  const pinned = readRanges();
  const current = await readLive(pinned);
  const { refusals, notes } = rangeDrift(pinned, current);
  if (refusals.length === 0 && notes.length === 0) {
    console.log(`GitHub's ranges are unchanged since ${pinned.refreshed}; nothing to do.`);
    return 0;
  }
  for (const line of [...refusals, ...notes]) console.log(line);
  if (!write) {
    if (refusals.length > 0) {
      console.log('Run with --write to take the published ranges, then read the change before committing it.');
      return 1;
    }
    console.log('Going ahead: GitHub only stopped listing an address, and keeping it allowed breaks no pull.');
    return 0;
  }
  const updated = refreshed(pinned, current, new Date().toISOString().slice(0, 10));
  if (prefixesDiffer(updated, pinned)) {
    save(rangesText(updated));
    console.log(`Wrote ${RANGES_FILE}. A changed range is a deployment change: redeploy before the next image pull.`);
  }
  const left = rangeDrift(updated, current).refusals;
  for (const problem of left) console.log(`still wrong after the update: ${problem}`);
  return left.length === 0 ? 0 : 1;
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
