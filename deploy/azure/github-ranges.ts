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
 * both hosts and reports any drift (exit 1); `--write` updates the file. It is
 * on the weekly list and must be run before a deploy, because a stale range
 * breaks an image pull. It is never run in CI: it needs the network, and a
 * GitHub outage must not fail our build.
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
  readonly source: string;
  /** The day the prefixes below were last checked against `source`, as YYYY-MM-DD. */
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
function prefixList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const prefixes: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string') return undefined;
    prefixes.push(entry);
  }
  return prefixes;
}

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

const same = (one: readonly string[], other: readonly string[]): boolean =>
  sorted(one).join(' ') === sorted(other).join(' ');

/** Every prefix meta publishes anywhere, so a hand-pinned group can be held to addresses GitHub owns. */
const everyPublished = (meta: LiveRanges['meta']): ReadonlySet<string> =>
  new Set(Object.values(meta).flatMap((value) => prefixList(value) ?? []));

/**
 * Why the pinned ranges no longer match GitHub, a line each, or nothing at all.
 * Three ways they can go wrong: a group copied from a meta field has fallen
 * behind it; a group pinned by hand names a prefix meta no longer publishes;
 * or a host now answers from an address no pinned prefix covers, which is the
 * one that breaks a pull.
 */
export function rangeProblems(pinned: GithubRanges, live: LiveRanges): string[] {
  const problems: string[] = [];
  const published = everyPublished(live.meta);
  for (const [name, group] of groupsOf(pinned)) {
    if (group.publishedUnder !== null) {
      const current = prefixList(live.meta[group.publishedUnder]);
      if (current === undefined) {
        problems.push(`${name}: ${pinned.source} no longer publishes a "${group.publishedUnder}" field`);
      } else if (!same(group.prefixes, current)) {
        problems.push(`${name}: the "${group.publishedUnder}" field has changed; run with --write to take it`);
      }
    } else {
      for (const prefix of group.prefixes.filter((prefix) => !published.has(prefix))) {
        problems.push(`${name}: ${prefix} is pinned by hand but ${pinned.source} no longer publishes it anywhere`);
      }
    }
    const addresses = live.addresses[group.host] ?? [];
    if (addresses.length === 0) problems.push(`${name}: ${group.host} resolved to no address`);
    for (const address of addresses.filter((address) => !group.prefixes.some((prefix) => covers(prefix, address)))) {
      problems.push(`${name}: ${group.host} answers from ${address}, which no allowed prefix covers`);
    }
  }
  return problems;
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
  const response = await fetch(ranges.source, { headers: { accept: 'application/vnd.github+json' } });
  if (!response.ok) throw new Error(`${ranges.source} answered ${String(response.status)}`);
  const meta = (await response.json()) as LiveRanges['meta'];
  const addresses: Record<string, readonly string[]> = {};
  for (const [, group] of groupsOf(ranges)) {
    addresses[group.host] = await resolve4(group.host);
  }
  return { meta, addresses };
}

async function main(argv: readonly string[]): Promise<number> {
  const write = argv.includes('--write');
  const pinned = readRanges();
  const current = await live(pinned);
  const problems = rangeProblems(pinned, current);
  if (problems.length === 0) {
    console.log(`GitHub's ranges are unchanged since ${pinned.refreshed}; nothing to do.`);
    return 0;
  }
  for (const problem of problems) console.log(problem);
  if (!write) {
    console.log('Run with --write to take the published ranges, then read the change before committing it.');
    return 1;
  }
  const today = new Date().toISOString().slice(0, 10);
  const updated = refreshed(pinned, current, today);
  writeFileSync(RANGES_FILE, rangesText(updated), 'utf8');
  const left = rangeProblems(updated, current);
  for (const problem of left) console.log(`still wrong after the update: ${problem}`);
  console.log(`Wrote ${RANGES_FILE}. A changed range is a deployment change: redeploy before the next image pull.`);
  return left.length === 0 ? 0 : 1;
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
