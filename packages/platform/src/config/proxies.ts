// SEC-AV-07 (threat AV-6): the proxies whose `X-Forwarded-For` the API
// believes. Each entry is an address or a CIDR range, and a range is judged by
// what it covers, not how it's written. It's refused when it covers far more
// than a set of proxies could: an IPv4 range wider than /16, an IPv6 range
// wider than /48, or an IPv6 range in the IPv4-mapped block (::ffff:0:0/96).
// The proxy check matches an IPv4 client against an IPv6 range in its mapped
// form, so `::ffff:0:0/96`, or `::/64`, which contains it, would trust every
// IPv4 client, letting any of them choose its own address.
import { z } from 'zod';

const IPV4_WIDEST_PREFIX = 16;
const IPV6_WIDEST_PREFIX = 48;

/** The IPv4-mapped block, ::ffff:0:0/96, as a 128-bit number and its prefix. */
const MAPPED_BLOCK = 0xffffn << 32n;
const MAPPED_PREFIX = 96;

const singleAddress = z.union([z.ipv4(), z.ipv6()]);
const ipv4Range = z.cidrv4();
const ipv6Range = z.cidrv6();

/**
 * A dotted IPv4 tail (`::ffff:10.0.0.1`) fills an address's last two groups.
 * Only where it sits matters: the check below never reads the last 32 bits.
 */
const IPV4_TAIL = ['0', '0'];

function groupsOf(part: string): string[] {
  return part === '' ? [] : part.split(':').flatMap((group) => (group.includes('.') ? IPV4_TAIL : [group]));
}

const valueOf = (groups: readonly string[]): bigint =>
  groups.reduce((value, group) => (value << 16n) | BigInt(Number.parseInt(group, 16)), 0n);

/** An IPv6 address zod has already accepted, as a 128-bit number (a dotted tail counts as zero). */
function ipv6Value(address: string): bigint {
  // `::` stands for zero groups: the groups before it move up past them.
  const gap = address.indexOf('::');
  const before = groupsOf(gap === -1 ? address : address.slice(0, gap));
  const after = groupsOf(gap === -1 ? '' : address.slice(gap + 2));
  return (valueOf(before) << BigInt(16 * (8 - before.length))) | valueOf(after);
}

/** For a range zod has already accepted: `start/prefix`. */
function isTooWide(range: string): boolean {
  const slash = range.indexOf('/');
  const prefix = Number(range.slice(slash + 1));
  if (ipv4Range.safeParse(range).success) return prefix < IPV4_WIDEST_PREFIX;
  // Two ranges overlap when they agree on the bits both prefixes fix.
  const fixed = BigInt(128 - Math.min(prefix, MAPPED_PREFIX));
  return prefix < IPV6_WIDEST_PREFIX || ipv6Value(range.slice(0, slash)) >> fixed === MAPPED_BLOCK >> fixed;
}

function isAcceptable(entry: string): boolean {
  if (singleAddress.safeParse(entry).success) return true;
  return (ipv4Range.safeParse(entry).success || ipv6Range.safeParse(entry).success) && !isTooWide(entry);
}

/** The positions (from 1) of the entries that aren't acceptable proxy addresses. */
export function refusedProxyEntries(entries: readonly string[]): number[] {
  return entries.flatMap((entry, index) => (isAcceptable(entry) ? [] : [index + 1]));
}
