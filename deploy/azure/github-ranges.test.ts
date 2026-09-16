// SEC-OPS-09: the apps subnet's way out is an allowlist, so the addresses in
// it must be GitHub's own and must still be current. These check the refresher
// that keeps them so (github-ranges.ts) without touching the network: the live
// answers are stand-ins, and the checked-in file is read as it is.
import { describe, expect, it } from 'vitest';

import {
  covers,
  type GithubRanges,
  type LiveRanges,
  rangeProblems,
  rangesText,
  readRanges,
  refreshed,
} from './github-ranges.ts';

const PINNED: GithubRanges = {
  source: 'https://api.github.com/meta',
  refreshed: '2026-09-16',
  registry: { what: 'the manifest', host: 'registry.example', publishedUnder: 'packages', prefixes: ['192.0.2.0/24'] },
  downloads: { what: 'the layers', host: 'downloads.example', publishedUnder: null, prefixes: ['198.51.100.0/24'] },
};

const LIVE: LiveRanges = {
  meta: { packages: ['192.0.2.0/24'], web: ['198.51.100.0/24'] },
  addresses: { 'registry.example': ['192.0.2.7'], 'downloads.example': ['198.51.100.9'] },
};

/** The stand-in answers with one part replaced. */
const liveWith = (change: Partial<LiveRanges>): LiveRanges => ({ ...LIVE, ...change });

describe('covers', () => {
  it('reads a prefix as the block of addresses it stands for', () => {
    expect(covers('192.0.2.7/32', '192.0.2.7')).toBe(true);
    expect(covers('192.0.2.7/32', '192.0.2.8')).toBe(false);
    // The /31 GitHub publishes for two neighbouring addresses.
    expect(covers('192.30.255.164/31', '192.30.255.165')).toBe(true);
    expect(covers('192.30.255.164/31', '192.30.255.166')).toBe(false);
    // The /22 every layer download lands in.
    for (const address of ['185.199.108.154', '185.199.111.154']) {
      expect(covers('185.199.108.0/22', address)).toBe(true);
    }
    expect(covers('185.199.112.1', '185.199.112.1')).toBe(false);
    expect(covers('185.199.108.0/22', '185.199.112.1')).toBe(false);
    expect(covers('0.0.0.0/0', '8.8.8.8')).toBe(true);
  });

  it('treats anything that is not an address and a length as covering nothing', () => {
    for (const [prefix, address] of [
      ['192.0.2.0/24', '192.0.2'],
      ['192.0.2.0/24', '192.0.2.256'],
      ['192.0.2.0/24', 'not an address'],
      ['192.0.2.0/33', '192.0.2.1'],
      ['192.0.2.0/-1', '192.0.2.1'],
      ['192.0.2.0/no', '192.0.2.1'],
      ['2001:db8::/32', '2001:db8::1'],
      ['', '192.0.2.1'],
    ] as const) {
      expect(covers(prefix, address)).toBe(false);
    }
  });
});

describe('rangeProblems', () => {
  it('says nothing while the pinned ranges match what GitHub publishes and answers from', () => {
    expect(rangeProblems(PINNED, LIVE)).toEqual([]);
  });

  it('notices a field that has moved on, or gone', () => {
    expect(
      rangeProblems(
        PINNED,
        liveWith({ meta: { packages: ['192.0.2.0/24', '203.0.113.0/24'], web: ['198.51.100.0/24'] } }),
      ),
    ).toEqual(['registry: the "packages" field has changed; run with --write to take it']);
    expect(rangeProblems(PINNED, liveWith({ meta: { web: ['198.51.100.0/24'] } }))).toEqual([
      'registry: https://api.github.com/meta no longer publishes a "packages" field',
    ]);
  });

  it('notices a hand-pinned prefix GitHub no longer publishes anywhere', () => {
    expect(rangeProblems(PINNED, liveWith({ meta: { packages: ['192.0.2.0/24'] } }))).toEqual([
      'downloads: 198.51.100.0/24 is pinned by hand but https://api.github.com/meta no longer publishes it anywhere',
    ]);
  });

  it('notices a host that has moved out of its allowed prefixes, which is what breaks a pull', () => {
    expect(
      rangeProblems(
        PINNED,
        liveWith({ addresses: { 'registry.example': ['192.0.2.7', '203.0.113.4'], 'downloads.example': ['1.1.1.1'] } }),
      ),
    ).toEqual([
      'registry: registry.example answers from 203.0.113.4, which no allowed prefix covers',
      'downloads: downloads.example answers from 1.1.1.1, which no allowed prefix covers',
    ]);
  });

  it('notices a host that resolves to nothing, rather than reading it as agreement', () => {
    expect(rangeProblems(PINNED, liveWith({ addresses: { 'registry.example': [] } }))).toEqual([
      'registry: registry.example resolved to no address',
      'downloads: downloads.example resolved to no address',
    ]);
  });
});

describe('refreshed', () => {
  it('takes a published group from GitHub, sorted, and leaves a hand-pinned one alone', () => {
    const live = liveWith({ meta: { packages: ['203.0.113.0/24', '192.0.2.0/24'], web: ['198.51.100.0/24'] } });
    const updated = refreshed(PINNED, live, '2026-10-01');
    expect(updated.registry.prefixes).toEqual(['192.0.2.0/24', '203.0.113.0/24']);
    expect(updated.downloads).toEqual(PINNED.downloads);
    expect(updated.refreshed).toBe('2026-10-01');
    // What it writes is what a second run reads back with nothing left to say.
    expect(rangeProblems(updated, live)).toEqual([]);
    expect(rangesText(updated).endsWith('}\n')).toBe(true);
  });
});

describe('the checked-in ranges', () => {
  const ranges = readRanges();

  it('names the source, the day it was last checked, and a host for each group', () => {
    expect(ranges.source).toBe('https://api.github.com/meta');
    expect(ranges.refreshed).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(ranges.registry.host).toBe('ghcr.io');
    expect(ranges.registry.publishedUnder).toBe('packages');
    // Every layer download is a redirect to this host, whose addresses are in
    // no packages key: allowing the registry alone stops a pull at the first
    // layer, so the group is pinned by hand and checked by resolving it.
    expect(ranges.downloads.host).toBe('pkg-containers.githubusercontent.com');
    expect(ranges.downloads.publishedUnder).toBeNull();
  });

  it('holds only IPv4 prefixes, and at least one for each group', () => {
    for (const group of [ranges.registry, ranges.downloads]) {
      expect(group.prefixes.length).toBeGreaterThan(0);
      for (const prefix of group.prefixes) {
        expect(prefix).toMatch(/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/);
        // A prefix that covers its own first address is one `covers` can read.
        expect(covers(prefix, prefix.split('/')[0] ?? '')).toBe(true);
      }
    }
  });

  it('opens no door wider than GitHub needs', () => {
    for (const prefix of [...ranges.registry.prefixes, ...ranges.downloads.prefixes]) {
      expect(Number(prefix.split('/')[1])).toBeGreaterThanOrEqual(22);
    }
  });
});
