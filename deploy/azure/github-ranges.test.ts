// SEC-OPS-09: the apps subnet's way out is an allowlist, so the addresses in
// it must be GitHub's own and must still be current. These check the refresher
// that keeps them so (github-ranges.ts) without touching the network: the live
// answers are stand-ins, and the checked-in file is read as it is.
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  covers,
  type GithubRanges,
  type LiveRanges,
  main,
  META,
  rangeDrift,
  rangesText,
  readRanges,
  refreshed,
  writablePrefix,
} from './github-ranges.ts';

const PINNED: GithubRanges = {
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

const KEPT = 'it stays allowed until the file is refreshed; refresh it at the next weekly read';
const ADDED = '203.0.113.0/24';
const REMOVED = '20.201.28.144/32';
/** The stand-in file with one more registry prefix, which GitHub no longer lists. */
const PINNED_EXTRA: GithubRanges = {
  ...PINNED,
  registry: { ...PINNED.registry, prefixes: ['192.0.2.0/24', REMOVED] },
};

describe('rangeDrift', () => {
  it('says nothing while the pinned ranges match what GitHub publishes and answers from', () => {
    expect(rangeDrift(PINNED, LIVE)).toEqual({ refusals: [], notes: [] });
  });

  it('refuses on a range GitHub has added, which the file does not allow yet', () => {
    expect(
      rangeDrift(PINNED, liveWith({ meta: { packages: ['192.0.2.0/24', ADDED], web: ['198.51.100.0/24'] } })),
    ).toEqual({
      refusals: [
        `registry: GitHub now publishes ${ADDED} under "packages", which the file doesn't allow yet; run with --write to take it`,
      ],
      notes: [],
    });
  });

  it('only notes a range GitHub stopped listing: it is still allowed, and breaks no pull', () => {
    expect(rangeDrift(PINNED_EXTRA, LIVE)).toEqual({
      refusals: [],
      notes: [`registry: GitHub no longer lists ${REMOVED}; ${KEPT}`],
    });
  });

  it('refuses when ranges were added and removed at once', () => {
    const drift = rangeDrift(
      PINNED_EXTRA,
      liveWith({ meta: { packages: ['192.0.2.0/24', ADDED], web: ['198.51.100.0/24'] } }),
    );
    expect(drift.refusals).toHaveLength(1);
    expect(drift.notes).toEqual([`registry: GitHub no longer lists ${REMOVED}; ${KEPT}`]);
  });

  it('refuses on a field that has gone', () => {
    expect(rangeDrift(PINNED, liveWith({ meta: { web: ['198.51.100.0/24'] } })).refusals).toEqual([
      `registry: ${META} no longer publishes a "packages" field`,
    ]);
  });

  it('refuses a hand-pinned prefix GitHub no longer publishes anywhere: --write never takes it out', () => {
    expect(rangeDrift(PINNED, liveWith({ meta: { packages: ['192.0.2.0/24'] } }))).toEqual({
      refusals: [
        'downloads: GitHub no longer lists 198.51.100.0/24, pinned by hand; take it out of the file by hand (or pin what GitHub lists now), then deploy',
      ],
      notes: [],
    });
  });

  it('refuses on a host that has moved out of its allowed prefixes, which is what breaks a pull', () => {
    expect(
      rangeDrift(
        PINNED,
        liveWith({ addresses: { 'registry.example': ['192.0.2.7', '203.0.113.4'], 'downloads.example': ['1.1.1.1'] } }),
      ).refusals,
    ).toEqual([
      'registry: registry.example answers from 203.0.113.4, which no allowed prefix covers',
      'downloads: downloads.example answers from 1.1.1.1, which no allowed prefix covers',
    ]);
  });

  it('refuses on a host that resolves to nothing, rather than reading it as agreement', () => {
    expect(rangeDrift(PINNED, liveWith({ addresses: { 'registry.example': [] } })).refusals).toEqual([
      'registry: registry.example resolved to no address',
      'downloads: downloads.example resolved to no address',
    ]);
  });
});

/**
 * The command the foundation deploy runs, against the checked-in file and
 * stand-in answers built from it: its exit code is the deploy's go or stop.
 */
describe('main', () => {
  const pinned = readRanges();
  const firstAddress = (prefixes: readonly string[]): string => prefixes[0]?.split('/')[0] ?? '';
  /** GitHub's answer with the registry field as given, each host inside the file's first prefix. */
  const answering =
    (registry: readonly string[]): (() => Promise<LiveRanges>) =>
    () =>
      Promise.resolve({
        meta: { packages: [...registry], web: [...pinned.downloads.prefixes] },
        addresses: {
          [pinned.registry.host]: [firstAddress(pinned.registry.prefixes)],
          [pinned.downloads.host]: [firstAddress(pinned.downloads.prefixes)],
        },
      });
  const withoutLast = pinned.registry.prefixes.slice(0, -1);
  const last = pinned.registry.prefixes.at(-1) ?? '';
  const said = (): string[] => vi.mocked(console.log).mock.calls.map(([line]) => String(line));

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('goes ahead with a plain note when GitHub only removed a range', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    expect(await main([], answering(withoutLast))).toBe(0);
    expect(said()).toContain(`registry: GitHub no longer lists ${last}; ${KEPT}`);
    expect(said().at(-1)).toMatch(/^Going ahead/);
  });

  it('refuses when GitHub added a range, alone or beside a removal', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    expect(await main([], answering([...pinned.registry.prefixes, ADDED]))).toBe(1);
    expect(await main([], answering([...withoutLast, ADDED]))).toBe(1);
  });

  it('refuses, as it always has, when GitHub cannot be read', async () => {
    await expect(main([], () => Promise.reject(new Error('meta answered 503')))).rejects.toThrow('503');
  });

  it('with --write, writes only when a prefix moved', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const save = vi.fn<(text: string) => void>();
    expect(await main(['--write'], answering(pinned.registry.prefixes), save)).toBe(0);
    expect(save).not.toHaveBeenCalled();
    expect(await main(['--write'], answering(withoutLast), save)).toBe(0);
    const written = JSON.parse(save.mock.calls[0]?.[0] ?? '{}') as GithubRanges;
    expect(written.registry.prefixes).toEqual([...withoutLast].sort());
  });

  it('with --write, writes nothing GitHub gives that is not a plain IPv4 range of /22 or narrower', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    for (const odd of ['10.0.0.0/8', '2001:db8::/32', '300.1.1.1/32', 'x', '1.2.3.4']) {
      const save = vi.fn<(text: string) => void>();
      expect(await main(['--write'], answering([...pinned.registry.prefixes, odd]), save)).toBe(1);
      expect(save).not.toHaveBeenCalled();
    }
    expect(writablePrefix('20.201.28.151/32')).toBe(true);
    expect(writablePrefix('185.199.108.0/22')).toBe(true);
    expect(writablePrefix('185.199.108.0/21')).toBe(false);
  });

  it('with --write, still fails when a refusal is left after the update: the daily run then emails it', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const save = vi.fn<(text: string) => void>();
    const outside = async (): Promise<LiveRanges> => {
      const live = await answering(pinned.registry.prefixes)();
      return { ...live, addresses: { ...live.addresses, [pinned.registry.host]: ['192.0.2.200'] } };
    };
    expect(await main(['--write'], outside, save)).toBe(1);
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
    expect(rangeDrift(updated, live)).toEqual({ refusals: [], notes: [] });
    expect(rangesText(updated).endsWith('}\n')).toBe(true);
  });
});

describe('the checked-in ranges', () => {
  const ranges = readRanges();

  it('names the day it was last checked, and a host for each group', () => {
    // Where to ask is the code's (`META`), never the file's: a data file that
    // could redirect an outbound call is a different thing from one holding
    // addresses (CodeQL alert 5, PR #33).
    expect(META).toBe('https://api.github.com/meta');
    expect(Object.keys(ranges)).not.toContain('source');
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
