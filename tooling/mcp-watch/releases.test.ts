// 6E4: the daily MCP release watch. Releases and advisories are fixtures shaped
// like GitHub's (their tags as each repository wrote them at S201); seen.json
// and the lockfile are the real files. The positive controls: a fake newer
// release goes red, an SDK advisory covering our pin goes red, and a source
// that can't be read, or whose tags this watch no longer reads, goes red, never
// green.
import { readFileSync } from 'node:fs';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type Advisory,
  installedVersions,
  judgeSdkAdvisories,
  judgeSource,
  main,
  mcpLines,
  parseSeen,
  PRODUCTION_PACKAGES,
  type Release,
  SEEN_FILE,
  type Source,
  SOURCES,
  versionOf,
  watch,
} from './releases.ts';

const readRepo = (file: string): string => readFileSync(file, 'utf8');
const SEEN = parseSeen(JSON.parse(readRepo(SEEN_FILE)));
const source = (key: string): Source => {
  const found = SOURCES.find((each) => each.key === key);
  if (found === undefined) throw new Error(key);
  return found;
};
const seenOf = (key: string) => {
  const found = SEEN.seen.get(key);
  if (found === undefined) throw new Error(key);
  return found;
};
const release = (tag: string, more: Partial<Release> = {}): Release => ({
  tag_name: tag,
  prerelease: false,
  draft: false,
  html_url: `https://github.com/x/y/releases/tag/${tag}`,
  published_at: '2026-11-18T00:00:00Z',
  body: 'Fixed a thing.',
  ...more,
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe('the MCP release watch (6E4)', () => {
  it('has a usable seen.json entry for every source it follows, and nothing else', () => {
    expect(SEEN.errors).toEqual([]);
    expect([...SEEN.seen.keys()]).toEqual(SOURCES.map((each) => each.key));
  });

  it("reads each repository's tags on the line it follows, and no other", () => {
    const on = (key: string, tag: string) => versionOf(source(key), tag)?.numbers;
    expect(on('spec', '2026-07-28')).toEqual([2026, 7, 28]);
    expect(versionOf(source('spec'), '2026-07-28-RC')?.pre).toEqual(['rc']);
    expect(on('typescript-sdk', 'v2.4.0')).toEqual([2, 4, 0]);
    // Its per-package tags and its 1.x line are not the release line.
    expect(on('typescript-sdk', '@modelcontextprotocol/server@2.5.0')).toBeUndefined();
    expect(on('typescript-sdk', '1.32.2')).toBeUndefined();
    expect(on('codex', 'rust-v0.169.1')).toEqual([0, 169, 1]);
    expect(on('codex', 'rusty-v8-v152.2.0')).toBeUndefined();
    expect(on('vscode', '1.146.0')).toEqual([1, 146, 0]);
    expect(on('hermes-agent', 'v0.23.2')).toEqual([0, 23, 2]);
    // Its calendar tags are from before the 0.x line, and would read as newer.
    expect(on('hermes-agent', 'v2026.9.24')).toBeUndefined();
    expect(on('openclaw', 'v2026.11.5')).toEqual([2026, 11, 5]);
  });

  describe('a source against what was seen', () => {
    it('is quiet when nothing is newer, an older line patched later included', () => {
      const releases = [release('v2026.9.37'), release('v2026.11.5'), release('v2026.11.4')];
      expect(judgeSource(source('openclaw'), seenOf('openclaw'), releases)).toEqual({
        errors: [],
        summary: expect.stringContaining('Nothing newer.') as unknown,
      });
    });

    it('goes red on a fake newer release of the SDK (positive control), naming it, its link and the file to move', () => {
      const { errors, summary } = judgeSource(source('typescript-sdk'), seenOf('typescript-sdk'), [
        release('v2.5.0'),
        release('v2.4.1'),
        release('v2.4.0'),
        release('@modelcontextprotocol/server@2.6.0'),
      ]);
      expect(errors).toHaveLength(1);
      expect(errors[0]).toMatch(
        /^the official TypeScript SDK has 2 newer releases than the v2\.4\.0 last seen, up to v2\.5\.0 /,
      );
      expect(errors[0]).toContain('https://github.com/x/y/releases/tag/v2.5.0');
      expect(errors[0]).toContain(`move "typescript-sdk" in ${SEEN_FILE} to v2.5.0, with a note`);
      expect(summary).toContain('| red | [v2.5.0]');
      expect(summary).not.toContain('2.6.0');
    });

    it('goes red on a new dated revision of the specification, and on its candidate first', () => {
      const candidate = judgeSource(source('spec'), seenOf('spec'), [
        release('2027-03-01-RC', { prerelease: true }),
        release('2026-07-28'),
      ]);
      expect(candidate.errors[0]).toContain('up to 2027-03-01-RC');
      expect(candidate.errors[0]).toContain('read its changelog, check MCP-Guide.md §2');
      expect(judgeSource(source('spec'), seenOf('spec'), [release('2027-03-01')]).errors).toHaveLength(1);
      // A seen candidate, then its release: newer.
      const seenRc = { version: '2027-03-01-RC', note: 'read' };
      expect(judgeSource(source('spec'), seenRc, [release('2027-03-01')]).errors).toHaveLength(1);
    });

    it('leaves out drafts and, where the line has none, pre-releases', () => {
      const releases = [
        release('v2.5.0', { draft: true }),
        release('v2.6.0-beta.1', { prerelease: true }),
        release('v2.4.0'),
      ];
      expect(judgeSource(source('typescript-sdk'), seenOf('typescript-sdk'), releases).errors).toEqual([]);
      const canary = release('v0.24.0+canary.1', { prerelease: true });
      expect(judgeSource(source('hermes-agent'), seenOf('hermes-agent'), [canary, release('v0.23.2')]).errors).toEqual(
        [],
      );
    });

    it('turns a busy client red only when a newer release names MCP, listing every newer one either way', () => {
      const quiet = judgeSource(source('claude-code'), seenOf('claude-code'), [
        release('v2.1.327', { body: 'Faster startup.\nFixed a crash.' }),
      ]);
      expect(quiet.errors).toEqual([]);
      expect(quiet.summary).toContain('| report only | [v2.1.327]');
      const loud = judgeSource(source('claude-code'), seenOf('claude-code'), [
        release('v2.1.328', { body: '- Fixed MCP OAuth refresh | on <b>Windows</b>\n- Other' }),
        release('v2.1.327', { body: 'Nothing here.' }),
      ]);
      expect(loud.errors).toHaveLength(1);
      expect(loud.summary).toContain('Fixed MCP OAuth refresh \\| on &lt;b&gt;Windows&lt;/b&gt;');
      expect(loud.summary).toContain('| report only | [v2.1.327]');
    });

    it('turns VS Code red on a new minor alone', () => {
      const patch = judgeSource(source('vscode'), seenOf('vscode'), [release('1.146.1')]);
      expect(patch.errors).toEqual([]);
      expect(judgeSource(source('vscode'), seenOf('vscode'), [release('1.147.0')]).errors).toHaveLength(1);
      expect(judgeSource(source('vscode'), seenOf('vscode'), [release('2.0.0')]).errors).toHaveLength(1);
    });

    it("goes red when none of a repository's releases is on the followed line: its tags may have changed", () => {
      const { errors } = judgeSource(source('codex'), seenOf('codex'), [
        release('codex-v1.0.0'),
        release('rusty-v8-v1.0.0'),
      ]);
      expect(errors).toHaveLength(1);
      expect(errors[0]).toContain('may have changed how it tags releases');
      expect(judgeSource(source('codex'), seenOf('codex'), []).errors).toHaveLength(1);
      expect(judgeSource(source('codex'), seenOf('codex'), [{}]).errors).toHaveLength(1);
    });

    it('goes red on every source in the positive control, which judges against nothing seen', () => {
      const { errors, summary } = judgeSource(
        source('openclaw'),
        seenOf('openclaw'),
        [release('v2026.11.5', { body: 'MCP' })],
        true,
      );
      expect(errors[0]).toContain('than nothing seen (the positive control)');
      expect(summary).toContain('Positive control');
    });
  });

  it("picks at most three of a release's lines naming MCP, each cut short", () => {
    expect(mcpLines(null)).toEqual([]);
    expect(mcpLines('* MCP one\n## mcp two\nnot this: MCPs\n- MCP three\n- MCP four')).toEqual([
      'MCP one',
      'mcp two',
      'MCP three',
    ]);
    expect(mcpLines(`MCP ${'x'.repeat(300)}`)[0]).toHaveLength(161);
  });

  describe('seen.json read', () => {
    it("goes red on a missing map, a source without an entry, a version off its line, no note, or one it doesn't follow", () => {
      expect(parseSeen(null).errors).toHaveLength(1);
      expect(parseSeen({ seen: [] }).errors).toHaveLength(1);
      const entries = Object.fromEntries([...SEEN.seen.entries()]);
      expect(parseSeen({ seen: { ...entries, spec: undefined } }).errors[0]).toContain('"spec"');
      expect(parseSeen({ seen: { ...entries, codex: { version: 'v0.169.1', note: 'x' } } }).errors[0]).toContain(
        '"codex"',
      );
      expect(parseSeen({ seen: { ...entries, vscode: { version: '1.146.0', note: ' ' } } }).errors[0]).toContain(
        '"vscode"',
      );
      expect(parseSeen({ seen: { ...entries, cursor: { version: '1', note: 'x' } } }).errors).toEqual([
        `${SEEN_FILE} names cursor, which this watch doesn't follow. Remove them.`,
      ]);
    });
  });

  describe("the SDK's advisories", () => {
    /** The SDK's advisories as published at S201 (GHSA-jm63's fix is in 2.3.0), less their prose. */
    const ADVISORIES: Advisory[] = [
      {
        ghsa_id: 'GHSA-jm63-cq47-j5jp',
        summary: "Shared transport or server instances delivered one HTTP client's messages to another",
        severity: 'high',
        html_url: 'https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-jm63-cq47-j5jp',
        vulnerabilities: [
          {
            package: { name: '@modelcontextprotocol/server' },
            vulnerable_version_range: '>= 2.0.0, < 2.3.0',
            patched_versions: '2.3.0',
          },
        ],
      },
      {
        ghsa_id: 'GHSA-6prh-2h8m-c8cw',
        severity: 'medium',
        vulnerabilities: [
          {
            package: { name: '@modelcontextprotocol/sdk' },
            vulnerable_version_range: '< 1.32.0',
            patched_versions: '1.32.0',
          },
          {
            package: { name: '@modelcontextprotocol/client' },
            vulnerable_version_range: '>= 2.0.0, < 2.3.0',
            patched_versions: '2.3.0',
          },
        ],
      },
      {
        ghsa_id: 'GHSA-wwww-wwww-wwww',
        withdrawn_at: '2026-10-01T00:00:00Z',
        vulnerabilities: [{ package: { name: '@modelcontextprotocol/core' }, vulnerable_version_range: '< 9.0.0' }],
      },
    ];
    const ours = installedVersions(readRepo('pnpm-lock.yaml'));

    it("reads the versions the API runs from the lockfile: the server's and its core's", () => {
      const server = JSON.parse(readRepo('apps/api/package.json')) as { dependencies: Record<string, string> };
      expect(ours.get('@modelcontextprotocol/server')).toEqual([server.dependencies['@modelcontextprotocol/server']]);
      expect(ours.get('@modelcontextprotocol/core')?.length).toBe(1);
    });

    it("is quiet on our pin, whose advisories are fixed, and leaves out the client's and withdrawn ones", () => {
      const { errors, summary } = judgeSdkAdvisories(ADVISORIES, ours, false);
      expect(errors).toEqual([]);
      expect(summary).toContain('3 published advisories: 0 apply');
    });

    it('goes red on an advisory covering the version the API runs (positive control), any severity', () => {
      const old = new Map(PRODUCTION_PACKAGES.map((name) => [name, ['2.2.0']]));
      const { errors, summary } = judgeSdkAdvisories(ADVISORIES, old, true);
      expect(errors).toHaveLength(1);
      expect(errors[0]).toMatch(
        /^Positive control: @modelcontextprotocol\/server 2\.2\.0 \(not what the API runs\) is covered by the SDK's high-severity advisory GHSA-jm63-cq47-j5jp/,
      );
      expect(errors[0]).toContain('2.3.0 or later');
      expect(summary).toContain('| red | GHSA-jm63-cq47-j5jp |');
      const medium: Advisory = {
        ghsa_id: 'GHSA-m',
        severity: 'medium',
        vulnerabilities: [{ package: { name: '@modelcontextprotocol/core' }, vulnerable_version_range: '< 3.0.0' }],
      };
      const real = judgeSdkAdvisories([medium], ours, false).errors;
      expect(real).toHaveLength(1);
      expect(real[0]).toContain(
        "which the API's MCP server runs, is covered by the SDK's medium-severity advisory GHSA-m",
      );
      expect(real[0]).toContain('none yet: read the advisory for a workaround');
    });

    it("goes red on a range it can't read, or when no pinned version is found", () => {
      const odd: Advisory = {
        ghsa_id: 'GHSA-o',
        vulnerabilities: [
          { package: { name: '@modelcontextprotocol/server' }, vulnerable_version_range: 'all of 2.x' },
        ],
      };
      expect(judgeSdkAdvisories([odd], ours, false).errors[0]).toContain(
        "gives an affected range this watch can't read",
      );
      expect(judgeSdkAdvisories([], new Map(), false).errors[0]).toContain('The lockfile names no version');
    });
  });

  describe('the whole watch, and its command line', () => {
    const releasesOf: Record<string, Release[]> = {
      'modelcontextprotocol/modelcontextprotocol': [release('2026-07-28')],
      'modelcontextprotocol/typescript-sdk': [release('v2.4.0')],
      'modelcontextprotocol/conformance': [release('v0.1.16')],
      'anthropics/claude-code': [release('v2.1.326')],
      'openai/codex': [release('rust-v0.169.1')],
      'microsoft/vscode': [release('1.146.0')],
      'google-gemini/gemini-cli': [release('v0.68.0')],
      'NousResearch/hermes-agent': [release('v0.23.2')],
      'openclaw/openclaw': [release('v2026.11.5')],
    };
    const github = (overrides: Record<string, unknown> = {}) =>
      vi.fn((url: string, init: { headers: Record<string, string> }) => {
        expect(init.headers.authorization).toBe('Bearer t');
        const path = new URL(url).pathname.replace(/^\/repos\//, '');
        // A repository's releases by its name; the SDK's advisories by their own path.
        const repo = path.replace(/\/releases$/, '');
        const body = overrides[repo] ?? (path.endsWith('security-advisories') ? [] : releasesOf[repo]);
        if (body instanceof Error) return Promise.reject(body);
        if (typeof body === 'number') return Promise.resolve(new Response('{}', { status: body }));
        return Promise.resolve(Response.json(body));
      });

    it('is quiet when every source is as seen and no advisory covers our pin', async () => {
      const fetcher = github();
      const verdict = await watch({ read: readRepo, fetcher, token: 't' });
      expect(verdict.errors).toEqual([]);
      // Nine sources and the advisories.
      expect(fetcher).toHaveBeenCalledTimes(SOURCES.length + 1);
    });

    it("goes red on a source or the advisories it can't read, on an answer that isn't a list, and on the controls", async () => {
      const unreadable = github({
        'openai/codex': new Error('socket hang up'),
        'microsoft/vscode': 502,
        'openclaw/openclaw': { message: 'moved' },
        'modelcontextprotocol/typescript-sdk/security-advisories': 403,
      });
      const { errors } = await watch({ read: readRepo, fetcher: unreadable, token: 't' });
      expect(errors).toHaveLength(4);
      expect(errors[0]).toContain("OpenAI Codex's releases (openai/codex) could not be read today (socket hang up)");
      expect(errors[1]).toContain('(GitHub answered 502)');
      expect(errors[2]).toContain('(GitHub answered with no list)');
      expect(errors[3]).toContain(
        "The TypeScript SDK's security advisories could not be read today (GitHub answered 403)",
      );
      const unseen = await watch({ read: readRepo, fetcher: github(), token: 't', unseen: true });
      // Every source with a release on its line (the clients whose notes don't name MCP are listed, not red).
      expect(unseen.errors.length).toBeGreaterThanOrEqual(4);
      const advisory = [
        {
          ghsa_id: 'GHSA-x',
          vulnerabilities: [{ package: { name: '@modelcontextprotocol/server' }, vulnerable_version_range: '< 2.3.0' }],
        },
      ];
      const control = await watch({
        read: readRepo,
        fetcher: github({ 'modelcontextprotocol/typescript-sdk/security-advisories': advisory }),
        token: 't',
        serverVersion: '2.2.0',
      });
      expect(control.errors).toEqual([expect.stringContaining('Positive control: @modelcontextprotocol/server 2.2.0')]);
    });

    it('goes red on a broken seen.json, judging the sources it can still read', async () => {
      const read = (file: string) =>
        file === SEEN_FILE ? JSON.stringify({ seen: { spec: { version: '2026-07-28', note: 'x' } } }) : readRepo(file);
      const { errors } = await watch({ read, fetcher: github(), token: 't' });
      expect(errors).toHaveLength(SOURCES.length - 1);
    });

    it('main: 0 when quiet, 1 when red, passing the controls on', async () => {
      vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      expect(await main([], { GH_TOKEN: 't' }, github())).toBe(0);
      const advisory = [
        {
          ghsa_id: 'GHSA-x',
          vulnerabilities: [{ package: { name: '@modelcontextprotocol/server' }, vulnerable_version_range: '< 2.3.0' }],
        },
      ];
      const fetcher = github({ 'modelcontextprotocol/typescript-sdk/security-advisories': advisory });
      expect(await main(['--server-version', 'v2.2.0'], { GH_TOKEN: 't' }, fetcher)).toBe(1);
      expect(await main(['--control-unseen'], { GH_TOKEN: 't' }, github())).toBe(1);
    });
  });
});
