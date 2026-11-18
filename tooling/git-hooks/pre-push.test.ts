import { execFileSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import type { LintPart } from '../quality/lint-parts.ts';

import {
  changedFiles,
  commitCount,
  gitleaksArgs,
  knownCommit,
  lintTargets,
  logRanges,
  parseRefs,
  prePush,
  type Steps,
} from './pre-push.ts';

const NONE = '0'.repeat(40);
const A = 'a'.repeat(40);
const B = 'b'.repeat(40);
const C = 'c'.repeat(40);
const PARTS: readonly LintPart[] = [
  { label: 'the root files', paths: ['a.ts', 'b.js'] },
  { label: 'apps/api', paths: ['apps/api'] },
  { label: 'tooling', paths: ['tooling'] },
];

describe("reading git's list of refs being pushed", () => {
  it('reads one ref per line and ignores blank or partial lines', () => {
    const stdin = [
      `refs/heads/x ${A} refs/heads/x ${B}`,
      '',
      'garbage',
      `refs/heads/y ${C} refs/heads/y ${NONE}`,
      '',
    ].join(String.fromCharCode(10));
    expect(parseRefs(stdin)).toEqual([
      { localRef: 'refs/heads/x', localSha: A, remoteRef: 'refs/heads/x', remoteSha: B },
      { localRef: 'refs/heads/y', localSha: C, remoteRef: 'refs/heads/y', remoteSha: NONE },
    ]);
  });
});

describe('the commits a push adds', () => {
  it('scans after the remote commit, a new branch against everything the remote has, and skips a deletion', () => {
    expect(
      logRanges(
        [
          { localRef: 'refs/heads/x', localSha: A, remoteRef: 'refs/heads/x', remoteSha: B },
          { localRef: 'refs/heads/new', localSha: C, remoteRef: 'refs/heads/new', remoteSha: NONE },
          { localRef: '(delete)', localSha: NONE, remoteRef: 'refs/heads/old', remoteSha: B },
        ],
        'origin',
        () => true,
      ),
    ).toEqual([`${B}..${A}`, `${C} --not --remotes=origin`]);
  });

  it("scans everything the remote hasn't got when this clone lacks the remote's commit (the branch moved on GitHub)", () => {
    const ref = { localRef: 'refs/heads/x', localSha: A, remoteRef: 'refs/heads/x', remoteSha: B };
    expect(logRanges([ref], 'origin', (sha) => sha !== B)).toEqual([`${A} --not --remotes=origin`]);
  });

  it('asks git whether a commit is here, and how many commits a range names, refusing a range it cannot read', () => {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const absent = '0123456789abcdef0123456789abcdef01234567';
    expect(knownCommit(head)).toBe(true);
    expect(knownCommit(absent)).toBe(false);
    expect(commitCount(`${head}..${head}`)).toBe(0);
    expect(commitCount(`${head} --not ${head}`)).toBe(0);
    expect(() => commitCount(`${absent}..${head}`)).toThrow('git rev-list failed');
  });

  it('runs gitleaks as CI does, on the repository and with its rules, redacting what it finds', () => {
    expect(gitleaksArgs(`${B}..${A}`)).toEqual([
      'git',
      '--no-banner',
      '--redact',
      '--config',
      '.gitleaks.toml',
      '--log-opts',
      `${B}..${A}`,
      '.',
    ]);
  });
});

describe('the hook', () => {
  const push = `refs/heads/x ${A} refs/heads/x ${B}`;

  /** Steps that succeed unless told otherwise, recording the order they ran in. */
  const steps = (
    fail: Partial<Record<'gitleaks' | 'typecheck' | 'lint', number | Error>> & { lintPath?: string } = {},
    commits: (range: string) => number = () => 1,
    changed: () => readonly string[] | undefined = () => ['a.ts'],
    parts: () => Promise<readonly LintPart[]> = () => Promise.resolve(PARTS),
  ): Steps & { ran: string[] } => {
    const ran: string[] = [];
    const outcome = (name: 'typecheck' | 'lint') => {
      const set = fail[name];
      return typeof set === 'number' ? set : 0;
    };
    return {
      ran,
      known: () => true,
      commits,
      gitleaks: (range) => {
        ran.push(`gitleaks ${range}`);
        const set = fail.gitleaks;
        return set instanceof Error ? Promise.reject(set) : Promise.resolve(set ?? 0);
      },
      typecheck: () => {
        ran.push('typecheck');
        return outcome('typecheck');
      },
      changed,
      parts,
      lint: (paths) => {
        ran.push(`lint ${paths.join(' ')}`);
        return paths.includes(String(fail.lintPath)) ? 1 : outcome('lint');
      },
    };
  };

  it('scans, then type-checks, then lints, and lets a clean push through', async () => {
    const run = steps();
    expect(await prePush(push, 'origin', run, () => undefined)).toBe(0);
    expect(run.ran).toEqual([`gitleaks ${B}..${A}`, 'typecheck', 'lint a.ts']);
  });

  it('does nothing for a push that only deletes', async () => {
    const run = steps();
    expect(await prePush(`(delete) ${NONE} refs/heads/old ${B}`, 'origin', run, () => undefined)).toBe(0);
    expect(run.ran).toEqual([]);
  });

  it.each([
    ['gitleaks', 'gitleaks found something in the commits being pushed', [`gitleaks ${B}..${A}`]],
    ['typecheck', 'the type check failed', [`gitleaks ${B}..${A}`, 'typecheck']],
    ['lint', 'lint failed', [`gitleaks ${B}..${A}`, 'typecheck', 'lint a.ts']],
  ] as const)('refuses when %s fails, and stops there', async (step, reason, ran) => {
    const run = steps({ [step]: 1 });
    const said: string[] = [];
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(1);
    expect(run.ran).toEqual(ran);
    expect(said.at(-1)).toBe(
      `Push refused by the pre-push hook: ${reason}. CI would refuse it too; never skip this with --no-verify.`,
    );
  });

  it('skips the scan for a push that adds no commits, and still type-checks and lints', async () => {
    const run = steps({}, () => 0);
    expect(await prePush(push, 'origin', run, () => undefined)).toBe(0);
    expect(run.ran).toEqual(['typecheck', 'lint a.ts']);
  });

  it('refuses a push whose commits git cannot read, rather than pass it unscanned', async () => {
    const said: string[] = [];
    const run = steps({}, () => {
      throw new Error('git rev-list failed: bad revision');
    });
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(1);
    expect(run.ran).toEqual([]);
    expect(said[0]).toContain(
      "git can't read the commits being pushed (git rev-list failed: bad revision); fetch, then push again",
    );
  });

  it('refuses when gitleaks cannot run, and says how to install it', async () => {
    const said: string[] = [];
    const run = steps({ gitleaks: new Error('offline') });
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(1);
    expect(said[0]).toContain('gitleaks could not run (offline); run corepack pnpm hooks');
  });

  it('lints the whole repository in parts, one run each, when git cannot say what changed', async () => {
    const said: string[] = [];
    const run = steps(
      {},
      () => 1,
      () => undefined,
    );
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(0);
    expect(run.ran).toEqual([`gitleaks ${B}..${A}`, 'typecheck', 'lint a.ts b.js', 'lint apps/api', 'lint tooling']);
    expect(said).toEqual([
      'Linting the whole repository in 3 parts (the lint setup changed, or git could not say what changed).',
      'Linting part 1 of 3: the root files...',
      'Linting part 2 of 3: apps/api...',
      'Linting part 3 of 3: tooling...',
    ]);
  });

  it('stops at the first part that fails, and names it', async () => {
    const said: string[] = [];
    const run = steps(
      { lintPath: 'apps/api' },
      () => 1,
      () => ['package.json'],
    );
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(1);
    expect(run.ran).toEqual([`gitleaks ${B}..${A}`, 'typecheck', 'lint a.ts b.js', 'lint apps/api']);
    expect(said.at(-1)).toBe(
      'Push refused by the pre-push hook: lint failed in part 2 (apps/api). CI would refuse it too; never skip this with --no-verify.',
    );
  });

  it('refuses when the files for the whole lint cannot be listed', async () => {
    const said: string[] = [];
    const run = steps(
      {},
      () => 1,
      () => undefined,
      () => Promise.reject(new Error('git ls-files failed: boom')),
    );
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(1);
    expect(run.ran).toEqual([`gitleaks ${B}..${A}`, 'typecheck']);
    expect(said.at(-1)).toContain('the files to lint could not be listed (git ls-files failed: boom)');
  });

  it('skips the lint when no changed file is one it reads, and says CI lints the whole', async () => {
    const said: string[] = [];
    const run = steps(
      {},
      () => 1,
      () => ['README.md'],
    );
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(0);
    expect(run.ran).toEqual([`gitleaks ${B}..${A}`, 'typecheck']);
    expect(said).toEqual(['No changed files to lint; CI lints the whole repository.']);
  });

  it('says how many changed files it lints', async () => {
    const said: string[] = [];
    const run = steps(
      {},
      () => 1,
      () => ['a.ts', 'b.tsx'],
    );
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(0);
    expect(said).toEqual(['Linting the 2 changed file(s); CI lints the whole repository.']);
  });
});

describe('what the lint reads', () => {
  it('is the whole repository when git could not say what changed', () => {
    expect(lintTargets(undefined)).toBe('all');
  });

  it.each([
    'eslint.config.js',
    'eslint.quality.config.js',
    'tooling/quality/lint.ts',
    'package.json',
    'apps/console/package.json',
    'pnpm-lock.yaml',
    'tsconfig.json',
    'apps/console/tsconfig.app.json',
  ])('is the whole repository when %s changed', (path) => {
    expect(lintTargets(['a.ts', path])).toBe('all');
  });

  it('is the changed script files alone otherwise', () => {
    expect(
      lintTargets(['a.ts', 'b.tsx', 'c.js', 'd.mjs', 'e.cjs', 'f.jsx', 'g.mts', 'README.md', 'x.css', 'y.sql']),
    ).toEqual(['a.ts', 'b.tsx', 'c.js', 'd.mjs', 'e.cjs', 'f.jsx', 'g.mts']);
  });

  it('keeps a near name that is not the lint setup', () => {
    expect(lintTargets(['docs/eslint.config.js.md', 'apps/x/eslint.config.ts', 'tooling/qualityx/a.ts'])).toEqual([
      'apps/x/eslint.config.ts',
      'tooling/qualityx/a.ts',
    ]);
  });
});

describe('the changed files', () => {
  it('is undefined when git cannot find where the branch left the base', () => {
    expect(changedFiles('refs/heads/no-such-branch-s200')).toBeUndefined();
  });

  it('lists the working tree against a commit git has, sorted and without repeats', () => {
    const files = changedFiles('HEAD');
    expect(files).toBeDefined();
    expect(files).toEqual([...new Set(files)].sort());
  });
});
