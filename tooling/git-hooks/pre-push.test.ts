import { execFileSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { commitCount, gitleaksArgs, knownCommit, logRanges, parseRefs, prePush, type Steps } from './pre-push.ts';

const NONE = '0'.repeat(40);
const A = 'a'.repeat(40);
const B = 'b'.repeat(40);
const C = 'c'.repeat(40);

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
    fail: Partial<Record<'gitleaks' | 'typecheck' | 'lint', number | Error>> = {},
    commits: (range: string) => number = () => 1,
  ): Steps & { ran: string[] } => {
    const ran: string[] = [];
    return {
      ran,
      known: () => true,
      commits,
      gitleaks: (range) => {
        ran.push(`gitleaks ${range}`);
        const outcome = fail.gitleaks;
        return outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome ?? 0);
      },
      script: (name) => {
        ran.push(name);
        const outcome = fail[name];
        return typeof outcome === 'number' ? outcome : 0;
      },
    };
  };

  it('scans, then type-checks, then lints, and lets a clean push through', async () => {
    const run = steps();
    expect(await prePush(push, 'origin', run, () => undefined)).toBe(0);
    expect(run.ran).toEqual([`gitleaks ${B}..${A}`, 'typecheck', 'lint']);
  });

  it('does nothing for a push that only deletes', async () => {
    const run = steps();
    expect(await prePush(`(delete) ${NONE} refs/heads/old ${B}`, 'origin', run, () => undefined)).toBe(0);
    expect(run.ran).toEqual([]);
  });

  it.each([
    ['gitleaks', 'gitleaks found something in the commits being pushed', [`gitleaks ${B}..${A}`]],
    ['typecheck', 'the type check failed', [`gitleaks ${B}..${A}`, 'typecheck']],
    ['lint', 'lint failed', [`gitleaks ${B}..${A}`, 'typecheck', 'lint']],
  ] as const)('refuses when %s fails, and stops there', async (step, reason, ran) => {
    const run = steps({ [step]: 1 });
    const said: string[] = [];
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(1);
    expect(run.ran).toEqual(ran);
    expect(said).toEqual([
      `Push refused by the pre-push hook: ${reason}. CI would refuse it too; never skip this with --no-verify.`,
    ]);
  });

  it('skips the scan for a push that adds no commits, and still type-checks and lints', async () => {
    const run = steps({}, () => 0);
    expect(await prePush(push, 'origin', run, () => undefined)).toBe(0);
    expect(run.ran).toEqual(['typecheck', 'lint']);
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
});
