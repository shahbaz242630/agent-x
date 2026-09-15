import { describe, expect, it } from 'vitest';

import { gitleaksArgs, logRanges, parseRefs, prePush, type Steps } from './pre-push.ts';

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
      ),
    ).toEqual([`${B}..${A}`, `${C} --not --remotes=origin`]);
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
  ): Steps & { ran: string[] } => {
    const ran: string[] = [];
    return {
      ran,
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

  it('refuses when gitleaks cannot run, and says how to install it', async () => {
    const said: string[] = [];
    const run = steps({ gitleaks: new Error('offline') });
    expect(await prePush(push, 'origin', run, (line) => said.push(line))).toBe(1);
    expect(said[0]).toContain('gitleaks could not run (offline); run corepack pnpm hooks');
  });
});
