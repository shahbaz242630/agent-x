// The release workflow's last word (AZ5, review S190): whether staging got this
// merge, or why not, so a merge whose release never ran is never taken for done.
//
//   node deploy/azure/landed.ts <commit> <release job's result>
//
// The approved infrastructure deploy shares the release's concurrency group, so
// the two never write the apps at once. GitHub keeps one job waiting in a group
// and cancels an older waiting one, grey, not red: a merge's release can be
// cancelled while another merge's deploy waits for the partner's Approve. That is
// sound only when a newer merge's release covers it. So this run:
// - its release succeeded: says so
// - it didn't, and a newer commit is on main: says that run's release covers this
//   one (and that run says the same of itself, the newest red when it didn't land)
// - it didn't, and this is main's newest: fails red, staging behind main
import { SOURCE_REPOSITORY } from '../image/verify.ts';

const COMMIT = /^[0-9a-f]{40}$/;

/** Main's newest commit, from GitHub (public: no credential needed). */
export type NewestOnMain = () => Promise<string>;

/** What the run ends with: the words, and whether it is red. */
export interface Landed {
  readonly red: boolean;
  readonly line: string;
}

/** The verdict for a run of `commit` whose release job ended `result`. */
export async function landed(commit: string, result: string, newest: NewestOnMain): Promise<Landed> {
  if (result === 'success') return { red: false, line: `Staging runs ${commit}: its release succeeded.` };
  const head = await newest();
  if (!COMMIT.test(head)) {
    return {
      red: true,
      line: `This merge's release ended ${result || 'unrun'}, and main's newest commit couldn't be read: staging may be behind main. Re-run the release workflow for main's newest commit.`,
    };
  }
  if (head !== commit) {
    return {
      red: false,
      line: `This merge's release ended ${result || 'unrun'}, and main has moved on to ${head}: that run's release covers this one, and says whether it landed.`,
    };
  }
  return {
    red: true,
    line: `This merge is main's newest, and its release ended ${result || 'unrun'}: staging is behind main. Read the infrastructure and release jobs above (an Approve not given, or a red step), fix that, and re-run this workflow.`,
  };
}

/** GitHub's answer for main's newest commit, or nothing it could read. */
export const realNewest: NewestOnMain = async () => {
  try {
    const response = await fetch(`https://api.github.com/repos/${SOURCE_REPOSITORY}/commits/main`, {
      headers: { accept: 'application/vnd.github+json' },
      signal: AbortSignal.timeout(30_000),
    });
    const body = (await response.json()) as { sha?: unknown };
    return response.ok && typeof body.sha === 'string' ? body.sha : '';
  } catch {
    return '';
  }
};

/** The command, its words printed as GitHub annotations: an error when red, a notice otherwise. */
export async function main(
  argv: readonly string[],
  newest: NewestOnMain = realNewest,
  say: (line: string) => void = console.log,
): Promise<number> {
  const [commit = '', result = ''] = argv;
  if (!COMMIT.test(commit)) {
    say('Usage: node deploy/azure/landed.ts <commit> <release job result>');
    return 2;
  }
  const verdict = await landed(commit, result, newest);
  say(`::${verdict.red ? 'error' : 'notice'}::${verdict.line}`);
  return verdict.red ? 1 : 0;
}

if (import.meta.main) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
