// `pnpm lint` (Rule Book §5; S201): the whole repository's lint, one part at a
// time (lint-parts.ts), each part its own lint.ts process with a 6 GB heap,
// stopping at the first that fails. One typed ESLint run over the whole passed
// V8's cap and died, on CI's runner as on a laptop, so CI's Lint step and the
// pre-push hook's whole lint take the same parts the same way (pre-push.ts
// uses wholeParts and lintPart from here). The SonarJS findings that only get
// reported (lint.ts) are summed across the parts into one report at the end.
// Files named on the command line are linted in one run, as before.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { lintWith, REPORT_FILE_ENV } from './lint.ts';
import { lintParts, type LintPart, workspaceGlobs } from './lint-parts.ts';

/** What the lint reads: TypeScript and JavaScript sources. */
const LINTED = /\.(?:[cm]?[jt]s|[jt]sx)$/;

/** A git command's output, or a failure naming it. */
function git(args: readonly string[]): string {
  const result = spawnSync('git', [...args], { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`git ${args[0] ?? ''} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

/**
 * The files one whole lint reads, as parts: those git lists, tracked and untracked, deleted ones left out, less
 * those ESLint ignores, so no part names a directory holding only ignored files (ESLint stops on one: "All files
 * matched ... are ignored").
 */
export async function wholeParts(): Promise<readonly LintPart[]> {
  const eslint = lintWith();
  const listed = git(['ls-files', '--cached', '--others', '--exclude-standard', '--deduplicate'])
    .split(String.fromCharCode(10))
    .filter((file) => LINTED.test(file) && existsSync(file));
  const ignored = await Promise.all(listed.map((file) => eslint.isPathIgnored(file)));
  return lintParts(
    listed.filter((_, index) => ignored[index] === false),
    workspaceGlobs(),
  );
}

/**
 * One lint run over the paths, in a process of its own (node itself, no shell: a long file list would pass cmd.exe's
 * line limit), its reported-only counts written to `reportFile` when given: its exit status.
 */
export function lintPart(paths: readonly string[], reportFile?: string): number {
  const result = spawnSync(process.execPath, ['--max-old-space-size=6144', 'tooling/quality/lint.ts', ...paths], {
    stdio: 'inherit',
    windowsHide: true,
    env: reportFile === undefined ? process.env : { ...process.env, [REPORT_FILE_ENV]: reportFile },
  });
  return result.status ?? 1;
}

/** The reported-only counts each part wrote, one JSON list a line, summed by rule, the most first. */
export function summedReport(text: string): readonly (readonly [string, number])[] {
  const counts = new Map<string, number>();
  for (const line of text.split('\n').filter((one) => one.trim() !== '')) {
    for (const [rule, count] of JSON.parse(line) as [string, number][])
      counts.set(rule, (counts.get(rule) ?? 0) + count);
  }
  return [...counts].sort(([a, m], [b, n]) => n - m || (a < b ? -1 : 1));
}

/** The parts in turn, stopping at the first that fails: the failing part's number from 1, or none. */
export function firstFailing(
  parts: readonly LintPart[],
  lint: (paths: readonly string[]) => number,
  log: (line: string) => void,
): number | undefined {
  for (const [index, part] of parts.entries()) {
    log(`Linting part ${index + 1} of ${parts.length}: ${part.label}...`);
    if (lint(part.paths) !== 0) return index + 1;
  }
  return undefined;
}

async function main(files: readonly string[]): Promise<number> {
  if (files.length > 0) return lintPart(files);
  const parts = await wholeParts();
  const dir = mkdtempSync(path.join(tmpdir(), 'agentx-lint-'));
  const reportFile = path.join(dir, 'reported.jsonl');
  try {
    console.log(`Linting the whole repository in ${parts.length} parts.`);
    const failed = firstFailing(parts, (paths) => lintPart(paths, reportFile), console.log);
    const reported = existsSync(reportFile) ? summedReport(readFileSync(reportFile, 'utf8')) : [];
    if (reported.length > 0) {
      console.log('Garbage-code report (SonarJS, not yet blocking), every part together:');
      for (const [rule, count] of reported) console.log(`${String(count).padStart(6)}  ${rule}`);
    }
    if (failed === undefined) return 0;
    console.log(`Lint failed in part ${failed} of ${parts.length} (${parts[failed - 1]?.label ?? ''}).`);
    return 1;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
