// The whole lint in parts (S201): one typed ESLint run over the whole
// repository passed V8's 6 GB cap and died, so the pre-push hook lints the
// whole one part at a time, each part its own process. The parts are the
// workspace packages (pnpm-workspace.yaml's globs) and the other top-level
// directories, from the files git lists, so a new package or directory is a
// part without anyone listing it. A part with more files than MAX_PART_FILES
// is split by what sits inside it, in name order. A part names directories
// (ESLint walks them with its own ignores) and files (the root's own, or those
// of a directory split for its size).
import { readFileSync } from 'node:fs';

import { parse } from 'yaml';

/** One lint run: what it is called in the log and the paths it names. */
export interface LintPart {
  readonly label: string;
  readonly paths: readonly string[];
}

/**
 * Most files one part lints. Measured S201: at 100 the biggest part (apps/api)
 * peaked at 3.1 GB of heap, against 3.9 GB for apps/api whole; heap grows
 * with the program a part's files pull in, not evenly with their count.
 */
export const MAX_PART_FILES = 100;

/** The workspace globs, such as `apps/*`. */
export function workspaceGlobs(file = 'pnpm-workspace.yaml'): readonly string[] {
  const parsed = parse(readFileSync(file, 'utf8')) as { packages?: readonly string[] } | null;
  return parsed?.packages ?? [];
}

/** The area a file belongs to: its workspace package, else its top-level directory; '' for a root file. */
export function areaOf(file: string, globs: readonly string[]): string {
  const segments = file.split('/');
  if (segments.length === 1) return '';
  for (const glob of globs) {
    const pattern = glob.split('/');
    const matches = pattern.every((part, index) => part === '*' || part === segments[index]);
    if (segments.length > pattern.length && matches) return segments.slice(0, pattern.length).join('/');
  }
  return segments[0] ?? '';
}

/** The files grouped by the key each gets, keys in name order. */
function groupBy(files: readonly string[], key: (file: string) => string): [string, string[]][] {
  const groups = new Map<string, string[]>();
  for (const file of files) {
    const name = key(file);
    groups.set(name, [...(groups.get(name) ?? []), file]);
  }
  return [...groups].sort(([a], [b]) => (a < b ? -1 : 1));
}

/** The first letter of a path's last name, for a part's label. */
const letter = (path: string): string => (path.split('/').at(-1) ?? '').charAt(0).toLowerCase();

/** One part over consecutive entries of a directory, labelled by their first letters. */
function packed(dir: string, entries: readonly string[]): LintPart {
  const first = letter(entries[0] ?? '');
  const last = letter(entries.at(-1) ?? '');
  const letters = first === last ? first : first + '–' + last;
  return { label: `${dir} (${letters})`, paths: entries };
}

/** A directory's files as parts: the directory whole, or split by its entries when it is too big. */
function splitDir(dir: string, files: readonly string[], max: number): LintPart[] {
  if (files.length <= max) return [{ label: dir, paths: [dir] }];
  const entries = groupBy(files, (file) => `${dir}/${file.slice(dir.length + 1).split('/')[0] ?? ''}`);
  const [only] = entries;
  if (entries.length === 1 && only !== undefined && only[1][0] !== only[0]) return splitDir(only[0], files, max);
  const parts: LintPart[] = [];
  let bucket: string[] = [];
  let count = 0;
  const flush = () => {
    if (bucket.length > 0) parts.push(packed(dir, bucket));
    bucket = [];
    count = 0;
  };
  for (const [entry, inside] of entries) {
    if (inside.length > max) {
      flush();
      parts.push(...splitDir(entry, inside, max));
      continue;
    }
    if (count + inside.length > max) flush();
    bucket.push(entry);
    count += inside.length;
  }
  flush();
  return parts;
}

/** The lintable files as parts, in name order, the root's own files first. */
export function lintParts(
  files: readonly string[],
  globs: readonly string[],
  max: number = MAX_PART_FILES,
): readonly LintPart[] {
  return groupBy(files, (file) => areaOf(file, globs)).flatMap(([area, inside]) =>
    area === '' ? [{ label: 'the root files', paths: inside }] : splitDir(area, inside, max),
  );
}
