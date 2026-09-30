// Names that must never reach the public repository (Rule Book §7; the S68
// audit): the staging domain, which slipped into one commit's comment (#112)
// and stays in the history. The names themselves are never written here: the
// pre-commit hook reads them from `.tools/private-names` (one a line; `.tools/`
// is never committed), and CI from the repository variable STAGING_APP_ORIGIN,
// whose host's registrable part it takes (`app.example.com` gives
// `example.com`). A match is reported by file and line, never by the text.
import { existsSync, readFileSync } from 'node:fs';

/** Where the hook reads the names on a developer's machine. */
const PRIVATE_NAMES_FILE = '.tools/private-names';

/** The shortest name checked: a shorter one would match ordinary words. */
const SHORTEST = 6;

/** The registrable part of an origin's host: its last two labels (`app.example.com` gives `example.com`). */
export function domainOf(origin: string): string | undefined {
  if (!URL.canParse(origin)) return undefined;
  const labels = new URL(origin).hostname.split('.').filter((label) => label !== '');
  return labels.length >= 2 ? labels.slice(-2).join('.') : undefined;
}

/**
 * The private names known here, in lower case: the lines of `file` (blank
 * lines and `#` comments aside) and the domain of `origin`. Names shorter than
 * 6 characters are dropped: they would match ordinary text.
 */
export function privateNames({
  fileText,
  origin,
}: {
  readonly fileText?: string | undefined;
  readonly origin?: string | undefined;
}): string[] {
  const fromFile = (fileText ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'));
  const fromOrigin = origin === undefined || origin === '' ? [] : [domainOf(origin)];
  return [
    ...new Set(
      [...fromFile, ...fromOrigin]
        .filter((name): name is string => name !== undefined && name.length >= SHORTEST)
        .map((name) => name.toLowerCase()),
    ),
  ];
}

/** The private names this process knows: the file, if there is one, and STAGING_APP_ORIGIN, if set. */
export function knownPrivateNames(env: NodeJS.ProcessEnv = process.env): string[] {
  const fileText = existsSync(PRIVATE_NAMES_FILE) ? readFileSync(PRIVATE_NAMES_FILE, 'utf8') : undefined;
  return privateNames({ fileText, origin: env.STAGING_APP_ORIGIN });
}

/** The 1-based lines of `text` holding any of `names`, whatever their case. */
export function linesNaming(text: string, names: readonly string[]): number[] {
  if (names.length === 0) return [];
  const lines: number[] = [];
  text.split('\n').forEach((line, index) => {
    const lower = line.toLowerCase();
    if (names.some((name) => lower.includes(name))) lines.push(index + 1);
  });
  return lines;
}
