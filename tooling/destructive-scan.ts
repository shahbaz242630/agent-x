// S185: the destructive commands the repository's code may run, found by shape.
//
// **Why.** An agent once wrote restore steps that would have deleted staging's live
// Postgres server and its restore points. Code like that reads as ordinary code to a
// reviewer in a hurry, so every line that could destroy something (an Azure delete
// or purge, a REST DELETE, a dropped or truncated table, a DELETE FROM, a Complete
// mode deployment, a compose `down -v`, a recursive remove of a path not written
// out, a forced push) must be named in tooling/destructive-allowed.ts with the
// guard that stops it reaching the wrong thing and the test proving that guard.
// tooling/checks/destructive-commands.test.ts runs this over every tracked file
// (migrations aside: tooling/migration-danger.ts reads those as SQL).
//
// Lines read by shape, not parsed: comments are skipped (codeOf says which),
// everything else is matched, strings included, since an Azure command is a list
// of strings; a REST method split over two lines is read across them. A false hit costs an entry; a missed one could cost the
// server, so the shapes are wide.

/** One kind of destructive command, by name. */
type DangerKind =
  | 'azure-delete'
  | 'rest-delete'
  | 'sql-drop'
  | 'sql-truncate'
  | 'sql-delete'
  | 'complete-mode'
  | 'volumes-down'
  | 'recursive-remove'
  | 'force-push';

/** The list, which quotes each line it names, and this file, whose shapes spell the commands: both run nothing. */
const OWN_FILES = new Set(['tooling/destructive-allowed.ts', 'tooling/destructive-scan.ts']);

/** Files whose comments start with `#`: shell, PowerShell, YAML, Dockerfiles and the git hooks. */
const HASH_COMMENTS = /\.(?:sh|ps1|ya?ml)$|(?:^|\/)Dockerfile[^/]*$|^\.githooks\//;

/**
 * The files read: code and scripts that can run (Dockerfiles, the git hooks, package.json's scripts among them), tests,
 * migrations and the list aside. db/bootstrap's SQL goes through migration-danger.ts's rules instead.
 */
export function isScanned(file: string): boolean {
  if (OWN_FILES.has(file) || file.startsWith('db/migrations/') || /\.test\.[cm]?[jt]sx?$/.test(file)) return false;
  return (
    /\.(?:[cm]?[jt]s|[jt]sx|sh|ps1|ya?ml|bicep)$/.test(file) ||
    /(?:^|\/)(?:Dockerfile[^/]*|package\.json)$/.test(file) ||
    /^\.githooks\/[^/.]+$/.test(file)
  );
}

/** A quoted `delete` or `purge`. */
const WORD = String.raw`['"\x60](?:delete|purge)['"\x60]`;

const SHAPES: readonly (readonly [DangerKind, RegExp])[] = [
  // `delete` or `purge` as a word of an argument list (`'server', 'delete'`, or ending a line or a call), an az line
  // saying one, the Azure SDK's beginDelete, or PowerShell's Remove-Az.
  [
    'azure-delete',
    new RegExp(String.raw`${WORD}\s*(?:,|$)|,\s*${WORD}|\baz\b.*\b(?:delete|purge)\b|\bbeginDelete\w*\(|\bRemove-Az\w`),
  ],
  // Any case, given to a call or a name (`server('delete');`, `const verb = 'DELETE';`), never compared (`=== 'delete'`).
  ['azure-delete', new RegExp(String.raw`(?:\(|(?<![=!<>])=)\s*${WORD}\s*[);]`, 'i')],
  ['rest-delete', /\bmethod\b\W{0,4}delete\b|--method\s+delete\b|(?:\s-X\s*|--request\s+)['"]?delete\b/i],
  ['sql-drop', /\bdrop\s+(?:database|table|schema)\b|\.drop(?:Table|Schema)\(/i],
  // Upper case anywhere; lower case before TABLE, ONLY or a schema's name (`truncate audit.heads`).
  ['sql-truncate', /\bTRUNCATE\b|\btruncate\s+(?:(?:table|only)\b|"?[a-z_]+"?\s*\.)/],
  ['sql-delete', /\.deleteFrom\(|\bDELETE\s+FROM\b|\bdelete from\s+(?:[a-z_]+\.[a-z_]|\$\{|")/],
  ['complete-mode', /\bmode\b\W{0,4}complete\b|--mode\s+complete\b/i],
  ['volumes-down', /\bdown\b\W{1,4}(?:-v|--volumes)\b|['"`]--volumes['"`]/],
  // A recursive remove whose target isn't a string written out in full (a variable, a glob, home): what it removes is
  // decided when it runs.
  [
    'recursive-remove',
    /\brm(?:dir)?(?:Sync)?\((?!\s*['"][^'"`$]*['"]\s*[,)]).*\brecursive\b|(?<![-\w])rm\s+-[\w-]*[rR].*[$*`~]|\bRemove-Item\b.*-Recurse/,
  ],
  ['force-push', /\bpush\b.*(?:--force\b|--force-with-lease\b|\s-f\b|['"]-f['"]|[\s'"]\+[\w/])/],
];

/** A REST method split by prettier: `'--method',` at a line's end and `'DELETE'` starting the next. */
const SPLIT_METHOD = /--method['"`]?\s*,?\s*$/i;
const SPLIT_DELETE = new RegExp(String.raw`^\s*${WORD}`, 'i');

/** One destructive line found. */
export interface Hit {
  readonly file: string;
  readonly line: number;
  readonly kind: DangerKind;
  readonly text: string;
}

/**
 * What of each line is code: a `//` line, a `#` line where `#` comments, a line inside a block comment, and a block
 * comment opening a line are left out; what follows a block comment's close on its line is read. A block comment opened
 * after code on its line isn't followed, so the lines after it are read: more is read, never less.
 */
function codeOf(file: string, lines: readonly string[]): string[] {
  const hashes = HASH_COMMENTS.test(file);
  let inBlock = false;
  return lines.map((line) => {
    let rest = line;
    // Block comments only where the language has them: in a `#` file a line opening `/*` hides nothing after it.
    if (!hashes && !inBlock && /^\s*\/\*/.test(rest)) {
      inBlock = true;
      rest = rest.replace(/^\s*\/\*/, '');
    }
    if (inBlock) {
      const close = rest.indexOf('*/');
      if (close === -1) return '';
      inBlock = false;
      rest = rest.slice(close + 2);
    }
    if (/^\s*\/\//.test(rest) || (hashes && /^\s*#(?!!)/.test(rest))) return '';
    return rest;
  });
}

/** Every destructive line in one file's text. */
export function hitsIn(file: string, text: string): Hit[] {
  const lines = text.split(/\r?\n/);
  const code = codeOf(file, lines);
  return code.flatMap((said, index) => {
    const kinds = new Set(SHAPES.filter(([, shape]) => shape.test(said)).map(([kind]) => kind));
    if (SPLIT_METHOD.test(said) && SPLIT_DELETE.test(code[index + 1] ?? '')) kinds.add('rest-delete');
    return [...kinds].map((kind) => ({ file, line: index + 1, kind, text: (lines[index] ?? '').trim() }));
  });
}

/** One destructive site let through: its line by a piece of its text, the guard it keeps and the test proving it. */
export interface Allowed {
  readonly file: string;
  /** Text the hit's line holds, enough to name that one site. */
  readonly match: string;
  /** An identifier the file holds: the check that stops the command reaching the wrong thing. */
  readonly guard: string;
  /** The test proving the guard: its file and a title it holds. */
  readonly proof: { readonly file: string; readonly title: string };
  /** Why this command may run, in a line. */
  readonly why: string;
  /** How many lines it names: 1 unless said, so a second line of the same text is never let through unseen. */
  readonly lines?: number;
}

/** A line that only looks destructive (a list of method names, a message to a person): named, and why. */
export interface NotACommand {
  readonly file: string;
  readonly match: string;
  readonly why: string;
}

/**
 * Each problem with the hits against the lists: a hit no entry names, an entry naming no line (stale) or another
 * number of lines than it says, an allowed entry whose guard is not in its file, and one whose proof title is not in
 * its proof file. `read` gives a file's text, or undefined when there is none.
 */
export function allowProblems(
  hits: readonly Hit[],
  lists: { readonly allowed: readonly Allowed[]; readonly notCommands: readonly NotACommand[] },
  read: (file: string) => string | undefined,
): string[] {
  const { allowed, notCommands } = lists;
  const every: readonly (Allowed | NotACommand)[] = [...allowed, ...notCommands];
  const named = (entry: Allowed | NotACommand, hit: Hit): boolean =>
    hit.file === entry.file && hit.text.includes(entry.match);
  // One problem a line, its kinds together: a line can be an az delete and a REST DELETE at once.
  const unnamed = new Map<string, Hit[]>();
  for (const hit of hits.filter((one) => !every.some((entry) => named(entry, one)))) {
    const at = `${hit.file}:${String(hit.line)}`;
    unnamed.set(at, [...(unnamed.get(at) ?? []), hit]);
  }
  const unlisted = [...unnamed].map(
    ([at, [first, ...rest]]) =>
      `${at} ${[first, ...rest].map((hit) => hit?.kind).join(', ')} isn't in destructive-allowed.ts: ${first?.text ?? ''}`,
  );
  const counted = every.flatMap((entry) => {
    const found = new Set(hits.filter((hit) => named(entry, hit)).map((hit) => hit.line)).size;
    const said = 'lines' in entry ? (entry.lines ?? 1) : 1;
    if (found === 0) return [`${entry.file} (${entry.match}) names no destructive line: take it out`];
    return found === said
      ? []
      : [`${entry.file} (${entry.match}) names ${String(found)} lines, not ${String(said)}: name each on its own`];
  });
  const guarded = allowed.flatMap((entry) => {
    const where = `${entry.file} (${entry.match})`;
    return [
      ...((read(entry.file) ?? '').includes(entry.guard) ? [] : [`${where}: its guard ${entry.guard} isn't there`]),
      ...((read(entry.proof.file) ?? '').includes(entry.proof.title)
        ? []
        : [`${where}: its proof "${entry.proof.title}" isn't in ${entry.proof.file}`]),
    ];
  });
  return [...unlisted, ...counted, ...guarded];
}
