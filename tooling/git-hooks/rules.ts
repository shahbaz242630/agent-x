// What must never reach the repository, checked on the staged lines before a
// commit (pre-commit.ts) and on every tracked file in CI
// (tooling/checks/repo-text.test.ts), so a skipped hook lets nothing through:
// - a secret or key: private keys, provider tokens, key files, env files
// - the internal documents (Documents/)
// - text the secret scanners take for a secret (S4, S10): each such find
//   forced a fresh PR to clear the history
// - invisible characters an editor slipped into source (S5, S10)
// Messages name the rule and the place, never the matched text.

export type RuleId =
  'forbidden-file' | 'private-key' | 'provider-token' | 'scanner-bait' | 'placeholder-message' | 'invisible-character';

export interface Problem {
  readonly rule: RuleId;
  readonly file: string;
  /** 1-based; absent for a problem with the file itself. */
  readonly line?: number;
  readonly message: string;
}

/** Paths that must never be committed, whatever they hold. Case-insensitive: so is Windows. */
const FORBIDDEN_PATHS: readonly { readonly pattern: RegExp; readonly message: string }[] = [
  { pattern: /^Documents(?:\/|$)/i, message: 'the internal documents never go to git (Rule Book §7)' },
  { pattern: /(?:^|\/)\.env(?:\.(?!example$)[^/]+)?$/i, message: 'an env file holds local secrets' },
  { pattern: /\.(?:pem|key|p12|pfx|jks|keystore|pat)$/i, message: 'a key, certificate store or access-token file' },
  { pattern: /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)$/i, message: 'a private SSH key' },
  {
    // The hooks run these by name from the repository root, and Windows looks in the current folder first.
    pattern: /^(?:git|node|corepack|pnpm|npm|npx|tar|gitleaks|sh|bash)(?:\.[^/]+)?$/i,
    message: 'a root file named like a tool the hooks run: Windows would run it instead of the real one',
  },
];

// Built from pieces, so this file never holds text that looks like what it finds.
const DASHES = '-'.repeat(5);
const PRIVATE_KEY = new RegExp(`${DASHES}BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?${DASHES}`);

/** Token formats whose shape alone gives them away. */
const PROVIDER_TOKENS: readonly { readonly name: string; readonly pattern: RegExp }[] = [
  { name: 'a GitHub token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{80,255})\b/ },
  { name: 'an AWS access key', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { name: 'a Google API key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'a Slack token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { name: 'a Stripe live key', pattern: /\b[rs]k_live_[0-9A-Za-z]{20,}\b/ },
  { name: 'an npm token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'an Azure storage key', pattern: /AccountKey=[A-Za-z0-9+/]{40,}={0,2}/ },
  { name: 'a JSON web token', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
];

/**
 * A name that says "secret" given a random-looking literal: the shape gitleaks
 * and GitGuardian report even when the value is a harmless test vector (PR #15,
 * S10). Name test values after what they are, or build them when the test runs.
 */
const SECRET_NAMED_LITERAL =
  /\b[A-Za-z0-9_]*(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|credential)[A-Za-z0-9_]*\s*[:=]\s*(['"`])([A-Za-z0-9+/_.=-]{10,})\1/gi;

/**
 * A name that says "password" given a bare camelCase variable, which
 * GitGuardian read as the password itself (a test's login variable, PR #23,
 * S13). It passed over dotted paths, calls, names in capitals and variables
 * named for a secret. Written case by case, so the value's capitals still
 * count.
 */
const PASSWORD_NAMED_IDENTIFIER =
  /\b([A-Za-z0-9_]*[Pp][Aa][Ss][Ss][Ww](?:[Oo][Rr])?[Dd][A-Za-z0-9_]*)\s*:\s*([a-z][a-z0-9]*[A-Z][A-Za-z0-9]*)\s*(?:[,;})]|$)/g;
const NAMED_FOR_A_SECRET = /passw(?:or)?d|secret|token|key/i;
/** A key that holds where a password is, not the password: `AGENTX_DB_PASSWORD_FILE`. */
const NAMES_A_PLACE = /(?:file|path)$/i;

/** A required-variable placeholder with a message, which GitGuardian paired with a user name (PR #16, S10). */
const PLACEHOLDER_WITH_MESSAGE = /\$\{[A-Za-z0-9_]+:\?[^}]+\}/;
const YAML_FILE = /\.ya?ml$/i;

/** Control and invisible characters, and look-alike spaces; tab, line feed and carriage return are fine. */
const INVISIBLE: readonly (readonly [number, number])[] = [
  [0x00, 0x08],
  [0x0b, 0x0c],
  [0x0e, 0x1f],
  [0x7f, 0x9f],
  [0xa0, 0xa0],
  [0xad, 0xad],
  [0x34f, 0x34f],
  [0x61c, 0x61c],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x180e, 0x180e],
  [0x2000, 0x200f],
  [0x2028, 0x202f],
  [0x205f, 0x206f],
  [0x3000, 0x3000],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xfff9, 0xfffb],
  [0xe0000, 0xe007f],
];

const isInvisible = (codePoint: number): boolean =>
  INVISIBLE.some(([first, last]) => codePoint >= first && codePoint <= last);

/** Shannon entropy in bits per character. */
export function entropy(text: string): number {
  const counts = new Map<string, number>();
  let length = 0;
  for (const character of text) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
    length += 1;
  }
  let bits = 0;
  for (const count of counts.values()) bits -= (count / length) * Math.log2(count / length);
  return bits;
}

/** Letters and digits mixed, and varied enough to pass for a key (scanners use a similar test). */
const randomLooking = (value: string): boolean => /[0-9]/.test(value) && /[A-Za-z]/.test(value) && entropy(value) >= 3;

/** Why a path can't be committed, or nothing. Paths use forward slashes, relative to the repository. */
export function pathProblems(file: string): Problem[] {
  return FORBIDDEN_PATHS.filter(({ pattern }) => pattern.test(file)).map(({ message }) => ({
    rule: 'forbidden-file' as const,
    file,
    message,
  }));
}

/** What is wrong with one line of a file. */
export function lineProblems(file: string, line: number, text: string): Problem[] {
  const problems: Problem[] = [];
  const add = (rule: RuleId, message: string): void => {
    problems.push({ rule, file, line, message });
  };

  if (PRIVATE_KEY.test(text)) add('private-key', 'a private key');
  for (const { name, pattern } of PROVIDER_TOKENS) {
    if (pattern.test(text)) add('provider-token', `looks like ${name}`);
  }
  if ([...text.matchAll(SECRET_NAMED_LITERAL)].some((match) => randomLooking(match[2] ?? ''))) {
    add(
      'scanner-bait',
      'a random-looking value in a secret-named field; the secret scanners will flag it. Name it for what it is, or build it when the test runs',
    );
  }
  const passwordIdentifiers = [...text.matchAll(PASSWORD_NAMED_IDENTIFIER)].filter(
    ([, key = '', value = '']) => !NAMES_A_PLACE.test(key) && !NAMED_FOR_A_SECRET.test(value),
  );
  if (passwordIdentifiers.length > 0) {
    add(
      'scanner-bait',
      'a camelCase variable in a password-named field; GitGuardian reads its name as the password. Pass it as a dotted path or a call',
    );
  }
  if (YAML_FILE.test(file) && PLACEHOLDER_WITH_MESSAGE.test(text)) {
    add(
      'placeholder-message',
      'write required variables bare, as ${NAME:?}: GitGuardian reads a message as a password',
    );
  }
  for (const character of text) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (isInvisible(codePoint)) {
      add(
        'invisible-character',
        `invisible character U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}; write it as String.fromCharCode in code`,
      );
    }
  }
  return problems;
}

/** Every problem in a whole file's text (CI's pass over the repository). */
export function textProblems(file: string, text: string): Problem[] {
  return text.split('\n').flatMap((line, index) => lineProblems(file, index + 1, line));
}

/** One line per problem, for a terminal: `file:line [rule] message`. */
export function describeProblem(problem: Problem): string {
  const where = problem.line === undefined ? problem.file : `${problem.file}:${String(problem.line)}`;
  return `${where} [${problem.rule}] ${problem.message}`;
}
