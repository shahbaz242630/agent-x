// Names that must never reach the public repository (Rule Book §7; the S68
// audit): the staging domain, which slipped into one commit's comment (#112)
// and stays in the history. The names themselves are never written here, nor
// passed to CI (a repository variable is printed in public logs): each is
// kept as the SHA-256 of its lower-case form, and every domain-like word of a
// text is hashed and compared, with each of its parent domains
// (`auth.example.com` is checked as itself and as `example.com`). A match is
// reported by file and line, never by the text. A hash only confirms a guess;
// the hosts are in public certificate logs anyway.
import { createHash } from 'node:crypto';

/** The SHA-256 of each private name, in lower case: the staging domain. */
export const PRIVATE_NAME_FINGERPRINTS: readonly string[] = [
  '0e3982851bc02063ec91b560200802639649c2fc17d79de14352f29cc7bf2ad3',
];

/** A word shaped like a domain: labels of letters, digits and dashes, joined by dots. */
const DOMAIN_LIKE = /[\p{L}\p{Nd}-]+(?:\.[\p{L}\p{Nd}-]+)+/gu;

const fingerprintOf = (name: string): string => createHash('sha256').update(name, 'utf8').digest('hex');

/** Whether a line names one of the private names: a domain-like word, or a parent of one, whose fingerprint is listed. */
function names(line: string, fingerprints: ReadonlySet<string>): boolean {
  for (const [word] of line.toLowerCase().matchAll(DOMAIN_LIKE)) {
    const labels = word.split('.');
    for (let start = 0; start + 2 <= labels.length; start += 1) {
      if (fingerprints.has(fingerprintOf(labels.slice(start).join('.')))) return true;
    }
  }
  return false;
}

/** The 1-based lines of `text` naming a private name, whatever their case. */
export function linesNaming(text: string, fingerprints: readonly string[] = PRIVATE_NAME_FINGERPRINTS): number[] {
  const known = new Set(fingerprints);
  const lines: number[] = [];
  text.split('\n').forEach((line, index) => {
    if (names(line, known)) lines.push(index + 1);
  });
  return lines;
}
