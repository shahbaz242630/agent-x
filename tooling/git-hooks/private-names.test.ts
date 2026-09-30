// The S68 audit: a private name is found by its fingerprint, as a word or
// inside a longer host, whatever its case, and never said. Stand-in names
// only: the real one is never written here.
import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { stagedProblems } from './pre-commit.ts';
import { linesNaming, PRIVATE_NAME_FINGERPRINTS } from './private-names.ts';

const STAND_IN = 'staging-name.example';
const FINGERPRINT = [createHash('sha256').update(STAND_IN).digest('hex')];

describe('the private names (the S68 audit)', () => {
  it('keeps a fingerprint for the staging domain, a SHA-256, never the name', () => {
    expect(PRIVATE_NAME_FINGERPRINTS.length).toBeGreaterThan(0);
    for (const each of PRIVATE_NAME_FINGERPRINTS) expect(each).toMatch(/^[0-9a-f]{64}$/);
  });

  it('finds the name as a word, as a host’s parent, in a URL, whatever its case', () => {
    const text = [
      'first',
      `see ${STAND_IN} here`,
      `https://auth.${STAND_IN.toUpperCase()}/v1`,
      'third',
      `mail to team@app.${STAND_IN}.`,
    ].join('\n');

    expect(linesNaming(text, FINGERPRINT)).toEqual([2, 3, 5]);
  });

  it('finds nothing in a name that only contains it, or with no fingerprint to find', () => {
    expect(linesNaming(`x${STAND_IN} and ${STAND_IN}x`, FINGERPRINT)).toEqual([]);
    expect(linesNaming(`see ${STAND_IN}`, [])).toEqual([]);
  });

  it('refuses a staged line naming one, by file and line, never saying the name', () => {
    const diff = [
      'diff --git a/deploy/notes.md b/deploy/notes.md',
      '+++ b/deploy/notes.md',
      '@@ -0,0 +1,2 @@',
      `+the login is at auth.${STAND_IN}`,
      '+nothing here',
    ].join('\n');

    const problems = stagedProblems(['deploy/notes.md'], diff, FINGERPRINT);

    expect(problems).toEqual([expect.objectContaining({ rule: 'private-name', file: 'deploy/notes.md', line: 1 })]);
    expect(JSON.stringify(problems)).not.toContain('staging-name');
    expect(stagedProblems(['deploy/notes.md'], diff, [])).toEqual([]);
  });
});
