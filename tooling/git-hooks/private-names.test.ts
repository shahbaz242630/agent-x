// The S68 audit: the names that must never reach the repository, read from a
// local file and the staging origin, and found whatever their case. Stand-in
// names only: the real ones are never written here.
import { describe, expect, it } from 'vitest';

import { domainOf, linesNaming, privateNames } from './private-names.ts';
import { stagedProblems } from './pre-commit.ts';

describe('the private names (the S68 audit)', () => {
  it('takes the registrable part of an origin’s host', () => {
    expect(domainOf('https://app.staging-name.example')).toBe('staging-name.example');
    expect(domainOf('https://staging-name.example')).toBe('staging-name.example');
    expect(domainOf('https://localhost')).toBeUndefined();
    expect(domainOf('not an origin')).toBeUndefined();
  });

  it('reads the file’s names, blank lines and comments aside, and the origin’s domain, in lower case, once each', () => {
    const names = privateNames({
      fileText: '# a comment\n\nStaging-Name.example\r\nother-name.example\n',
      origin: 'https://app.staging-name.example',
    });

    expect(names).toEqual(['staging-name.example', 'other-name.example']);
  });

  it('drops a name shorter than 6 characters, which would match ordinary words, and has none from nothing', () => {
    expect(privateNames({ fileText: 'a.bc\n' })).toEqual([]);
    expect(privateNames({})).toEqual([]);
    expect(privateNames({ origin: '' })).toEqual([]);
  });

  it('finds the lines naming one, whatever the case', () => {
    const text = 'first\nsee auth.STAGING-NAME.example here\nthird\nstaging-name.example\n';

    expect(linesNaming(text, ['staging-name.example'])).toEqual([2, 4]);
    expect(linesNaming(text, [])).toEqual([]);
  });

  it('refuses a staged line naming one, by file and line, never saying the name', () => {
    const diff = [
      'diff --git a/deploy/notes.md b/deploy/notes.md',
      '+++ b/deploy/notes.md',
      '@@ -0,0 +1,2 @@',
      '+the login is at auth.staging-name.example',
      '+nothing here',
    ].join('\n');

    const problems = stagedProblems(['deploy/notes.md'], diff, ['staging-name.example']);

    expect(problems).toEqual([expect.objectContaining({ rule: 'private-name', file: 'deploy/notes.md', line: 1 })]);
    expect(JSON.stringify(problems)).not.toContain('staging-name');
    expect(stagedProblems(['deploy/notes.md'], diff)).toEqual([]);
  });
});
