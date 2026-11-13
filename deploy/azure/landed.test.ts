// The release workflow's last word (AZ5, review S190): a merge whose release never ran is never taken for done.
import { describe, expect, it } from 'vitest';

import { landed, main } from './landed.ts';

const THIS = 'a'.repeat(40);
const NEWER = 'b'.repeat(40);
const newest = (sha: string) => () => Promise.resolve(sha);

describe('landed', () => {
  it('passes a release that succeeded, without asking GitHub', async () => {
    const asked: string[] = [];
    const verdict = await landed(THIS, 'success', () => {
      asked.push('newest');
      return Promise.resolve(NEWER);
    });
    expect(verdict).toEqual({ red: false, line: `Staging runs ${THIS}: its release succeeded.` });
    expect(asked).toEqual([]);
  });

  it('lets a release that didn’t run pass only when a newer merge on main covers it', async () => {
    for (const result of ['cancelled', 'skipped', 'failure', '']) {
      expect((await landed(THIS, result, newest(NEWER))).red).toBe(false);
      const behind = await landed(THIS, result, newest(THIS));
      expect(behind.red).toBe(true);
      expect(behind.line).toContain('staging is behind main');
    }
    expect((await landed(THIS, 'cancelled', newest(NEWER))).line).toContain(`main has moved on to ${NEWER}`);
  });

  it('fails red when main’s newest commit can’t be read', async () => {
    const verdict = await landed(THIS, 'cancelled', newest(''));
    expect(verdict.red).toBe(true);
    expect(verdict.line).toContain("couldn't be read");
  });

  it('prints its word as an annotation, and refuses what isn’t a commit', async () => {
    const said: string[] = [];
    expect(await main([THIS, 'cancelled'], newest(THIS), (line) => said.push(line))).toBe(1);
    expect(said.at(-1)).toMatch(/^::error::This merge is main's newest/);
    expect(await main([THIS, 'cancelled'], newest(NEWER), (line) => said.push(line))).toBe(0);
    expect(said.at(-1)).toMatch(/^::notice::/);
    expect(await main(['main', 'success'], newest(THIS), (line) => said.push(line))).toBe(2);
  });
});
