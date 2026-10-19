// L4b: the place file's pin. The real Dockerfile's pin is read, moved to
// another month's release and checksum (and nothing else in the file
// changes), and judged stale in plain words past MOST_AGE_DAYS.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { ageProblem, MOST_AGE_DAYS, monthDue, monthOf, pinned, pinnedMonth } from './pin.ts';

const DOCKERFILE = readFileSync('Dockerfile', 'utf8');
const MONTH = pinnedMonth(DOCKERFILE) ?? '';
const SHA = 'a'.repeat(64);

describe('the place file’s pin (L4b)', () => {
  it('reads the month the Dockerfile pins', () => {
    expect(MONTH).toMatch(/^\d{4}-\d{2}$/);
    expect(pinnedMonth('FROM node')).toBeUndefined();
  });

  it('is due the month after, not the month it pins', () => {
    expect(monthDue(DOCKERFILE, new Date(`${MONTH}-20T12:00:00Z`))).toBeUndefined();
    const next = new Date(Date.parse(`${MONTH}-01T00:00:00Z`) + 40 * 86_400_000);
    expect(monthDue(DOCKERFILE, next)).toBe(monthOf(next));
    expect(monthOf(new Date('2026-12-31T23:59:59Z'))).toBe('2026-12');
  });

  it('moves the release URL, the checksum and the comment’s month, and nothing else', () => {
    const moved = pinned(DOCKERFILE, '2027-01', SHA);

    expect(pinnedMonth(moved)).toBe('2027-01');
    expect(moved).toContain(`--checksum=sha256:${SHA}`);
    expect(moved).toContain('/geoip-dbip-city-lite-2027-01/dbip-city-lite-2027-01.mmdb.gz');
    expect(moved).toContain('City Lite, January 2027');
    const changed = moved.split('\n').filter((line, index) => line !== DOCKERFILE.split('\n')[index]);
    expect(changed).toHaveLength(3);
    // Moved back, it is the file it was.
    const sha = /--checksum=sha256:([0-9a-f]{64})/.exec(DOCKERFILE)?.[1] ?? '';
    const name = /City Lite, ([A-Z][a-z]+ \d{4})/.exec(DOCKERFILE)?.[1] ?? '';
    expect(pinned(moved, MONTH, sha).replace(/City Lite, [A-Z][a-z]+ \d{4}/, `City Lite, ${name}`)).toBe(DOCKERFILE);
  });

  it.each([
    ['a month that isn’t one', '2027-13', SHA, /not a month/],
    ['a checksum that isn’t SHA-256', '2027-01', 'A'.repeat(64), /not a SHA-256/],
  ])('refuses %s', (_what, month, sha, error) => {
    expect(() => pinned(DOCKERFILE, month, sha)).toThrow(error);
  });

  it.each([
    ['release URL', DOCKERFILE.replace(/releases\/download/, 'releases/latest')],
    ['checksum', DOCKERFILE.replace('ADD --checksum', 'ADD')],
    ['comment naming the month', DOCKERFILE.replace(/City Lite, /, 'City Lite ')],
  ])('refuses a Dockerfile with no %s to move', (what, text) => {
    expect(() => pinned(text, '2027-01', SHA)).toThrow(`the Dockerfile has no ${what} to move`);
  });

  it(`is fresh up to ${String(MOST_AGE_DAYS)} days past its month’s start, then stale in plain words`, () => {
    const start = Date.parse(`${MONTH}-01T00:00:00Z`);
    expect(ageProblem(DOCKERFILE, new Date(start + MOST_AGE_DAYS * 86_400_000))).toBeUndefined();
    expect(ageProblem(DOCKERFILE, new Date(start + (MOST_AGE_DAYS + 1) * 86_400_000))).toMatch(
      /^The place file is 46 days old .*going out of date\. The monthly refresh/,
    );
    expect(ageProblem('FROM node', new Date())).toMatch(/pins no place file/);
  });
});

describe('the pin’s command line, as the workflows run it', () => {
  const run = (...args: string[]) =>
    spawnSync(process.execPath, ['tooling/places/pin.ts', ...args], { encoding: 'utf8' });

  it('says the file is fresh, and nothing is due, in the month it pins (or names the month due)', () => {
    const age = run('age');
    const due = run('due');

    expect(age.status).toBe(ageProblem(DOCKERFILE, new Date()) === undefined ? 0 : 1);
    expect(due.status).toBe(0);
    expect(due.stdout).toBe(monthDue(DOCKERFILE, new Date()) ?? '');
  });

  it('refuses a command it doesn’t know, saying how it is used', () => {
    const wrong = run('move');

    expect(wrong.status).toBe(2);
    expect(wrong.stderr).toMatch(/^usage: pin\.ts due \| pin <YYYY-MM> <sha256> \| age/);
  });
});
