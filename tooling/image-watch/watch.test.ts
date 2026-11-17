// DT5: the daily image watch. The images are read from the real files that
// pin them; Grype's reports and Zitadel's advisories are fixtures shaped like
// the real ones (S201). The positive control: a Zitadel version before the
// S190 fix goes red on the advisories that fix covered, and a silent or empty
// input goes red, never green.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ACCEPTED_FILE,
  compareVersions,
  escapeCommand,
  flattenAdvisories,
  inRange,
  judgeAdvisories,
  judgeGrype,
  main,
  parameterValue,
  parseAccepted,
  parseVersion,
  serviceImage,
  watchedImages,
  zitadelVersion,
  type Accepted,
  type GrypeMatch,
  type GrypeReport,
  type WatchedImage,
} from './watch.ts';

const readRepo = (file: string): string => readFileSync(file, 'utf8');
const IMAGES = watchedImages(readRepo);
const byKey = (key: string): WatchedImage => {
  const image = IMAGES.find((each) => each.key === key);
  if (image === undefined) throw new Error(key);
  return image;
};

const version = (text: string) => {
  const parsed = parseVersion(text);
  if (parsed === undefined) throw new Error(text);
  return parsed;
};

/** Every distinct affected range in Zitadel's published repository advisories at S201 (86 advisories), as written. */
const PUBLISHED_RANGES = [
  '>= 4.0.0, <= 4.20.2',
  '>= 4.19.5, <= 4.20.2',
  '>= 4.5.0, <= 4.20.2',
  '4.0.0 - 4.19.4',
  '3.0.0 - 3.4.15',
  '>= 4.0.0, <= 4.17.3',
  '>= 3.0.0, <= 3.4.15',
  '4.0.0 - 4.19.1',
  '4.0.0 - 4.17.2',
  '4.0.0 - 4.17.0',
  '3.0.0 - 3.4.14',
  '4.0.0 - 4.16.1',
  '3.0.0 - 3.4.13',
  '<=4.16.1',
  '<= 3.4.13',
  '4.0.0 - 4.16.0',
  '<=4.15.1',
  '4.0.0 - 4.15.2',
  '3.0.0 - 3.4.12',
  '4.0.0 - 4.15.0',
  '<=2.71.19 , 3.0.0 - 3.4.10',
  '<=4.15.2',
  '<=4.15.3',
  '4.0.0 - 4.14.0',
  '2.71.11 - 2.71.19 , 3.1.0 - 3.4.9',
  '4.0.0 - 4.15.1',
  '<=3.4.11',
  '4.0.0 - 4.11.0',
  '<=2.71.19 , 3.0.0 - 3.4.6',
  '4.0.0 - 4.12.1',
  '< 3.4.8',
  '2.68.0 - 2.71.19 , 3.0.0 - 3.4.7',
  '4.0.0 - 4.12.0',
  '4.0.0 - 4.11.1',
  '4.0.0 - 4.12.2',
  '< 3.4.9',
  '4.0.0 - 4.10.1',
  '2.31.0 - 2.71.19, 3.0.0 - 3.4.6',
  '4.0.0 - 4.9.0',
  '<=2.71.19 , 3.0.0 - 3.4.5',
  '4.0.0-rc.1 - 4.7.0',
  '4.0.0-rc.1 - 4.6.2',
  '4.0.0 - 4.6.5',
  '3.0.0 - 3.4.3',
  '2.50.0 - 2.71.18',
  '4.0.0 - 4.5.0',
  '3.0.0 - 3.4.2',
  '< 2.71.18',
  '4.0.0-rc.1 - 4.7.1',
  '2.44.0 - 2.71.19, 3.0.0 - 3.4.4',
  '2.53.6 - 2.53.9, 2.54.3 - 2.54.10, 2.55.0 - 2.71.17',
  '4.0.0 - 4.0.2',
  '3.0.0 - 3.3.6',
  '< 2.71.14',
  '4.0.0-rc.1',
  '3.0.0 - 3.3.0',
  '2.53.0 - 2.70.13, 2.71.0 - 2.71.12',
  '<3.2.2',
  '<2.70.12, 2.71.0 - 2.71.10',
  '3.0.0-rc.1 - 3.0.0-rc.3',
  '<2.70.10, 2.71.0 - 2.71.8',
  '>=2.62.0, <2.71.6, <2.70.8, <2.69.9, <2.68.9, <2.67.13, <2.66.16, <2.65.7, <2.64.6, <2.63.9',
  '<2.63.8, <2.64.5, <2.66.11, <2.67.8, <2.68.4, <2.69.4, <2.70.1, <2.71.0',
  ' <2.71.6, <2.70.8, <2.69.9, <2.68.9, <2.67.13, <2.66.16, <2.65.7, <2.64.6, <2.63.9',
  '<2.58.6, <2.59.4, <2.60.3, <2.61.3, <2.62.6, < 2.63.4, ',
  '<2.54.9, <2.55.7, <2.56.5, <2.57.4, <2.58.4, <2.59.2, <2.60.1, 2.61.0, 2.62.0',
  '<2.58.6, <2.59.4, <2.60.3, <2.61.3, <2.62.7, <2.63.5, 2.64.0',
  '<2.52.3, <2.53.9, <2.54.8, <2.55.5, <2.56.2, 2.57.0, 2.58.0',
  '2.53.0-2.53.8, 2.54.0-2.54.7, 2.55.0-2.55.4, 2.56.0-2.56.1, 2.57.0, 2.58.0',
  '2.55.0, 2.54.0-2.54.4, 2.53.0-2.53.7',
  '<2.45.7, <2.46.7, <2.47.10, <2.48.5, <2.49.5, <2.50.3',
  '<2.42.17, <2.43.11, <2.44.7, 2.45.5, 2.46.5, <2.47.8, <2.48.3',
  '<2.41.15, <2.42.15, <2.43.9, <2.44.3, 2.45.0, 2.46.0, <2.47.3',
  '<2.50.0',
  '< 2.41.6, < 2.40.10, <2.39.9, >=2.39.0',
  '< 2.44.3, >=2.45.0, <2.46.0',
  '>=2.39.0,<2.40.4',
  '<2.38.3',
  '<2.38.2',
  '>=2.39.0, <2.39.2',
  '<2.37.2',
  '>=2.0.0, <2.17.3',
  '>=2.16.0, <2.16.4',
  '>=2.0.0, < 2.2.0',
  '>=1.42.0, <1.87.1',
];

describe('DT5: the images the watch scans', () => {
  it('reads Zitadel and its login from staging, Postgres and nginx from the compose stack, all pinned', () => {
    expect(IMAGES.map((each) => each.key)).toEqual(['zitadel', 'zitadel-login', 'postgres', 'nginx']);
    const staging = readRepo('deploy/azure/staging.apps.bicepparam');
    expect(byKey('zitadel').image).toBe(parameterValue(staging, 'zitadelImage'));
    expect(byKey('zitadel-login').image).toBe(parameterValue(staging, 'zitadelLoginImage'));
    const compose = readRepo('deploy/compose/compose.yaml');
    expect(byKey('postgres').image).toBe(serviceImage(compose, 'db'));
    expect(byKey('nginx').image).toBe(serviceImage(compose, 'edge'));
    for (const each of IMAGES) expect(each.image).toMatch(/:[A-Za-z0-9][\w.-]*@sha256:[0-9a-f]{64}$/);
    expect(zitadelVersion(IMAGES)).toMatch(/^4\.\d+\.\d+$/);
  });

  it('reads a compose service only inside its own block', () => {
    const compose = 'services:\n  db:\n    build: .\n  edge:\n    image: nginx:1@sha256:x\n';
    expect(serviceImage(compose, 'db')).toBeUndefined();
    expect(serviceImage(compose, 'edge')).toBe('nginx:1@sha256:x');
    expect(serviceImage(compose, 'missing')).toBeUndefined();
    expect(serviceImage('services:\n  db:\n    build: .\n', 'db')).toBeUndefined();
  });

  it('says in plain words when a pin moved or lost its digest, rather than scanning nothing', () => {
    const unpinned = (file: string): string =>
      readRepo(file).replace(/(param zitadelImage = '[^@]+)@sha256:[0-9a-f]{64}/, '$1');
    expect(() => watchedImages(unpinned)).toThrow(/no longer pins ghcr\.io\/zitadel\/zitadel as name:tag@sha256/);
    const noEdge = (file: string): string => readRepo(file).replace('  edge:', '  front:');
    expect(() => watchedImages(noEdge)).toThrow(/service edge\) no longer pins nginx/);
    expect(zitadelVersion([])).toBe('');
  });
});

describe('DT5: Grype reports', () => {
  const nginx = byKey('nginx');
  const report = (matches: GrypeMatch[], userInput = nginx.image): GrypeReport => ({
    descriptor: { name: 'grype' },
    source: { type: 'image', target: { userInput } },
    matches,
  });
  const match = (id: string, severity: string, state: string, versions: string[] = []) => ({
    vulnerability: { id, severity, fix: { state, versions } },
    artifact: { name: 'libssl3', version: '3.5.8-r0', type: 'apk' },
  });

  it('goes red on a high or critical finding with a fix, and only reports the rest', () => {
    const verdict = judgeGrype(
      report([
        match('CVE-1', 'Critical', 'fixed', ['3.5.9-r0']),
        match('CVE-2', 'High', 'fixed', ['3.5.9-r0']),
        match('CVE-3', 'High', 'unknown'),
        match('CVE-4', 'High', 'not-fixed'),
        match('CVE-5', 'Medium', 'fixed', ['3.5.9-r0']),
        match('CVE-6', 'Low', ''),
        {},
      ]),
      nginx,
    );
    expect(verdict.errors).toEqual([
      `nginx (${nginx.image}), which the local stack runs as its front door (staging uses Azure's own), has 2 ` +
        'high or critical known vulnerabilities with a fix available that tooling/image-watch/accepted.json does not accept: CVE-1 (critical) in libssl3 3.5.8-r0, fixed ' +
        'in 3.5.9-r0; CVE-2 (high) in libssl3 3.5.8-r0, fixed in 3.5.9-r0. ' +
        "The local stack's front door may be at risk. Move the image to a release that carries the fixes " +
        "(Dependabot's weekly bump, or by hand per ADR-003), then run the hand deploy where staging runs it; or, " +
        'when no vendor image has the fix yet, accept it there with a reason and a review date. ' +
        "The full list is in this run's summary.",
    ]);
    expect(verdict.summary).toContain('2 red, 0 accepted, 0 covered by the advisory check, 5 report only');
    expect(verdict.summary).toContain('| report only | high | CVE-4 | libssl3 3.5.8-r0 | no fix yet |');
    expect(verdict.summary).toContain('| report only | unknown | an unnamed finding | ? ? | no fix yet |');
  });

  it('names five red findings in its one line, and counts the rest', () => {
    const many = Array.from({ length: 7 }, (_, index) => match(`CVE-${String(index)}`, 'High', 'fixed', ['2']));
    const [line] = judgeGrype(report(many), nginx).errors;
    expect(line).toContain('has 7 high or critical known vulnerabilities');
    expect(line).toContain('CVE-4 (high)');
    expect(line).not.toContain('CVE-5');
    expect(line).toContain('; and 2 more.');
    expect(judgeGrype(report(many.slice(0, 1)), nginx).errors[0]).toContain(
      'has 1 high or critical known vulnerability with',
    );
  });

  it('says so when the image is clean', () => {
    const verdict = judgeGrype(report([]), nginx);
    expect(verdict.errors).toEqual([]);
    expect(verdict.summary).toContain('No known vulnerabilities.');
    expect(
      judgeGrype({ descriptor: { name: 'grype' }, source: { target: { userInput: nginx.image } } }, nginx).errors,
    ).toEqual([]);
  });

  it('goes red, never green, on a report that is not Grype’s on this image', () => {
    expect(judgeGrype(report([], 'nginx:other'), nginx).errors[0]).toMatch(/is not Grype's report on nginx:/);
    expect(judgeGrype({}, nginx).errors).toHaveLength(1);
  });
});

describe('DT5: accepted findings (lead, S201)', () => {
  const NOW = new Date('2026-11-17T12:00:00Z');
  const KEYS = IMAGES.map((each) => each.key);
  const nginx = byKey('nginx');
  const entry = (overrides: Partial<Accepted> = {}): Accepted => ({
    image: 'nginx',
    id: 'CVE-1',
    package: 'libssl3',
    reason: 'fixed upstream in libssl3 3.5.9-r0, no vendor image with it yet',
    reviewBy: '2026-12-01',
    ...overrides,
  });
  const scan = (...ids: string[]): GrypeReport => ({
    descriptor: { name: 'grype' },
    source: { target: { userInput: nginx.image } },
    matches: ids.map((id) => ({
      vulnerability: { id, severity: 'High', fix: { state: 'fixed', versions: ['3.5.9-r0'] } },
      artifact: { name: 'libssl3', version: '3.5.8-r0' },
    })),
  });

  it('keeps a new finding red beside an accepted one', () => {
    const verdict = judgeGrype(scan('CVE-1', 'CVE-2'), nginx, [entry()], NOW);
    expect(verdict.errors).toHaveLength(1);
    expect(verdict.errors[0]).toContain('has 1 high or critical known vulnerability');
    expect(verdict.errors[0]).toContain('CVE-2 (high)');
    expect(verdict.errors[0]).not.toContain('CVE-1 ');
    expect(verdict.summary).toContain('1 red, 1 accepted, 0 covered by the advisory check, 0 report only');
    expect(verdict.summary).toContain('| accepted until 2026-12-01 | high | CVE-1 |');
  });

  it('is green when every red finding is accepted, and only for its own image and package', () => {
    expect(judgeGrype(scan('CVE-1'), nginx, [entry()], NOW).errors).toEqual([]);
    expect(judgeGrype(scan('CVE-1'), nginx, [entry({ image: 'postgres' })], NOW).errors).toHaveLength(1);
    expect(judgeGrype(scan('CVE-1'), nginx, [entry({ package: 'libcrypto3' })], NOW).errors).toHaveLength(1);
    // The review day itself still counts.
    expect(judgeGrype(scan('CVE-1'), nginx, [entry({ reviewBy: '2026-11-17' })], NOW).errors).toEqual([]);
  });

  it('goes red again once an entry passes its review date', () => {
    const late = entry({ reviewBy: '2026-11-16' });
    expect(judgeGrype(scan('CVE-1'), nginx, [late], NOW).errors).toHaveLength(1);
    const checked = parseAccepted({ accepted: [late] }, KEYS, NOW);
    expect(checked.entries).toEqual([late]);
    expect(checked.errors).toEqual([
      'The accepted finding CVE-1 (libssl3) on nginx passed its review date 2026-11-16, so it is red again. Check ' +
        'whether the vendor shipped a fixed image, then move the pin, or renew the entry in ' +
        'tooling/image-watch/accepted.json with a reason and a new date.',
    ]);
  });

  it("lists Zitadel's own module in its server image as covered by the advisory check, and judges it anywhere else", () => {
    const zitadel = byKey('zitadel');
    const finding = (name: string): GrypeMatch[] => [
      {
        vulnerability: { id: 'GHSA-old', severity: 'Critical', fix: { state: 'fixed', versions: ['2.38.3'] } },
        artifact: { name, version: 'v1.80.0-v2.20.0.20261117133830-384bb9ec96b5' },
      },
    ];
    const own = judgeGrype(
      { ...scan(), source: { target: { userInput: zitadel.image } }, matches: finding('github.com/zitadel/zitadel') },
      zitadel,
      [],
      NOW,
    );
    expect(own.errors).toEqual([]);
    expect(own.summary).toContain('0 red, 0 accepted, 1 covered by the advisory check, 0 report only');
    expect(own.summary).toContain(
      '| covered by the advisory check | critical | GHSA-old | github.com/zitadel/zitadel ',
    );
    // Another package in the zitadel image is judged.
    const other = judgeGrype(
      { ...scan(), source: { target: { userInput: zitadel.image } }, matches: finding('stdlib') },
      zitadel,
      [],
      NOW,
    );
    expect(other.errors).toHaveLength(1);
    // The same package in another image is judged.
    const login = byKey('zitadel-login');
    const elsewhere = judgeGrype(
      { ...scan(), source: { target: { userInput: login.image } }, matches: finding('github.com/zitadel/zitadel') },
      login,
      [],
      NOW,
    );
    expect(elsewhere.errors).toHaveLength(1);
  });

  it('lists an entry matching no finding as stale, so the file shrinks', () => {
    const verdict = judgeGrype(scan('CVE-1'), nginx, [entry(), entry({ id: 'CVE-gone' })], NOW);
    expect(verdict.errors).toEqual([]);
    expect(verdict.summary).toContain('Stale: these accepted entries match no finding any more');
    expect(verdict.summary).toContain('- CVE-gone in libssl3');
    expect(judgeGrype(scan('CVE-1'), nginx, [entry()], NOW).summary).not.toContain('Stale');
  });

  it('goes red on a malformed entry, which accepts nothing', () => {
    const checked = parseAccepted(
      {
        accepted: [
          entry(),
          'CVE-1',
          entry({ reason: ' ' }),
          { image: 'nginx' },
          entry({ image: 'redis' }),
          entry({ reviewBy: '17/12/2026' }),
          entry({ reviewBy: '2026-02-30x' }),
          entry({ reviewBy: '2026-12-18' }),
        ],
      },
      KEYS,
      NOW,
    );
    expect(checked.entries).toEqual([entry()]);
    expect(checked.errors.map((error) => error.split(', so it accepts')[0])).toEqual([
      'Entry 2 of tooling/image-watch/accepted.json is not an object',
      'Entry 3 of tooling/image-watch/accepted.json has no reason',
      'Entry 4 of tooling/image-watch/accepted.json has no id, package, reason, reviewBy',
      'Entry 5 of tooling/image-watch/accepted.json names redis, which is not one of the watched images (zitadel, zitadel-login, postgres, nginx)',
      'Entry 6 of tooling/image-watch/accepted.json has the review date 17/12/2026, which is not a date (YYYY-MM-DD)',
      'Entry 7 of tooling/image-watch/accepted.json has the review date 2026-02-30x, which is not a date (YYYY-MM-DD)',
      'Entry 8 of tooling/image-watch/accepted.json has the review date 2026-12-18, more than 30 days ahead',
    ]);
    expect(checked.summary).toContain('1 accepted, 7 needing a person');
    expect(parseAccepted({}, KEYS, NOW).errors[0]).toMatch(/has no "accepted" list/);
    expect(parseAccepted(null, KEYS, NOW).errors).toHaveLength(1);
    expect(parseAccepted({ accepted: [] }, KEYS, NOW).errors).toEqual([]);
  });

  it('keeps the committed file well formed: every entry for a watched image, with a reason', () => {
    const committed = JSON.parse(readRepo(ACCEPTED_FILE)) as { accepted: Accepted[] };
    // Its dates are checked against the day it runs only by the workflow; here, against the day each was written.
    const written = new Date(
      Date.parse(`${committed.accepted[0]?.reviewBy ?? '2026-12-17'}T00:00:00Z`) - 30 * 86_400_000,
    );
    expect(parseAccepted(committed, KEYS, written).errors).toEqual([]);
    for (const each of committed.accepted) expect(each.reason.length).toBeGreaterThan(40);
  });
});

describe('DT5: version ranges', () => {
  it('orders versions, pre-releases before their release', () => {
    const order = [
      '1.0.0-alpha',
      '1.0.0-alpha.1',
      '1.0.0-alpha.beta',
      '1.0.0-beta.2',
      '1.0.0-beta.11',
      '1.0.0-rc.1',
      '1.0.0',
      '1.0.1',
      '1.1.0',
      '2.0.0',
    ];
    for (const [earlier, later] of order.slice(1).map((each, index) => [order[index] ?? '', each] as const)) {
      expect(compareVersions(version(earlier), version(later))).toBeLessThan(0);
      expect(compareVersions(version(later), version(earlier))).toBeGreaterThan(0);
    }
    expect(compareVersions(version('v4.19.5'), version('4.19.5'))).toBe(0);
    expect(compareVersions(version('1.0.0-rc.1'), version('1.0.0-rc.1'))).toBe(0);
    expect(parseVersion('4.19')).toBeUndefined();
  });

  it('reads every range Zitadel has published', () => {
    const v = version('4.19.5');
    expect(PUBLISHED_RANGES.filter((range) => inRange(range, v) === undefined)).toEqual([]);
    // Of them, only the open v4 ranges up to 4.20.2 cover it; 4.20.3 is past all.
    expect(PUBLISHED_RANGES.filter((range) => inRange(range, v) === true)).toEqual([
      '>= 4.0.0, <= 4.20.2',
      '>= 4.19.5, <= 4.20.2',
      '>= 4.5.0, <= 4.20.2',
    ]);
    expect(PUBLISHED_RANGES.filter((range) => inRange(range, version('4.20.3')) !== false)).toEqual([]);
  });

  it.each([
    ['4.0.0 - 4.19.4', '4.19.4', true],
    ['4.0.0 - 4.19.4', '4.0.0', true],
    ['4.0.0 - 4.19.4', '4.19.5', false],
    ['4.0.0 - 4.19.4', '3.9.9', false],
    ['>= 4.19.5, <= 4.20.2', '4.20.2', true],
    ['>= 4.19.5, <= 4.20.2', '4.19.4', false],
    ['> 4.1.0, < 4.2.0', '4.1.0', false],
    ['> 4.1.0, < 4.2.0', '4.1.5', true],
    ['> 4.1.0, < 4.2.0', '4.2.0', false],
    ['4.0.0-rc.1 - 4.7.0', '4.0.0-rc.2', true],
    ['4.0.0-rc.1', '4.0.0-rc.1', true],
    ['= 4.0.0', '4.0.0', true],
    ['<=3.4.11', '2.0.0', true],
    // A list of fixes, one per release line: each bound on its own line.
    ['<2.54.9, <2.55.7', '2.55.6', true],
    ['<2.54.9, <2.55.7', '2.54.9', false],
    ['<2.54.9, <2.55.7', '4.0.0', false],
    // GHSA-f3gh-529w-v32x: a line not listed (2.65) is affected below a higher fix (2.66.11).
    ['<2.63.8, <2.64.5, <2.66.11, <2.67.8, <2.68.4, <2.69.4, <2.70.1, <2.71.0', '2.65.0', true],
    ['<2.63.8, <2.64.5, <2.66.11, <2.67.8, <2.68.4, <2.69.4, <2.70.1, <2.71.0', '2.62.0', true],
    ['<2.63.8, <2.64.5, <2.66.11, <2.67.8, <2.68.4, <2.69.4, <2.70.1, <2.71.0', '2.64.5', false],
    ['<2.63.8, <2.64.5, <2.66.11, <2.67.8, <2.68.4, <2.69.4, <2.70.1, <2.71.0', '2.71.0', false],
    ['<4.18.3, <4.19.6', '4.17.5', true],
    ['<4.18.3, <4.19.6', '4.19.5', true],
    ['<4.18.3, <4.19.6', '4.20.0', false],
    ['<=4.18.3, <=4.19.6', '4.19.6', true],
    // A lone lower bound below a fix starts the fixes; at or above every fix, or with none, it runs on for ever.
    ['< 2.41.6, < 2.40.10, <2.39.9, >=2.39.0', '2.40.5', true],
    ['< 2.41.6, < 2.40.10, <2.39.9, >=2.39.0', '4.20.3', false],
    ['< 3.4.16, >= 4.0.0', '4.19.5', true],
    ['< 3.4.16, >= 4.0.0', '3.4.10', true],
    ['< 3.4.16, >= 4.0.0', '3.4.16', false],
    ['<= 3.4.15, >= 4.0.0', '4.19.5', true],
    ['<4.19.6, >=4.20.0', '4.20.3', true],
    ['<4.19.6, >=4.20.0', '4.19.0', true],
    ['<4.19.6, >=4.20.0', '4.19.6', false],
    ['< 2.41.6, < 2.40.10, <2.39.9, >=2.39.0', '2.38.0', false],
    ['< 2.41.6, < 2.40.10, <2.39.9, >=2.39.0', '2.42.0', false],
    ['< 2.41.6, < 2.40.10, <2.39.9, >=2.39.0', '4.19.5', false],
    ['>=2.39.0, 3.0.0 - 3.1.0', '4.19.5', true],
    ['< 2.44.3, >=2.45.0, <2.46.0', '2.45.3', true],
    ['< 2.44.3, >=2.45.0, <2.46.0', '2.44.5', false],
    ['<2.70.12, 2.71.0 - 2.71.10', '2.70.11', true],
    ['>= 4.0.0', '9.0.0', true],
    ['2.53.0-2.53.7', '2.53.7', true],
  ])('%s covers %s: %s', (range, at, expected) => {
    expect(inRange(range, version(at))).toBe(expected);
  });

  it("can't read a range in a form it doesn't know, and says so rather than no", () => {
    expect(inRange('all versions', version('4.19.5'))).toBeUndefined();
    expect(inRange('4.0.0 - latest', version('4.19.5'))).toBeUndefined();
    expect(inRange('', version('4.19.5'))).toBeUndefined();
    // A range written without spaces around a pre-release is not an exact version.
    expect(inRange('4.0.0-rc.1-4.7.0', version('4.19.5'))).toBeUndefined();
  });
});

describe("DT5: Zitadel's advisories (the positive control)", () => {
  const advisory = (id: string, severity: string | null, range: string, patched: string | null, extra = {}) => ({
    ghsa_id: id,
    summary: `title of ${id}`,
    severity,
    html_url: `https://github.com/zitadel/zitadel/security/advisories/${id}`,
    withdrawn_at: null,
    vulnerabilities: [
      { package: { ecosystem: 'other', name: 'ZITADEL' }, vulnerable_version_range: range, patched_versions: patched },
    ],
    ...extra,
  });
  /** Shaped like S190's account-takeover advisories (fixed in 4.19.5) and S201's (fixed in 4.20.3). */
  const ADVISORIES = [
    advisory('GHSA-s190-high', 'high', '4.0.0 - 4.19.4', '4.19.5'),
    advisory('GHSA-s190-crit', 'critical', '4.0.0 - 4.19.4', '4.19.5'),
    advisory('GHSA-old-v3', 'critical', '3.0.0 - 3.4.15', '3.4.16'),
    advisory('GHSA-medium', 'medium', '4.0.0 - 4.19.4', '4.19.5'),
    advisory('GHSA-nofix', 'high', '4.0.0 - 4.19.4', ''),
    advisory('GHSA-withdrawn', 'critical', '4.0.0 - 4.19.4', '4.19.5', { withdrawn_at: '2026-01-01T00:00:00Z' }),
  ];

  it('goes red for a version before the S190 fix, naming each high or critical advisory with a fix', () => {
    const verdict = judgeAdvisories(ADVISORIES, '4.19.4', true);
    expect(verdict.errors).toHaveLength(2);
    expect(verdict.errors[0]).toBe(
      'Positive control: Zitadel v4.19.4 (a version chosen for this run, not what staging runs) has a published ' +
        'high-severity advisory GHSA-s190-high (title of GHSA-s190-high). Sign-in may be at risk. Move Zitadel and ' +
        'its login image to a fixed version (4.19.5 or later; ADR-003) in deploy/compose/compose.yaml and ' +
        'deploy/azure/staging.apps.bicepparam, then run the hand deploy. ' +
        'https://github.com/zitadel/zitadel/security/advisories/GHSA-s190-high',
    );
    expect(verdict.errors[1]).toContain('critical-severity advisory GHSA-s190-crit');
    // The medium and the one with no fix are in the summary only; the withdrawn one nowhere.
    expect(verdict.summary).toContain('| report only | medium | GHSA-medium |');
    expect(verdict.summary).toContain(
      '| report only | high | GHSA-nofix | title of GHSA-nofix | 4.0.0 - 4.19.4 | no fix yet |',
    );
    expect(verdict.summary).not.toContain('GHSA-withdrawn');
    expect(verdict.summary).toContain('Positive control: v4.19.4 against 6 published advisories: 4 apply, 2 red.');
  });

  it('stays green once on the fixed version, and names the pinned version as what staging runs', () => {
    const verdict = judgeAdvisories(ADVISORIES, '4.19.5', false);
    expect(verdict.errors).toEqual([]);
    expect(verdict.summary).toContain('None applies.');
    const red = judgeAdvisories([advisory('GHSA-x', 'HIGH', '>= 4.19.5, <= 4.20.2', '4.20.3')], '4.19.5', false);
    expect(red.errors[0]).toMatch(
      /^Zitadel v4\.19\.5, which staging and the local stack run \(server and login pages\), has/,
    );
  });

  it('goes red on an advisory whose range it cannot read, rather than passing it', () => {
    const verdict = judgeAdvisories([advisory('GHSA-odd', 'low', 'every 4.x', null)], '4.19.5', false);
    expect(verdict.errors).toHaveLength(1);
    expect(verdict.errors[0]).toContain(`gives an affected range this watch can't read ("every 4.x")`);
    expect(verdict.summary).toContain('| red | low | GHSA-odd |');
  });

  it('goes red when there is nothing to judge: no advisories, or no version', () => {
    expect(judgeAdvisories([], '4.19.5', false).errors[0]).toMatch(/^Zitadel's advisory list came back empty, so/);
    expect(judgeAdvisories(ADVISORIES, '', false).errors[0]).toMatch(/^The Zitadel version \(none\) is not a version/);
    expect(judgeAdvisories(ADVISORIES, 'latest', true).errors[0]).toMatch(
      /^The Zitadel version latest is not a version/,
    );
  });

  it('copes with what GitHub may leave out', () => {
    const bare = [
      { vulnerabilities: [{}] },
      { vulnerabilities: null },
      { severity: null, vulnerabilities: [{ vulnerable_version_range: '4.19.5' }] },
    ];
    const verdict = judgeAdvisories(bare, '4.19.5', false);
    // Both the unreadable range and the advisory naming no affected versions are red.
    expect(verdict.errors).toHaveLength(2);
    expect(verdict.errors[1]).toContain(
      `gives an affected range this watch can't read ("(no affected versions given)")`,
    );
    expect(verdict.summary).toContain('| report only | unknown | ? |  | 4.19.5 | no fix yet |');
    expect(judgeAdvisories([{ ghsa_id: 'GHSA-e', vulnerabilities: [] }], '4.19.5', false).errors[0]).toContain(
      'GHSA-e',
    );
  });

  it("reads gh's pages of advisories as one list", () => {
    expect(flattenAdvisories([[{ ghsa_id: 'a' }], [{ ghsa_id: 'b' }]])).toEqual([{ ghsa_id: 'a' }, { ghsa_id: 'b' }]);
    expect(flattenAdvisories([{ ghsa_id: 'a' }])).toEqual([{ ghsa_id: 'a' }]);
    expect(flattenAdvisories({})).toEqual([]);
  });

  it('keeps outside text from ending its annotation line or the summary table', () => {
    expect(escapeCommand('a%b\r\n::warning::c')).toBe('a%25b%0D%0A::warning::c');
    const verdict = judgeAdvisories(
      [advisory('GHSA-x', 'high', '4.19.5', '4.20.3', { summary: 'a | b\nc' })],
      '4.19.5',
      false,
    );
    expect(verdict.summary).toContain('| a \\| b c |');
  });
});

describe('DT5: the command line', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'image-watch-'));
  const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  const errorWrite = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  afterEach(() => {
    write.mockClear();
    vi.unstubAllEnvs();
  });

  const files: Record<string, string> = {};
  const read = (file: string): string => files[file] ?? readRepo(file);
  const out = (): string => write.mock.calls.map(([text]) => String(text)).join('');

  it('prints the images as a job matrix', () => {
    expect(main(['images'], read)).toBe(0);
    const matrix = JSON.parse(out()) as { include: { key: string; image: string }[] };
    expect(matrix.include.map((each) => each.key)).toEqual(['zitadel', 'zitadel-login', 'postgres', 'nginx']);
    expect(matrix.include[0]?.image).toBe(byKey('zitadel').image);
  });

  it('judges a Grype report, writing ::error:: lines and the job summary', () => {
    const summary = path.join(dir, 'summary.md');
    vi.stubEnv('GITHUB_STEP_SUMMARY', summary);
    files['report.json'] = JSON.stringify({
      descriptor: { name: 'grype' },
      source: { target: { userInput: byKey('postgres').image } },
      matches: [
        {
          vulnerability: { id: 'CVE-9', severity: 'High', fix: { state: 'fixed', versions: ['2'] } },
          artifact: { name: 'p', version: '1' },
        },
      ],
    });
    expect(main(['grype', 'report.json', 'postgres'], read)).toBe(1);
    expect(out()).toMatch(/^::error::Postgres \(postgres:.*: CVE-9 \(high\) in p 1, fixed in 2\. /);
    expect(readFileSync(summary, 'utf8')).toContain('## Postgres');
    expect(() => main(['grype', 'report.json', 'redis'], read)).toThrow('redis is not one of the watched images');
  });

  it('judges the advisories against the pinned version, or the control version given', () => {
    vi.stubEnv('GITHUB_STEP_SUMMARY', '');
    const pinned = zitadelVersion(IMAGES);
    files['advisories.json'] = JSON.stringify([
      [
        {
          ghsa_id: 'GHSA-p',
          severity: 'high',
          withdrawn_at: null,
          vulnerabilities: [{ vulnerable_version_range: `4.0.0 - ${pinned}`, patched_versions: '99.0.0' }],
        },
      ],
    ]);
    expect(main(['advisories', 'advisories.json', ''], read)).toBe(1);
    expect(out()).toContain(`::error::Zitadel v${pinned}, which staging`);
    write.mockClear();
    expect(main(['advisories', 'advisories.json', 'v99.0.0'], read)).toBe(0);
    expect(out()).toBe('Nothing needs a person today.\n');
  });

  it('checks the accepted file, red on an expired entry', () => {
    files[ACCEPTED_FILE] = JSON.stringify({
      accepted: [{ image: 'nginx', id: 'CVE-1', package: 'p', reason: 'r', reviewBy: '2026-11-01' }],
    });
    expect(main(['accepted'], read, new Date('2026-11-17T00:00:00Z'))).toBe(1);
    expect(out()).toContain('::error::The accepted finding CVE-1 (p) on nginx passed its review date 2026-11-01');
    write.mockClear();
    files[ACCEPTED_FILE] = JSON.stringify({ accepted: [] });
    expect(main(['accepted'], read)).toBe(0);
  });

  it('says how to call it', () => {
    expect(main(['other'], read)).toBe(2);
    expect(errorWrite).toHaveBeenCalledWith(expect.stringContaining('usage: watch.ts images'));
    rmSync(dir, { recursive: true, force: true });
  });
});
