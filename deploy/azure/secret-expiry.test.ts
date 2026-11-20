import { beforeAll, describe, expect, it } from 'vitest';

import { COPIED_SECRETS, VAULT_SECRETS } from './deploy.ts';
import { expiryFor, expiryLine, expiryProblems, periodOf, readExpiry } from './secret-expiry.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

const schedule = readExpiry();
const day = (seconds: number | undefined): string => new Date((seconds ?? 0) * 1000).toISOString().slice(0, 10);

/** Each vault secret staging's secrets deployment writes, with the attributes it sends, from the pinned Bicep. */
let written: ReadonlyMap<string, unknown>;

beforeAll(() => {
  const staging = inCopy((dir) => environmentSnapshot(dir, 'staging')).together;
  written = new Map(
    staging.predictedResources
      .filter((resource) => resource.type === 'Microsoft.KeyVault/vaults/secrets')
      .map((resource) => [
        resource.name.split('/').at(-1) ?? '',
        (resource.properties as { attributes?: unknown }).attributes,
      ]),
  );
});

describe('secret-expiry.json (PL-25)', () => {
  it('names every secret a secrets run writes by name, and no other', () => {
    expect(Object.keys(schedule.secrets).toSorted()).toEqual(
      [...Object.keys(VAULT_SECRETS), ...COPIED_SECRETS].toSorted(),
    );
    for (const period of [...Object.values(schedule.secrets), schedule.keys, schedule.publicHalves]) {
      expect(period).toMatch(/^(?:P[12]Y)?$/);
    }
  });

  it('gives each the schedule Secrets-Register.md sets', () => {
    for (const name of ['db-admin-password', 'db-owner-password', 'db-app-password', 'db-backup-password']) {
      expect(periodOf(name)).toBe('P1Y');
    }
    expect(periodOf('db-operator-password')).toBe('P1Y');
    expect(periodOf('db-zitadel-password')).toBe('P1Y');
    expect(periodOf('login-client-private-key')).toBe('P1Y');
    expect(periodOf('api-oidc-client-secret')).toBe('P1Y');
    expect(periodOf('zitadel-directory-token')).toBe('P1Y');
    expect(periodOf('zitadel-reset-token')).toBe('P1Y');
    expect(periodOf('acs-access-key')).toBe('P1Y');
    expect(periodOf('login-cookie-secret')).toBe('P1Y');
    // Never rotated routinely, used once, or not credentials: no date.
    for (const name of [
      'zitadel-masterkey',
      'zitadel-machine-config',
      'zitadel-admin-password',
      'zitadel-our-actors',
      'zitadel-our-service-users',
    ]) {
      expect(periodOf(name)).toBe('');
    }
    // The app's keys two years, but the payee index (never rotated in place); the public halves with their keys.
    expect(periodOf('key-audit-mac-v1')).toBe('P2Y');
    expect(periodOf('key-audit-mac-v12')).toBe('P2Y');
    expect(periodOf('key-payee-index-v1')).toBe('');
    expect(periodOf('public-operator-signing-v1')).toBe('');
    // A job's held request is written per run: never held to a date.
    expect(periodOf('operator-request')).toBeUndefined();
  });

  it('is what secrets.bicep sends: each written secret dated from the first of the run’s month, or not at all', () => {
    // The snapshot leaves the run's month to Azure (utcNow), so the date is read as the expression expiryFor mirrors.
    const dated = (period: string): string =>
      `[dateTimeToEpoch(dateTimeAdd(format('{0}-01T00:00:00Z', utcNow('yyyy-MM')), '${period}'))]`;
    expect(written.size).toBeGreaterThan(20);
    for (const [name, attributes] of written) {
      const period = periodOf(name);
      expect(period, name).toBeDefined();
      expect(attributes, name).toEqual(period === '' || period === undefined ? {} : { exp: dated(period) });
    }
    expect(written.get('key-audit-mac-v1')).toEqual({ exp: dated('P2Y') });
    expect(written.get('key-payee-index-v1')).toEqual({});
    expect(written.get('acs-access-key')).toEqual({ exp: dated('P1Y') });
  });
});

describe('expiryFor', () => {
  it('counts from the first of the month, in whole years, and refuses any other period', () => {
    expect(day(expiryFor('P1Y', new Date('2026-09-16T16:42:15Z')))).toBe('2027-09-01');
    expect(day(expiryFor('P2Y', new Date('2026-12-31T23:59:59Z')))).toBe('2028-12-01');
    for (const period of ['', 'P12M', 'P0Y', 'P1Y2M']) {
      expect(() => expiryFor(period, new Date())).toThrow(/not a whole number of years/);
    }
  });
});

describe('expiryProblems', () => {
  const started = new Date('2026-09-30T23:59:00Z');
  const ended = new Date('2026-10-01T00:01:00Z');
  const september = expiryFor('P1Y', started);
  const october = expiryFor('P1Y', ended);

  it('passes what the run left alone, a held request, and each written secret with its month’s date', () => {
    expect(
      expiryProblems(
        [
          { name: 'db-app-password', version: '1' },
          { name: 'acs-access-key', version: '1' },
          { name: 'zitadel-masterkey', version: '1' },
        ],
        [
          // Left alone: whatever date it carries.
          { name: 'db-app-password', version: '1' },
          // Written either side of the month's end.
          { name: 'acs-access-key', version: '2', expires: september },
          { name: 'login-cookie-secret', version: '1', expires: october },
          { name: 'zitadel-masterkey', version: '1', expires: 5 },
          { name: 'operator-request', version: '9' },
          { name: 'key-session-mac-v1', version: '1', expires: expiryFor('P2Y', ended) },
          { name: 'key-payee-index-v1', version: '1' },
        ],
        started,
        ended,
      ),
    ).toEqual([]);
  });

  it('says each written secret with no date, another date, or one nobody scheduled', () => {
    expect(
      expiryProblems(
        [{ name: 'acs-access-key', version: '1' }],
        [
          { name: 'acs-access-key', version: '2' },
          { name: 'db-app-password', version: '1', expires: october + 86_400 },
          { name: 'key-payee-index-v1', version: '1', expires: october },
        ],
        started,
        ended,
      ),
    ).toEqual([
      "acs-access-key was written with expiry date none, not 2027-10-01 as the schedule says: secrets.bicep didn't set it, so the vault won't say when it is due. Run the same secrets command again; if it stays, fix secrets.bicep in a reviewed PR",
      "db-app-password was written with expiry date 2027-10-02, not 2027-10-01 as the schedule says: secrets.bicep didn't set it, so the vault won't say when it is due. Run the same secrets command again; if it stays, fix secrets.bicep in a reviewed PR",
      "key-payee-index-v1 was written with an expiry date (2027-10-01) the schedule doesn't give it: secret-expiry.json and secrets.bicep disagree, so fix them in a reviewed PR",
    ]);
  });
});

describe('expiryLine', () => {
  it('says the date, or that there is none', () => {
    expect(
      expiryLine({ name: 'db-app-password', version: '1', expires: expiryFor('P1Y', new Date('2026-09-16')) }),
    ).toBe('  db-app-password: expires 2027-09-01');
    expect(expiryLine({ name: 'zitadel-masterkey', version: '1' })).toBe('  zitadel-masterkey: no expiry date');
  });
});
