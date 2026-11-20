import { describe, expect, it } from 'vitest';

import {
  checkCertificates,
  DAYS_LEFT,
  type ManagedCertificate,
  readCertificates,
  type ServedEnd,
} from './certificate-watch.ts';
import type { Az, AzResult } from './deploy.ts';

const NOW = new Date('2026-11-20T04:00:00Z');
const inDays = (days: number): Date => new Date(NOW.getTime() + days * 86_400_000);

const APP: ManagedCertificate = { name: 'mc-agentx-stg-app', host: 'app.example.invalid', state: 'Succeeded' };
const AUTH: ManagedCertificate = { name: 'mc-agentx-stg-auth', host: 'auth.example.invalid', state: 'Succeeded' };

/** Each host's served end date, in days from NOW, or unreadable; every host asked kept. */
function servedBy(ends: Readonly<Record<string, number | 'unreadable'>>) {
  const asked: string[] = [];
  const served: ServedEnd = (host) => {
    asked.push(host);
    const days = ends[host];
    return Promise.resolve(
      days === undefined || days === 'unreadable' ? { unreadable: 'ECONNREFUSED' } : { ends: inDays(days) },
    );
  };
  return { served, asked };
}

describe('checkCertificates', () => {
  it('passes both doors’ certificates, provisioned and with 30 days or more, naming each by its resource alone', async () => {
    const { served } = servedBy({ 'app.example.invalid': 80, 'auth.example.invalid': DAYS_LEFT });
    const { lines, sound } = await checkCertificates([APP, AUTH], served, NOW);
    expect(sound).toBe(true);
    expect(lines).toEqual([
      "mc-agentx-stg-app (the app door's) is provisioned and ends 2027-02-08, in 80 days.",
      "mc-agentx-stg-auth (the auth door's) is provisioned and ends 2026-12-20, in 30 days.",
    ]);
    expect(lines.join('\n')).not.toContain('example.invalid');
  });

  it('fails one under 30 days, one not provisioned, one missing and one unreadable, each with what next', async () => {
    const short = await checkCertificates(
      [APP, AUTH],
      servedBy({ 'app.example.invalid': 29, 'auth.example.invalid': 90 }).served,
      NOW,
    );
    expect(short.sound).toBe(false);
    expect(short.lines[0]).toMatch(
      /^mc-agentx-stg-app \(the app door's\) ends 2026-12-19, in 29 days: under 30, so Azure hasn't renewed it .* What next: .* section U\)\.$/,
    );
    const failed = await checkCertificates([{ ...APP, state: 'Failed' }, AUTH], servedBy({}).served, NOW);
    expect(failed.lines[0]).toMatch(/^mc-agentx-stg-app \(the app door's\) is Failed, not Succeeded: /);
    const missing = await checkCertificates([AUTH], servedBy({ 'auth.example.invalid': 90 }).served, NOW);
    expect(missing).toMatchObject({ sound: false });
    expect(missing.lines[0]).toMatch(/^mc-agentx-stg-app \(the app door's\) isn't in Azure/);
    // Listed with no host: nothing to renew, and nothing to ask.
    const hostless = servedBy({ '': 90, 'auth.example.invalid': 90 });
    const noHost = await checkCertificates([{ ...APP, host: '' }, AUTH], hostless.served, NOW);
    expect(noHost.sound).toBe(false);
    expect(noHost.lines[0]).toMatch(/^mc-agentx-stg-app \(the app door's\) isn't in Azure/);
    expect(hostless.asked).toEqual(['auth.example.invalid']);
    const unread = await checkCertificates([APP, AUTH], servedBy({ 'app.example.invalid': 90 }).served, NOW);
    expect(unread.sound).toBe(false);
    expect(unread.lines[1]).toMatch(
      /^mc-agentx-stg-auth \(the auth door's\) is provisioned, but the certificate its host serves couldn't be read \(ECONNREFUSED\)/,
    );
    for (const outcome of [short, failed, missing, unread]) {
      expect(outcome.lines.join('\n')).not.toContain('example.invalid');
    }
  });

  it('takes Azure’s own end date where the certificate carries one, and asks the host only otherwise', async () => {
    const { served, asked } = servedBy({ 'app.example.invalid': 90 });
    const { lines, sound } = await checkCertificates(
      [APP, { ...AUTH, expires: inDays(10).toISOString() }],
      served,
      NOW,
    );
    expect(sound).toBe(false);
    expect(asked).toEqual(['app.example.invalid']);
    expect(lines[1]).toMatch(/^mc-agentx-stg-auth \(the auth door's\) ends 2026-11-30, in 10 days/);
    // An end date that isn't one is set aside for the host's own.
    const odd = servedBy({ 'app.example.invalid': 90, 'auth.example.invalid': 90 });
    expect((await checkCertificates([APP, { ...AUTH, expires: 'soon' }], odd.served, NOW)).sound).toBe(true);
    expect(odd.asked).toEqual(['app.example.invalid', 'auth.example.invalid']);
  });
});

describe('readCertificates', () => {
  it('lists the environment’s managed certificates through Resource Manager, with read rights alone', () => {
    const calls: (readonly string[])[] = [];
    const az: Az = {
      interactive: () => {
        throw new Error('never interactive');
      },
      run: (args): AzResult => {
        calls.push(args);
        return {
          status: 0,
          stderr: '',
          stdout: JSON.stringify({
            value: [
              {
                name: 'mc-agentx-stg-app',
                properties: { subjectName: 'app.example.invalid', provisioningState: 'Succeeded' },
              },
              {
                name: 'mc-agentx-stg-auth',
                properties: {
                  subjectName: 'auth.example.invalid',
                  provisioningState: 'Pending',
                  expirationDate: '2027-01-01T00:00:00Z',
                },
              },
            ],
          }),
        };
      },
    };
    expect(readCertificates(az, '00000000-0000-0000-0000-000000000000')).toEqual([
      APP,
      { ...AUTH, state: 'Pending', expires: '2027-01-01T00:00:00Z' },
    ]);
    expect(calls).toEqual([
      [
        'rest',
        '--method',
        'get',
        '--url',
        'https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-agentx-staging/providers/Microsoft.App/managedEnvironments/cae-agentx-staging/managedCertificates?api-version=2026-01-01',
        '--output',
        'json',
      ],
    ]);
  });
});
