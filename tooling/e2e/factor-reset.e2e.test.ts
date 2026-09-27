// B6-3c on the compose stack: the removal a reset ends in, against the real
// login service, with the token the API holds (`agentx-resets`, the
// organisation's Org User Manager role alone, as on staging): the product's
// own remover (idp-factors.ts) takes away a person's app code and email
// codes, reads the login service back with none left, and leaves the
// password; run again, it finds nothing to remove. The token can't read the
// instance's event feed, which is the directory's (IAM Owner Viewer). And the
// API started with the job on. The job's database side is
// reset-removals.db.test.ts; the reset's asking and confirming, B6-3b's.
import { describe, expect, inject, it } from 'vitest';

import { createSecondFactorRemover } from '../../packages/core/src/modules/identity/infrastructure/idp-factors.ts';
import { resetToken } from './api-sign-in.ts';
import { LOGIN_ORIGIN, readAutomationToken, serviceLogs } from './compose.ts';
import { zitadelClient } from './zitadel.ts';

const { users } = inject('e2e');
const target = users.resetTarget;

/** The product's remover, as the API makes it, calling the login service through the stack's edge. */
const remover = () =>
  createSecondFactorRemover({ issuer: LOGIN_ORIGIN, internalOrigin: undefined, token: resetToken(), fetch });

/** The person's methods, as the login service lists them to its automation user. */
async function methodsOf(userId: string): Promise<string[]> {
  const automation = zitadelClient(LOGIN_ORIGIN, await readAutomationToken());
  const { authMethodTypes = [] } = await automation.get<{ authMethodTypes?: string[] }>(
    `/v2/users/${userId}/authentication_methods`,
  );
  return [...authMethodTypes].sort();
}

describe('B6-3c a reset’s removal of every second factor, at the real login service', () => {
  it('starts with the person’s app code and email codes', async () => {
    expect(await methodsOf(target.userId)).toEqual([
      'AUTHENTICATION_METHOD_TYPE_OTP_EMAIL',
      'AUTHENTICATION_METHOD_TYPE_PASSWORD',
      'AUTHENTICATION_METHOD_TYPE_TOTP',
    ]);
  });

  it('SEC-OPS-04 removes both with the reset token, and the login service shows only the password left', async () => {
    expect(await remover().removeAll(target.userId)).toBe(2);

    expect(await methodsOf(target.userId)).toEqual(['AUTHENTICATION_METHOD_TYPE_PASSWORD']);
  });

  it('finds nothing left to remove when run again, as a run after a failed commit would', async () => {
    expect(await remover().removeAll(target.userId)).toBe(0);
  });

  it('holds a token that can’t read the instance’s event feed: the organisation’s users only', async () => {
    const resets = zitadelClient(LOGIN_ORIGIN, resetToken());

    await expect(resets.post('/admin/v1/events/_search', { limit: 1 })).rejects.toThrow(/failed: (401|403)/);
  });

  it('the API started with the resets’ removal on', async () => {
    const started = (await serviceLogs('api'))
      .split(String.fromCharCode(10))
      .filter((line) => line.startsWith('{'))
      .map((line) => JSON.parse(line) as { event: string; removing?: boolean })
      .filter(({ event }) => event === 'api.factor_resets');

    expect(started.at(-1)).toMatchObject({ removing: true });
  });
});
