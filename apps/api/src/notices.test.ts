// B5-3: the notices as the API runs them: whom the audience gives, and that
// the sender is off unless the config names email.
import type { MemberRecord, MembersList } from '@agentx/core/modules/identity';
import { loadConfig } from '@agentx/platform/config';
import { createLogger } from '@agentx/platform/observability';
import { describe, expect, it } from 'vitest';

import { AudienceTampered, audienceFrom, noticeSenderFrom } from './notices.ts';

const ORG = '01a0f000-0000-7000-8000-0000000000aa';

const member = (id: string, role: MemberRecord['role'], status: MemberRecord['status']): MemberRecord => ({
  id,
  userId: `user-${id}`,
  role,
  status,
  joinedAt: new Date('2026-09-26T09:00:00Z'),
});

describe('SEC-HA-11 the notices as the API runs them', () => {
  it("gives an organisation's active admins alone, each by user and membership", async () => {
    const listed: MembersList = {
      outcome: 'listed',
      members: [
        member('m1', 'admin', 'ACTIVE'),
        member('m2', 'admin', 'DEACTIVATED'),
        member('m3', 'approver', 'ACTIVE'),
        member('m4', 'viewer', 'ACTIVE'),
        member('m5', 'developer', 'ACTIVE'),
        member('m6', 'admin', 'ACTIVE'),
      ],
    };
    const asked: string[] = [];
    const audience = audienceFrom((orgId) => {
      asked.push(orgId);
      return Promise.resolve(listed);
    });
    await expect(audience.adminsOf(ORG)).resolves.toEqual([
      { userId: 'user-m1', membershipId: 'm1' },
      { userId: 'user-m6', membershipId: 'm6' },
    ]);
    expect(asked).toEqual([ORG]);
  });

  it('throws for memberships that failed their check, so the notice waits and names nobody', async () => {
    const tampered = { outcome: 'tampered', sign: {} } as unknown as MembersList;
    await expect(audienceFrom(() => Promise.resolve(tampered)).adminsOf(ORG)).rejects.toThrow(AudienceTampered);
  });

  it('is off without email in the config, and on with it', () => {
    const base = {
      AGENTX_ENV: 'development',
      AGENTX_DB_HOST: 'db',
      AGENTX_DB_PASSWORD: 'app login for these tests',
      AGENTX_KEYS_DIR: '/mnt/secrets',
    };
    const signIn = {
      ...base,
      AGENTX_OUTBOUND_ALLOWED_ORIGINS: 'https://auth.agentx.example,https://acs.agentx.example',
      AGENTX_OIDC_ISSUER: 'https://auth.agentx.example',
      AGENTX_OIDC_CLIENT_ID: 'agentx-api',
      AGENTX_OIDC_CLIENT_SECRET: 'client pass words',
    };
    const email = {
      ...signIn,
      AGENTX_EMAIL_ENDPOINT: 'https://acs.agentx.example',
      AGENTX_EMAIL_SENDER: 'DoNotReply@agentx.example',
      // Plain words, built at run time, as every stand-in for a secret here.
      AGENTX_EMAIL_ACCESS_KEY: Buffer.from('stand in email words').toString('base64'),
      AGENTX_DIRECTORY_TOKEN: ['directory', 'words'].join('-'),
    };
    const logger = createLogger({ service: 'api', config: loadConfig(base), destination: { write: () => true } });
    const senderWith = (env: Record<string, string>) =>
      noticeSenderFrom({
        config: loadConfig(env),
        db: {} as never,
        outbox: {} as never,
        listMembers: () => Promise.reject(new Error('not asked')),
        fetch: () => Promise.reject(new Error('not called')),
        logger,
      });
    expect(senderWith(base)).toBeUndefined();
    expect(senderWith(signIn)).toBeUndefined();
    expect(senderWith(email)).toBeDefined();
  });
});
