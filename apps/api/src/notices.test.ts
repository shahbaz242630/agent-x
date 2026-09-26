// B5-3: the notices as the API runs them: whom the audience gives, and that
// the sender is off unless the config names email.
import type { MemberRecord, MembersList } from '@agentx/core/modules/identity';
import type { ClaimedNotice } from '@agentx/core/modules/notifications';
import { loadConfig } from '@agentx/platform/config';
import { createLogger } from '@agentx/platform/observability';
import type { OutboundFetch } from '@agentx/platform/outbound';
import { describe, expect, it } from 'vitest';

import { AudienceTampered, audienceFrom, noticeSenderFrom } from './notices.ts';

const ORG = '01a0f000-0000-7000-8000-0000000000aa';
const ISSUER = 'https://auth.agentx.example';
const ENDPOINT = 'https://acs.agentx.example';
const SUBJECT = '338719472394810051';

const BASE = {
  AGENTX_ENV: 'development',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_PASSWORD: 'app login for these tests',
  AGENTX_KEYS_DIR: '/mnt/secrets',
};
const SIGN_IN = {
  ...BASE,
  AGENTX_OUTBOUND_ALLOWED_ORIGINS: `${ISSUER},${ENDPOINT}`,
  AGENTX_OIDC_ISSUER: ISSUER,
  AGENTX_OIDC_CLIENT_ID: 'agentx-api',
  AGENTX_OIDC_CLIENT_SECRET: 'client pass words',
};
const EMAIL = {
  ...SIGN_IN,
  AGENTX_EMAIL_ENDPOINT: ENDPOINT,
  AGENTX_EMAIL_SENDER: 'DoNotReply@agentx.example',
  // Plain words, built at run time, as every stand-in for a secret here.
  AGENTX_EMAIL_ACCESS_KEY: Buffer.from('stand in email words').toString('base64'),
  AGENTX_DIRECTORY_TOKEN: ['directory', 'words'].join('-'),
};

const logger = createLogger({ service: 'api', config: loadConfig(BASE), destination: { write: () => true } });

/** The sender a config gives, with stand-ins for what it reaches. */
function senderWith(
  env: Record<string, string>,
  parts: { readonly db?: unknown; readonly outbox?: unknown; readonly fetch?: OutboundFetch } = {},
) {
  return noticeSenderFrom({
    config: loadConfig(env),
    db: (parts.db ?? {}) as never,
    outbox: (parts.outbox ?? {}) as never,
    listMembers: () => Promise.reject(new Error('not asked')),
    fetch: parts.fetch ?? (() => Promise.reject(new Error('not called'))),
    logger,
  });
}

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
    expect(senderWith(BASE)).toBeUndefined();
    expect(senderWith(SIGN_IN)).toBeUndefined();
    expect(senderWith(EMAIL)).toBeDefined();
  });

  it("sends a due notice end to end: the user's subject, their verified address from Zitadel, one signed send to ACS", async () => {
    const notice: ClaimedNotice = {
      id: '01a0f000-0000-7000-8000-0000000000c1',
      orgId: ORG,
      recipientUserId: '01a0f000-0000-7000-8000-0000000000d1',
      kind: 'role_granted',
      membershipId: '01a0f000-0000-7000-8000-0000000000e1',
      role: 'admin',
      createdAt: new Date('2026-09-26T12:00:00Z'),
      attempts: 0,
    };
    const asked: string[] = [];
    const done: string[] = [];
    let due = [notice];
    const outbox = {
      claimDue: () => {
        const claimed = due;
        due = [];
        return Promise.resolve(claimed);
      },
      sent: (_db: unknown, id: string) => {
        done.push(`sent ${id}`);
        return Promise.resolve(true);
      },
      failed: (_db: unknown, id: string, failure: string) => {
        done.push(`failed ${id} ${failure}`);
        return Promise.resolve('retry' as const);
      },
    };
    // The one row the address book reads: the user's issuer and subject.
    const users = {
      selectFrom: () => ({
        select: () => ({
          where: () => ({ executeTakeFirst: () => Promise.resolve({ issuer: ISSUER, subject: SUBJECT }) }),
        }),
      }),
    };
    const sent: { url: string; body: unknown }[] = [];
    const sender = senderWith(EMAIL, {
      db: users,
      outbox,
      fetch: (url, init = {}) => {
        asked.push(String(url));
        if (String(url) === `${ISSUER}/v2/users/${SUBJECT}`) {
          const user = { user: { human: { email: { email: 'Sara@Example.test', isVerified: true } } } };
          return Promise.resolve(new Response(JSON.stringify(user), { status: 200 }));
        }
        sent.push({ url: String(url), body: JSON.parse(init.body as string) as unknown });
        return Promise.resolve(new Response(null, { status: 202 }));
      },
    });
    await sender?.run();
    expect(asked).toEqual([`${ISSUER}/v2/users/${SUBJECT}`, `${ENDPOINT}/emails:send?api-version=2025-09-01`]);
    expect(sent).toEqual([
      {
        url: `${ENDPOINT}/emails:send?api-version=2025-09-01`,
        body: expect.objectContaining({
          senderAddress: 'DoNotReply@agentx.example',
          recipients: { to: [{ address: 'sara@example.test' }] },
        }) as unknown,
      },
    ]);
    expect(done).toEqual([`sent ${notice.id}`]);
  });
});
