// The notice sender as the API runs it (B5-3): the outbox's notices sent by
// email through Azure Communication Services, to the address the login
// service gives, each organisation's admins found in their verified
// memberships. Off, and the notices left waiting in the outbox, unless the
// config names email (and so sign-in, whose login service gives the addresses).
import { createAddressBook, type IdentityTables, type MembersList, subjectOfUser } from '@agentx/core/modules/identity';
import {
  type Admin,
  type Audience,
  createAcsNotifier,
  createNoticeSender,
  type NoticeSender,
  type NotificationsTables,
  type Outbox,
} from '@agentx/core/modules/notifications';
import { systemClock } from '@agentx/core/shared-kernel';
import type { Config } from '@agentx/platform/config';
import type { Database } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';
import type { OutboundFetch } from '@agentx/platform/outbound';

/** How often the sender looks for due notices, once the last run has ended. */
export const NOTICES_EVERY_MS = 60_000;

/** An organisation's memberships couldn't be believed: its notices wait. */
export class AudienceTampered extends Error {
  override readonly name = 'AudienceTampered';
  constructor() {
    super("the organisation's memberships failed their check");
  }
}

/** The active admins in an organisation's verified list; a list that can't be believed throws. */
export function audienceFrom(listMembers: (orgId: string) => Promise<MembersList>): Audience {
  return {
    async adminsOf(orgId): Promise<readonly Admin[]> {
      const listed = await listMembers(orgId);
      if (listed.outcome !== 'listed') throw new AudienceTampered();
      return listed.members
        .filter((member) => member.role === 'admin' && member.status === 'ACTIVE')
        .map((member) => ({ userId: member.userId, membershipId: member.id }));
    },
  };
}

/** The sender, or undefined when the config names no email. */
export function noticeSenderFrom({
  config,
  db,
  outbox,
  listMembers,
  fetch,
  logger,
}: {
  readonly config: Config;
  readonly db: Database<IdentityTables & NotificationsTables>;
  readonly outbox: Outbox;
  readonly listMembers: (orgId: string) => Promise<MembersList>;
  readonly fetch: OutboundFetch;
  readonly logger: Logger;
}): NoticeSender | undefined {
  const { email, signIn } = config;
  if (email === undefined || signIn === undefined) return undefined;
  return createNoticeSender({
    db,
    outbox,
    notifier: createAcsNotifier({
      settings: { endpoint: email.endpoint, sender: email.sender, accessKey: email.accessKey },
      fetch,
      clock: systemClock,
    }),
    addresses: createAddressBook({
      subjectOf: (userId) => subjectOfUser(db, userId),
      issuer: signIn.issuer,
      internalOrigin: signIn.internalOrigin,
      token: email.directoryToken,
      fetch,
    }),
    audience: audienceFrom(listMembers),
    logger,
  });
}
