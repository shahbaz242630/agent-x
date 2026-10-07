// The notice sender as the API runs it (B5-3): the outbox's notices sent by
// email through Azure Communication Services, to the address the login
// service gives, each organisation's admins found in their verified
// memberships, and its registered contacts in their verified rows (B6-1b); a
// contact asked to confirm a reset sent its link, read from the reset's
// verified row (B6-3b). Off, and the notices left waiting in the outbox,
// unless the config names email (and so sign-in, whose login service gives
// the addresses).
import { createAddressBook, type IdentityTables, type MembersList, subjectOfUser } from '@agentx/core/modules/identity';
import {
  type Admin,
  type Audience,
  createAcsNotifier,
  createNoticeSender,
  type NoticeSender,
  type NotificationsTables,
  type Outbox,
  type ResetLinks,
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

/**
 * The active admins, and every active member (E2-2b), in an organisation's
 * verified list; its ACTIVE registered contacts, and those that count now
 * (E2-2b). A list that can't be believed throws.
 */
export function audienceFrom(
  listMembers: (orgId: string) => Promise<MembersList>,
  listContacts: (orgId: string) => Promise<readonly string[]>,
  listCountingContacts: (orgId: string) => Promise<readonly string[]>,
): Audience {
  const activeMembers = async (orgId: string) => {
    const listed = await listMembers(orgId);
    if (listed.outcome !== 'listed') throw new AudienceTampered();
    return listed.members.filter((member) => member.status === 'ACTIVE');
  };
  return {
    contactsOf: listContacts,
    countingContactsOf: listCountingContacts,
    async adminsOf(orgId): Promise<readonly Admin[]> {
      return (await activeMembers(orgId))
        .filter((member) => member.role === 'admin')
        .map((member) => ({ userId: member.userId, membershipId: member.id }));
    },
    async adminsAndApproversOf(orgId): Promise<readonly string[]> {
      return (await activeMembers(orgId))
        .filter((member) => member.role === 'admin' || member.role === 'approver')
        .map((member) => member.userId);
    },
    async membersOf(orgId): Promise<readonly string[]> {
      return (await activeMembers(orgId)).map((member) => member.userId);
    },
  };
}

/** The sender, or undefined when the config names no email. */
export function noticeSenderFrom({
  config,
  db,
  outbox,
  listMembers,
  listContacts,
  listCountingContacts,
  contactAddress,
  resetLink,
  fetch,
  logger,
}: {
  readonly config: Config;
  readonly db: Database<IdentityTables & NotificationsTables>;
  readonly outbox: Outbox;
  readonly listMembers: (orgId: string) => Promise<MembersList>;
  /** The organisation's ACTIVE registered contacts' IDs, verified (identity's activeContactsFor). */
  readonly listContacts: (orgId: string) => Promise<readonly string[]>;
  /** Those that count now (identity's countingContactsFor, E2-2b). */
  readonly listCountingContacts: (orgId: string) => Promise<readonly string[]>;
  /** A contact's address from its verified row (identity's contactAddressFor). */
  readonly contactAddress: (orgId: string, contactId: string) => Promise<string | undefined>;
  /** A contact's link to confirm a reset, from its verified row (identity's resetLinkFor, B6-3b). */
  readonly resetLink: ResetLinks['linkFor'];
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
    contactAddresses: { addressOf: contactAddress },
    resetLinks: { linkFor: resetLink },
    audience: audienceFrom(listMembers, listContacts, listCountingContacts),
    logger,
  });
}
