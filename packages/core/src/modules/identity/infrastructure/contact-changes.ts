// Adding and removing registered contacts (ADR-012 §1, §8; SEC-OPS-06;
// B6-1c): an admin's change to the organisation's trust anchor, each with a
// step-up (ADR-003 §8), each told to the organisation's admins and its
// contacts, a removed contact told of its own removal too.
//
// 1. `add` (`contacts.add`): the key claimed first; the organisation's
//    contact changes one at a time, as confirm; the admin read again, active
//    and still an admin; the organisation within its budget of contacts
//    started (CONTACT_ADDS_SPENT, B8-2); the organisation's contacts, every one
//    verified, so the address isn't one of its ACTIVE contacts already
//    (CONTACT_EXISTS) and there is room (CONTACTS_FULL); then the pending
//    change's SHA-256 bound into a step-up challenge for the admin's own
//    session; the contact kept as a DRAFT naming the challenge. Answered 202.
// 2. `confirm` (`contacts.add.confirm`): the key claimed first; the
//    organisation's contact changes one at a time (a transaction advisory
//    lock, so two confirmations can't both find room for the last place); the
//    admin read again; the draft read for the change and its hash worked out
//    again from the verified row and its address; the contacts checked again
//    as the add did; the challenge the draft names consumed only for this
//    session, action and hash, with a passkey (SEC-HA-12); the contact's start
//    set a cooling-off from now and the contact made ACTIVE, with the
//    step-up's evidence; the admins and the contacts told, in the same
//    transaction (the new contact is ACTIVE when they are found, so it is
//    told too).
// 3. `remove` (`contacts.remove`): the key claimed first; the admin read
//    again; the contact, ACTIVE; a step-up challenge bound to it. The
//    challenge is the write's resource, so a retry answers the same one.
// 4. `removeConfirm` (`contacts.remove.confirm`): the key claimed first; the
//    admin read again; the contact read for the change, ACTIVE; the challenge
//    named consumed only for this session, action and hash, with a passkey;
//    the contact REMOVED, with the step-up's evidence; the admins, the
//    remaining contacts and the removed contact told.
//
// A refusal throws inside the write, so the claim and everything written roll
// back and the same key may be sent again. Each statement is limited to 10
// seconds.
import { createIdempotentWrites, holdTransactionLock, type IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely, Transaction } from 'kysely';

import { type Clock, DAY_MS, type IdGenerator, type ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import type { Notice, NotificationsTables, Outbox } from '../../notifications/index.ts';
import { contactCountsFrom, MOST_CONTACTS, MOST_CONTACTS_STARTED_A_DAY } from '../domain/registered-contact.ts';
import type { InvitingAdmin } from './inviting.ts';
import {
  activateContact,
  contactChange,
  contactRecordsCount,
  type ContactWithAddress,
  contactShown,
  contactsOf,
  contactToActivate,
  contactToRemove,
  draftContact,
  MOST_CONTACT_RECORDS,
  removeContact,
  TooManyContacts,
} from './registered-contacts.ts';
import { type StepUpChallenges, stepUpDetails } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { activeAdminId, Refusal } from './refusals.ts';

/** Asking to add a contact: its operation, which the step-up challenge names as its action too. */
export const CONTACT_ADD_OPERATION = 'contacts.add';
/** Adding it, once stepped up. */
export const CONTACT_ADD_CONFIRM_OPERATION = 'contacts.add.confirm';
/** Asking to remove a contact. */
export const CONTACT_REMOVE_OPERATION = 'contacts.remove';
/** Removing it, once stepped up. */
export const CONTACT_REMOVE_CONFIRM_OPERATION = 'contacts.remove.confirm';

/** What a contact change's write answers. */
export type ContactChangeWrite =
  | {
      readonly outcome: 'written';
      readonly status: number;
      readonly contact: ContactWithAddress;
      /** The step-up to sign in again for, while the contact is a DRAFT. */
      readonly stepUpChallengeId?: string;
    }
  | { readonly outcome: 'asked'; readonly stepUpChallengeId: string }
  | { readonly outcome: 'conflict' | 'busy' }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

export interface ContactChanges {
  add(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    email: string,
    correlationId: string,
  ): Promise<ContactChangeWrite>;
  confirm(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    contactId: string,
    correlationId: string,
  ): Promise<ContactChangeWrite>;
  remove(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    contactId: string,
    correlationId: string,
  ): Promise<ContactChangeWrite>;
  removeConfirm(
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    contactId: string,
    stepUpChallengeId: string,
    correlationId: string,
  ): Promise<ContactChangeWrite>;
}

class ContactRefused extends Refusal {
  constructor(status: number, code: ReasonCode) {
    super(`a registered contact's change refused: ${code}`, status, code);
    this.name = 'ContactRefused';
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables;

/**
 * The notices of a contact added or removed, in the change's transaction: to
 * the organisation's admins and its ACTIVE contacts, found as they are sent,
 * and to a removed contact itself.
 */
const noticesOf = (orgId: string, contactId: string, kind: 'contact_added' | 'contact_removed'): Notice[] => {
  const about = { orgId, kind, membershipId: null, role: null, aboutId: contactId } as const;
  return [
    { ...about, recipientUserId: null },
    { ...about, recipientUserId: null, toContacts: true },
    ...(kind === 'contact_removed' ? [{ ...about, recipientUserId: null, recipientContactId: contactId }] : []),
  ];
};

export function createContactChanges({
  database,
  keys,
  ids,
  clock,
  challenges,
  outbox,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly challenges: StepUpChallenges;
  /** Where the notices of each change are written (B6-1b). */
  readonly outbox: Outbox;
  readonly logger: Logger;
}): ContactChanges {
  /** Refuses an address one of the organisation's ACTIVE contacts has already, or a list with no room. */
  const mustHaveRoomFor = async (tx: Transaction<Tables>, states: SignedStates, orgId: string, email: string) => {
    const listed = await contactsOf(tx, states, keys, orgId);
    if (listed.outcome === 'tampered') throw new ContactRefused(503, 'INTEGRITY_FAILED');
    const active = listed.contacts.filter((contact) => contact.status === 'ACTIVE');
    if (active.some((contact) => contact.email === email)) throw new ContactRefused(409, 'CONTACT_EXISTS');
    if (active.length >= MOST_CONTACTS) throw new ContactRefused(409, 'CONTACTS_FULL');
  };

  /**
   * Refuses a contact started past the organisation's budget of
   * MOST_CONTACTS_STARTED_A_DAY (CONTACT_ADDS_SPENT, B8-2), and warns once its
   * records pass half of what the list reads, long before it can't be read.
   * Under oneAtATime's lock, so two adds at once can't both take the last one.
   */
  const withinBudget = async (tx: Transaction<Tables>, orgId: string, log: Logger): Promise<void> => {
    const count = await contactRecordsCount(tx, orgId, new Date(clock.now().getTime() - DAY_MS));
    if (count.held * 2 >= MOST_CONTACT_RECORDS)
      log.warn('identity.records_filling', {
        records: 'registered_contacts',
        held: count.held,
        most: MOST_CONTACT_RECORDS,
      });
    if (count.started >= MOST_CONTACTS_STARTED_A_DAY) throw new ContactRefused(409, 'CONTACT_ADDS_SPENT');
  };

  /** Runs the write in the organisation's transaction, its key claimed first; a refusal becomes an answer. */
  const write = async (
    admin: InvitingAdmin,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: Transaction<Tables>, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const services = { keys, ids, logger: logger.child({ correlationId }) };
    const idempotency = createIdempotentWrites({ keys, logger: services.logger });
    try {
      return await withSignedStates(database, admin.orgId, services, (tx, states) =>
        idempotency.run(tx, idempotent, () => work(tx, states)),
      );
    } catch (error) {
      if (error instanceof ContactRefused)
        return { outcome: 'refused' as const, status: error.status, code: error.code };
      if (error instanceof TooManyContacts)
        return { outcome: 'refused' as const, status: 409, code: 'TOO_MANY_CONTACTS' as const };
      throw error;
    }
  };

  /** Answers from the contact as it now stands, re-read by its ID, on a replay too. */
  const answer = async (
    admin: InvitingAdmin,
    correlationId: string,
    status: number,
    contactId: string,
  ): Promise<ContactChangeWrite> => {
    const read = await withSignedStates(
      database,
      admin.orgId,
      { keys, ids, logger: logger.child({ correlationId }) },
      (tx, states) => contactShown(tx, states, keys, admin.orgId, contactId),
    );
    if (read.outcome === 'tampered') return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
    if (read.outcome === 'missing') throw new Error('a contact written, or written before, is not there');
    const { contact } = read;
    return {
      outcome: 'written',
      status,
      contact,
      ...(contact.status === 'DRAFT' && { stepUpChallengeId: contact.stepUpChallengeId }),
    };
  };

  /** Serialises the organisation's contact changes, so a check for room holds until the change commits. */
  const oneAtATime = async (tx: Transaction<Tables>, orgId: string): Promise<void> => {
    await holdTransactionLock(tx, 'registered-contacts', orgId);
  };

  return {
    async add(admin, idempotent, email, correlationId) {
      const done = await write(admin, idempotent, correlationId, async (tx, states) => {
        await oneAtATime(tx, admin.orgId);
        const addedBy = await activeAdminId(tx, states, admin, ContactRefused);
        await withinBudget(tx, admin.orgId, logger.child({ correlationId }));
        const id = ids.next();
        const { change, changeHash } = contactChange({ orgId: admin.orgId, id, email, addedBy });
        await mustHaveRoomFor(tx, states, admin.orgId, change.email);
        const challenge = await challenges.open(tx, {
          sessionId: admin.sessionId,
          action: CONTACT_ADD_OPERATION,
          changeHash,
        });
        // The session ended since the access hook found it.
        if (challenge === undefined) throw new ContactRefused(401, 'UNAUTHENTICATED');
        await draftContact(tx, states, keys, change, {
          stepUpChallengeId: challenge.challengeId,
          createdAt: clock.now(),
          actor: { type: 'user', id: admin.userId },
        });
        return { status: 202, resourceId: id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, correlationId, done.result.status, done.result.resourceId);
    },

    async confirm(admin, idempotent, contactId, correlationId) {
      const done = await write(admin, idempotent, correlationId, async (tx, states) => {
        await oneAtATime(tx, admin.orgId);
        const held = await challenges.hold(tx, admin.sessionId);
        await activeAdminId(tx, states, admin, ContactRefused);
        const read = await contactToActivate(tx, states, keys, { orgId: admin.orgId, id: contactId });
        if (read.outcome === 'missing') throw new ContactRefused(404, 'NOT_FOUND');
        if (read.outcome === 'tampered') throw new ContactRefused(503, 'INTEGRITY_FAILED');
        if (read.outcome !== 'draft') throw new ContactRefused(409, 'CONTACT_CLOSED');
        await mustHaveRoomFor(tx, states, admin.orgId, read.change.email);
        const consumed = await challenges.consume(
          tx,
          held,
          read.contact.stepUpChallengeId,
          { sessionId: admin.sessionId, action: CONTACT_ADD_OPERATION, changeHash: read.changeHash },
          // An admin's change: proved with a passkey (SEC-HA-12).
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new ContactRefused(403, 'STEP_UP_FAILED');
        await activateContact(tx, states, {
          orgId: admin.orgId,
          id: read.contact.id,
          state: read.state,
          countsFrom: contactCountsFrom(clock.now()),
          actor: { type: 'user', id: admin.userId },
          details: stepUpDetails(consumed),
        });
        await outbox.add(tx, noticesOf(admin.orgId, read.contact.id, 'contact_added'));
        return { status: 200, resourceId: read.contact.id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, correlationId, done.result.status, done.result.resourceId);
    },

    async remove(admin, idempotent, contactId, correlationId) {
      const done = await write(admin, idempotent, correlationId, async (tx, states) => {
        await activeAdminId(tx, states, admin, ContactRefused);
        const read = await contactToRemove(tx, states, { orgId: admin.orgId, id: contactId });
        if (read.outcome === 'missing') throw new ContactRefused(404, 'NOT_FOUND');
        if (read.outcome === 'tampered') throw new ContactRefused(503, 'INTEGRITY_FAILED');
        if (read.outcome !== 'active') throw new ContactRefused(409, 'CONTACT_NOT_ACTIVE');
        const challenge = await challenges.open(tx, {
          sessionId: admin.sessionId,
          action: CONTACT_REMOVE_OPERATION,
          changeHash: read.changeHash,
        });
        if (challenge === undefined) throw new ContactRefused(401, 'UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return { outcome: 'asked', stepUpChallengeId: done.result.resourceId };
    },

    async removeConfirm(admin, idempotent, contactId, stepUpChallengeId, correlationId) {
      const done = await write(admin, idempotent, correlationId, async (tx, states) => {
        await oneAtATime(tx, admin.orgId);
        const held = await challenges.hold(tx, admin.sessionId);
        await activeAdminId(tx, states, admin, ContactRefused);
        const read = await contactToRemove(tx, states, { orgId: admin.orgId, id: contactId });
        if (read.outcome === 'missing') throw new ContactRefused(404, 'NOT_FOUND');
        if (read.outcome === 'tampered') throw new ContactRefused(503, 'INTEGRITY_FAILED');
        if (read.outcome !== 'active') throw new ContactRefused(409, 'CONTACT_NOT_ACTIVE');
        const consumed = await challenges.consume(
          tx,
          held,
          stepUpChallengeId,
          { sessionId: admin.sessionId, action: CONTACT_REMOVE_OPERATION, changeHash: read.changeHash },
          { passkeyRequired: true },
        );
        if (consumed === undefined) throw new ContactRefused(403, 'STEP_UP_FAILED');
        await removeContact(tx, states, {
          orgId: admin.orgId,
          id: read.contact.id,
          actor: { type: 'user', id: admin.userId },
          details: stepUpDetails(consumed),
        });
        await outbox.add(tx, noticesOf(admin.orgId, read.contact.id, 'contact_removed'));
        return { status: 200, resourceId: read.contact.id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      return answer(admin, correlationId, done.result.status, done.result.resourceId);
    },
  };
}
