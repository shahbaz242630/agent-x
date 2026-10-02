// A registered contact confirming a reset of a member's lost second factor,
// by the link it was emailed (ADR-003 §4, ADR-012 §8; SEC-OPS-04; B6-3b-3):
// the one change anyone makes without signing in, so it trusts nothing but
// the secret its link carries.
//
// In the organisation the link names, in one transaction:
// 1. the secret checked against the one written for that reset and contact,
//    in constant time, before anything about either is read: a link that
//    isn't one we wrote, for whatever reason, is NOT_FOUND alike, so a
//    guessed or altered link learns nothing; a secret that won't open is the
//    row planted or copied (503 INTEGRITY_FAILED);
// 2. the person the reset's row names, their membership read (level 2a) to
//    tell them;
// 3. the contact read again (2b): it must count now (CONTACT_NOT_ACTIVE for
//    one removed since it was asked);
// 4. the reset read for the change (2c), naming the same person: waiting for
//    a contact and not lapsed (RESET_CLOSED otherwise); one this same
//    contact confirmed already answers as it did, so the page may be pressed
//    twice (a public write takes no idempotency key, so it must be safe to
//    repeat);
// 5. the contact named, the cooling-off set from now, COOLING_OFF; the person,
//    the admins and the contacts told, in the same transaction.
//
// The answer tells a caller who holds the link only that it confirmed, and
// when the factor is removed: nothing of the person or organisation. Each
// statement is limited to 10 seconds.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely } from 'kysely';

import type { Clock, IdGenerator, ReasonCode } from '../../../shared-kernel/index.ts';
import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import type { NotificationsTables, Outbox } from '../../notifications/index.ts';
import { confirmableAt, resetCoolingOffUntil } from '../domain/factor-reset.ts';
import { countsNow } from '../domain/registered-contact.ts';
import {
  ConfirmationUnreadable,
  confirmationMatches,
  confirmReset,
  listedPersonOf,
  resetForChange,
  resetLinkToken,
} from './factor-resets.ts';
import { toldOfReset } from './grant-notices.ts';
import { memberOf } from './memberships.ts';
import { contactRecord } from './registered-contacts.ts';
import type { IdentityTables } from './tables.ts';
import { Refusal } from './refusals.ts';

/** What a contact's confirmation answers. */
export type ContactConfirmation =
  | { readonly outcome: 'confirmed'; readonly coolingOffUntil: Date }
  | { readonly outcome: 'refused'; readonly status: number; readonly code: ReasonCode };

export interface ContactConfirmations {
  /** Confirms the reset the link's token names, as its contact. */
  confirm(token: string, correlationId: string): Promise<ContactConfirmation>;
}

class ConfirmationRefused extends Refusal {
  constructor(status: number, code: ReasonCode) {
    super(`a contact's confirmation refused: ${code}`, status, code);
    this.name = 'ConfirmationRefused';
  }
}

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables;

export function createContactConfirmations({
  database,
  keys,
  ids,
  clock,
  outbox,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** Where the notices of the confirmation are written (0026). */
  readonly outbox: Outbox;
  readonly logger: Logger;
}): ContactConfirmations {
  return {
    async confirm(token, correlationId) {
      const link = resetLinkToken(token);
      if (link === undefined) return { outcome: 'refused', status: 404, code: 'NOT_FOUND' };
      const { orgId, resetId, contactId } = link;
      const services = { keys, ids, logger: logger.child({ correlationId }) };
      try {
        const coolingOffUntil = await withSignedStates(database, orgId, services, async (tx, states) => {
          const matched = await confirmationMatches(tx, keys, link);
          if (matched !== 'matches') throw new ConfirmationRefused(404, 'NOT_FOUND');
          // A secret was written for them, so the reset and the contact are the organisation's.
          const personId = await listedPersonOf(tx, orgId, resetId);
          if (personId === undefined) throw new ConfirmationRefused(503, 'INTEGRITY_FAILED');
          const person = await memberOf(tx, states, { orgId, id: personId }, 'share');
          const contact = await contactRecord(tx, states, orgId, contactId);
          const read = await resetForChange(tx, states, { orgId, id: resetId });
          // Missing is the row gone past the app, which never deletes one: tampering too. The reset's
          // person is sealed, and verified here from the row just read, so it is the one read above.
          if (person.outcome !== 'found' || contact.outcome !== 'found' || read.outcome !== 'found') {
            throw new ConfirmationRefused(503, 'INTEGRITY_FAILED');
          }
          const { reset } = read;
          const now = clock.now();
          // Pressed again: answered as the first press was.
          if (reset.status === 'COOLING_OFF' && reset.confirmedBy === contactId && reset.coolingOffUntil !== null) {
            return reset.coolingOffUntil;
          }
          if (!countsNow(contact.contact, now)) throw new ConfirmationRefused(409, 'CONTACT_NOT_ACTIVE');
          if (reset.status !== 'AWAITING_CONTACT' || !confirmableAt(reset.expiresAt, now)) {
            throw new ConfirmationRefused(409, 'RESET_CLOSED');
          }
          const until = resetCoolingOffUntil(now);
          await confirmReset(tx, states, {
            orgId,
            id: resetId,
            state: read.state,
            contactId,
            coolingOffUntil: until,
            details: {},
          });
          await outbox.add(tx, toldOfReset(orgId, 'factor_reset_confirmed', person.member.userId, true));
          return until;
        });
        return { outcome: 'confirmed', coolingOffUntil };
      } catch (error) {
        if (error instanceof ConfirmationRefused) {
          return { outcome: 'refused', status: error.status, code: error.code };
        }
        if (error instanceof ConfirmationUnreadable) {
          services.logger.error('factor_reset.confirmation_unreadable', { resetId, contactId });
          return { outcome: 'refused', status: 503, code: 'INTEGRITY_FAILED' };
        }
        throw error;
      }
    },
  };
}
