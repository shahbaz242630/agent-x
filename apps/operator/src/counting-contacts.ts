// OR2b (playbook K; CF Before production "The only-admin runbook's tools"):
// before our team removes a person's second factor at the login service, as no
// admin can ask the product's own reset, it checks who is asking, out of band,
// through the organisation's registered contacts that count now: it goes on only
// once one confirms in writing. This lists them, each by its ID, its address
// masked as a reset's email shows one (maskedEmail: s***@company.ae) and when it
// started to count. The address whole is never logged: factor-reset-notice
// writes to each at the address Agent X holds, and the team matches a reply to
// the masked one.
//
// Read-only, as the operator's own role, in one transaction for the
// organisation (withSignedStates', ADR-006 §6):
// 1. the organisation must exist and be verified (its row read for share, as
//    factor-reset-notice reads it; a record that can't be believed raises its
//    alarm and hold, as every read of it does);
// 2. every contact the table or the log knows of is judged as verifiedState
//    judges it, with no lock (0088 grants the role a read of the table's
//    columns it needs, never a lock: a lock needs a right to change a row), and
//    no list is given if any can't be believed. The runbook then stops: the
//    contacts are the reset's trust anchor.
import {
  type AuditTables,
  createAuditTrail,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import { type CountingContact, countingContactsAsRead, type IdentityTables } from '@agentx/core/modules/identity';
import { maskedEmail } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import type { Database } from '@agentx/platform/db';

import type { OperatorTables } from './create-organization.ts';
import { COUNTING_CONTACTS } from './request.ts';

/** Every table the listing reads: the organisation's row, its chain, and its contacts. */
export type CountingContactsTables = OperatorTables & IdentityTables & AuditTables;

/** Why no list is given. */
class ListRefused extends Error {
  readonly problem: string;

  constructor(problem: string) {
    super(`The list refused: ${problem}`);
    this.name = 'ListRefused';
    this.problem = problem;
  }
}

/**
 * The contacts as the log line shows them: each one's ID, its address masked, and its start. The field is `masked`,
 * never a name the redactor reads as an address's: the masked form is the one shown, the whole one never.
 */
export const shownContacts = (contacts: readonly CountingContact[]) =>
  contacts.map(({ id, email, countsFrom }) => ({
    contactId: id,
    masked: maskedEmail(email),
    countsFrom: countsFrom.toISOString(),
  }));

/** Lists the organisation's contacts that count at `now`, masked: the exit code, 0 once listed (an empty list too). */
export async function listCountingContacts(
  database: Database<CountingContactsTables>,
  services: SignedStatesServices,
  orgId: string,
  now: Date,
): Promise<number> {
  const log = services.logger.child({ orgId });
  const trail = createAuditTrail({ keys: services.keys, ids: services.ids });
  try {
    const contacts = await withSignedStates(database, orgId, services, async (tx, states) => {
      const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
      if (organization.outcome === 'missing') throw new ListRefused('no organisation has this ID');
      if (organization.outcome === 'tampered') throw new ListRefused("the organisation's records can't be verified");
      const read = await countingContactsAsRead(tx, { trail, keys: services.keys }, orgId, now);
      if (read.outcome === 'unverified') {
        throw new ListRefused("a registered contact's record can't be verified: no list, and no reset goes on");
      }
      return read.contacts;
    });
    log.info('operator.counting_contacts', { count: contacts.length, contacts: shownContacts(contacts) });
    return 0;
  } catch (error) {
    if (error instanceof ListRefused) {
      log.error('operator.refused', { problems: [error.problem] });
    } else {
      // Nothing is written by the list: the same command run again finds out.
      log.error('operator.failed', { command: COUNTING_CONTACTS, err: error });
    }
    return 1;
  }
}
