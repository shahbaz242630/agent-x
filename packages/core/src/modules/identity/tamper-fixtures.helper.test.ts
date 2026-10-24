// Real foreign identity records for the compose tamper pass. Drafts are
// enough to exercise tenant lookups without sending invitations or reset mail.
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { testLogger } from '@agentx/testing';

import { type AuditTables, withSignedStates } from '../audit/index.ts';
import type { Clock, IdGenerator } from '../../shared-kernel/index.ts';
import { draftReset } from './infrastructure/factor-resets.ts';
import { draftInvitation, invitationChange } from './infrastructure/invitations.ts';
import { contactChange, draftContact } from './infrastructure/registered-contacts.ts';
import type { IdentityTables } from './infrastructure/tables.ts';

/** Signed drafts exist in the foreign tenant even when the first route check is step-up. */
export async function tamperIdentityFixtures(
  database: Database<IdentityTables & AuditTables>,
  keys: KeyProvider,
  ids: IdGenerator,
  clock: Clock,
  person: { orgId: string; userId: string; membershipId: string },
  target: string,
) {
  const invitation = ids.next();
  const contact = ids.next();
  const reset = ids.next();
  const actor = { type: 'user' as const, id: person.userId };
  const now = clock.now();
  await withSignedStates(database, person.orgId, { keys, ids, logger: testLogger() }, async (tx, states) => {
    const invited = invitationChange({
      orgId: person.orgId,
      id: invitation,
      email: 'foreign-invitation@example.test',
      role: 'developer',
      invitedBy: person.membershipId,
      createdAt: now,
    });
    await draftInvitation(tx, states, keys, invited.change, { stepUpChallengeId: ids.next(), createdAt: now, actor });
    const added = contactChange({
      orgId: person.orgId,
      id: contact,
      email: 'foreign-contact@example.test',
      addedBy: person.membershipId,
    });
    await draftContact(tx, states, keys, added.change, { stepUpChallengeId: ids.next(), createdAt: now, actor });
    await draftReset(
      tx,
      states,
      {
        orgId: person.orgId,
        id: reset,
        person: target,
        requestedBy: person.membershipId,
        expiresAt: new Date(now.getTime() + 86_400_000),
      },
      { stepUpChallengeId: ids.next(), createdAt: now, actor },
    );
  });
  return { invitation, contact, reset };
}
