// B4-6b: the operator invites an organisation's first admin (ADR-005 §6,
// ADR-011 §3): the organisation the operator created has no members, so no
// admin can. In one transaction, withSignedStates' for the organisation:
// 1. the organisation must exist and be verified, and no one may be listed in
//    it, deactivated or not: the operator seats a new organisation's first
//    admin, never adds one to an organisation in use, whose admins invite
// 2. the invitation (the identity module's inviteFirstAdmin): an admin's,
//    naming no member and no step-up, opened with the token's SHA-256 the
//    request gives. The token itself is made where the link is shown (the
//    operator's own terminal, deploy/azure/operator.ts) and never reaches the
//    job, its logs or Azure
// 3. the same act on the platform audit chain, naming the organisation, the
//    invitation, the release that did it and the job's run
// Both chains or neither. The invited address is never logged; it is kept
// encrypted with the invitation, as any invited address is.
//
// The invitation's ID is made by deploy/azure/operator.ts, so a request left
// on the job and run again meets the invitation's key and changes nothing.
import { withSignedStates } from '@agentx/core/modules/audit';
import type { SignedStatesServices } from '@agentx/core/modules/audit';
import { listedMembers } from '@agentx/core/modules/directory';
import { type IdentityTables, inviteFirstAdmin } from '@agentx/core/modules/identity';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { systemClock } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';

import type { OperatorTables } from './create-organization.ts';

/** Every table the invitation reaches, the organisation's among them. */
export type FirstAdminTables = OperatorTables & IdentityTables;

/** Who acts, on both chains: the operator's command. */
const OPERATOR = Object.freeze({ type: 'system', id: 'operator' } as const);

export interface FirstAdminRequest {
  readonly orgId: string;
  /** The invitation's ID, made where the request was written. */
  readonly invitationId: string;
  /** The invited address: checked here, never logged. */
  readonly email: string;
  /** The SHA-256 of the token in the link, 32 bytes. */
  readonly tokenHash: Buffer;
  readonly release: string;
  readonly run: string | null;
}

/** Why the operator may not invite this organisation's first admin: each reason, never the address. */
export class FirstAdminRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The first admin's invitation refused: ${problems.join('; ')}`);
    this.name = 'FirstAdminRefused';
    this.problems = problems;
  }
}

/**
 * Invites the organisation's first admin, recorded on its own chain and the
 * platform's. Throws FirstAdminRefused for an organisation that isn't there,
 * can't be verified, or has members, with nothing changed.
 */
export async function inviteFirstAdminAsOperator(
  database: Database<FirstAdminTables>,
  services: SignedStatesServices,
  { orgId, invitationId, email, tokenHash, release, run }: FirstAdminRequest,
): Promise<{ readonly platformSeq: bigint }> {
  const platform = createPlatformChain({ keys: services.keys, ids: services.ids });
  return withSignedStates(database, orgId, services, async (tx, states) => {
    const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
    if (organization.outcome === 'missing') throw new FirstAdminRefused(['no organisation has this ID']);
    if (organization.outcome === 'tampered') {
      throw new FirstAdminRefused(["the organisation's records can't be verified"]);
    }
    if ((await listedMembers(tx, orgId, 1)).length > 0) {
      throw new FirstAdminRefused(['the organisation has members: its admins invite, not the operator']);
    }
    try {
      await inviteFirstAdmin(tx, states, services.keys, {
        orgId,
        id: invitationId,
        email,
        tokenHash,
        createdAt: systemClock.now(),
        actor: OPERATOR,
      });
    } catch (error) {
      if (error instanceof RangeError)
        throw new FirstAdminRefused(["the invited address, or the token's hash, isn't one"]);
      throw error;
    }
    const recorded = await platform.record(tx, {
      actor: OPERATOR,
      action: 'invitation.first_admin',
      details: { orgId, invitationId, release, run },
    });
    return Object.freeze({ platformSeq: recorded.seq });
  });
}
