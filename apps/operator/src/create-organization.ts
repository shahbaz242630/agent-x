// B1c: the operator creates an organisation (ADR-011 §3: organisation
// lifecycle is an operator action; no public sign-up in Phase 1). In one
// transaction, withSignedStates' for the new organisation:
// 1. the organisation itself (the organizations module): its directory entry,
//    its row, ACTIVE, and its first signed state, which starts its audit chain
//    (`organization.created`), then its integrity hold, CLEAR
// 2. the same act on the platform audit chain, naming the organisation and
//    the release that did it
// Both chains or neither: a failure anywhere rolls back the whole creation.
// The platform chain's head is locked last, after the organisation's (ADR-006
// §6: 12, then 13).
//
// The organisation's ID is made here, never given: the command can only ever
// create a new organisation, never reach one that exists (ADR-005 §6: operator
// tooling can't read or change a customer's authority).
import type { AuditTables, SignedStatesServices } from '@agentx/core/modules/audit';
import { withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { createOrganization, type OrganizationsTables } from '@agentx/core/modules/organizations';
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { Database } from '@agentx/platform/db';

/** Every table the command reaches, module by module. */
export type OperatorTables = OrganizationsTables & DirectoryTables & AuditTables & PlatformControlsTables;

/** Who acts, on both chains: the operator's command, by its process's name. */
const OPERATOR = Object.freeze({ type: 'system', id: 'operator' } as const);

export interface CreatedOrganization {
  readonly orgId: string;
  /** The organisation's first event on its own chain (1). */
  readonly orgSeq: bigint;
  /** Its place on the platform chain. */
  readonly platformSeq: bigint;
}

/**
 * Creates an organisation named `name`, ACTIVE and with its integrity hold
 * CLEAR, recorded on its own chain and the platform's. Throws
 * OrganizationRefused for a name it can't have, before any change is made.
 */
export async function createOrganizationAsOperator(
  database: Database<OperatorTables>,
  services: SignedStatesServices,
  { name, release }: { readonly name: string; readonly release: string },
): Promise<CreatedOrganization> {
  const orgId = services.ids.next();
  const platform = createPlatformChain({ keys: services.keys, ids: services.ids });
  return withSignedStates(database, orgId, services, async (tx, states) => {
    const created = await createOrganization(tx, states, { id: orgId, name, actor: OPERATOR });
    const recorded = await platform.record(tx, {
      actor: OPERATOR,
      action: 'organization.created',
      details: { orgId, release },
    });
    return Object.freeze({ orgId, orgSeq: created.seq, platformSeq: recorded.seq });
  });
}
