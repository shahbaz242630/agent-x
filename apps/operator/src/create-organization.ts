// B1c: the operator creates an organisation (ADR-011 §3: organisation
// lifecycle is an operator action; no public sign-up in Phase 1). In one
// transaction, withSignedStates' for the new organisation:
// 1. the organisation itself (the organizations module): its directory entry,
//    its row, ACTIVE, and its first signed state, which starts its audit chain
//    (`organization.created`), then its integrity hold, CLEAR
// 2. the same act on the platform audit chain, naming the organisation, the
//    release that did it and the job's run (B1c-2b), which leads to Azure's
//    record of the run and of who started it
// Both chains or neither: a failure anywhere rolls back the whole creation.
// The platform chain's head is locked last, after the organisation's (ADR-006
// §6: 12, then 13), and the wait for it is bounded (PlatformChain.record).
//
// The organisation's ID is made by the command (its IdGenerator), or by
// deploy/azure/operator.ts for a request file (B1c-2b), never typed; an ID
// already listed is refused by the directory's key, so a request run twice
// makes one organisation: the command can only ever create a new
// organisation, never reach one that exists (ADR-005 §6, amended S40: the one
// operator command that writes tenant tables, and its bounds).
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

export interface NewOrganizationRequest {
  /** Made before the call (the command's IdGenerator, or a request file's), so a failure can name it. */
  readonly orgId: string;
  readonly name: string;
  /** The release that runs the command, named in the platform's event. */
  readonly release: string;
  /** The job's run, as Azure names it, named in the platform's event; null for a run by hand (development and test). */
  readonly run: string | null;
}

/**
 * Creates the organisation, ACTIVE and with its integrity hold CLEAR,
 * recorded on its own chain and the platform's. Throws OrganizationRefused
 * for a name it can't have, before any change is made.
 */
export async function createOrganizationAsOperator(
  database: Database<OperatorTables>,
  services: SignedStatesServices,
  { orgId, name, release, run }: NewOrganizationRequest,
): Promise<CreatedOrganization> {
  const platform = createPlatformChain({ keys: services.keys, ids: services.ids });
  return withSignedStates(database, orgId, services, async (tx, states) => {
    const created = await createOrganization(tx, states, { id: orgId, name, actor: OPERATOR });
    const recorded = await platform.record(tx, {
      actor: OPERATOR,
      action: 'organization.created',
      details: { orgId, release, run },
    });
    return Object.freeze({ orgId, orgSeq: created.seq, platformSeq: recorded.seq });
  });
}
