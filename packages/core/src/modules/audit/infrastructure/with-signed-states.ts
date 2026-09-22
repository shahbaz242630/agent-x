// The one way product code gets signed states (ADR-012 §2): withTenant for the
// organisation, with that transaction's own signed states. Every tamper sign
// they find puts the organisation on its integrity hold
// (domain/integrity-hold.ts) once that transaction has ended, committed or
// rolled back, in a transaction of its own. Never:
// - inside the transaction that found it, which may roll back (a failed
//   change throws out of withTenant), taking the hold with it
// - beside it, on another connection, while it is still open: the hold takes
//   the chain head's lock, which the open transaction may hold already (a
//   change that failed after recording its event), and each would wait on
//   the other for ever
//
// A hold that can't be set raises the integrity alarm again (`check: hold`),
// and the work's own result or error still goes back to the caller. The
// finding's alarm has been raised already, and a hold can only fail to be set
// on a chain that refuses new events (its head fails its check), where every
// read of the hold is denied anyway.
import type { KeyProvider } from '@agentx/platform/keys';
import { withTenant } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely, Transaction } from 'kysely';

import type { IdGenerator } from '../../../shared-kernel/index.ts';
import { createAuditTrail } from './audit-trail.ts';
import { createSignedStates, type SignedStates, type TamperFinding } from './signed-states.ts';
import type { AuditTables } from './tables.ts';

/** What the work's signed states are built from. */
export interface SignedStatesServices {
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** The request's or job's logger, a child carrying its correlation ID (Rule Book §8). */
  readonly logger: Logger;
}

/** The first finding for each organisation, with how many there were. */
function byOrganisation(found: readonly TamperFinding[]): Map<string, { finding: TamperFinding; count: number }> {
  const each = new Map<string, { finding: TamperFinding; count: number }>();
  for (const finding of found) {
    const orgId = finding.orgId.toLowerCase();
    const seen = each.get(orgId);
    each.set(orgId, seen === undefined ? { finding, count: 1 } : { ...seen, count: seen.count + 1 });
  }
  return each;
}

/**
 * Runs `work` in withTenant's transaction for the organisation, with signed
 * states of its own, and then puts the organisation on hold for anything they
 * found tampered with. Returns what `work` returns, or throws what it throws.
 */
export async function withSignedStates<Tables extends AuditTables, Result>(
  // Both: the work's transaction has every table the caller's has, the hold's the audit tables.
  db: Kysely<Tables> & Kysely<AuditTables>,
  orgId: string,
  { keys, ids, logger }: SignedStatesServices,
  work: (tx: Transaction<Tables>, states: SignedStates) => Promise<Result>,
): Promise<Result> {
  const trail = createAuditTrail({ keys, ids });
  const found: TamperFinding[] = [];
  const states = createSignedStates({ keys, trail, logger, onTamper: (finding) => found.push(finding) });
  try {
    return await withTenant(db, orgId, (tx) => work(tx, states));
  } finally {
    for (const [held, { finding, count }] of byOrganisation(found)) {
      const log = logger.child({ orgId: held });
      try {
        // Its own signed states: a hold that can't be believed is set over, right here, not handed on again.
        const holder = createSignedStates({ keys, trail, logger, onTamper: () => undefined });
        const outcome = await withTenant<AuditTables, 'set' | 'already'>(db, held, (tx) =>
          holder.hold(tx, finding, count),
        );
        if (outcome === 'set') {
          log.warn('audit.integrity_hold_set', {
            reason: finding.sign,
            subjectType: finding.subjectType,
            findings: count,
          });
        }
      } catch (error) {
        log.error('audit.integrity_failed', {
          chain: 'organisation',
          check: 'hold',
          reason: 'not_recorded',
          err: error,
        });
      }
    }
  }
}
