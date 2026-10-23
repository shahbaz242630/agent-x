// The hand-off's test world (Phase 4 B4, E1a), shared by the hand-off's and
// the bank check's DB tests: a spend world whose first supplier has a payee
// registered with the world's own fake partner, and how a request's payment
// is read back.
import { withSignedStates } from '@agentx/core/modules/audit';
import { instructionOfRequest, type InstructionsTables } from '@agentx/core/modules/instructions';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import {
  addVersion,
  confirmPayeeChange,
  nextVersionNumber,
  recordRegistered,
  registrationOf,
  stagePayeeChange,
  startRegistration,
  supplierOf,
  versionOf,
} from '@agentx/core/modules/suppliers';
import { transactionOf, type TransactionsTables } from '@agentx/core/modules/transactions';
import type { Database } from '@agentx/platform/db';
import type { FixedClock, SequentialIds } from '@agentx/testing';

import type { MandateRegistry } from './mandate-registry.ts';
import { AED, keys, OPERATOR, type World } from './mandate-world.helper.test.ts';
import type { spendWorld, SpendWorldTables } from './spend-world.helper.test.ts';

export type HandoffWorldTables = SpendWorldTables & PlatformControlsTables & InstructionsTables & TransactionsTables;

/** AED 500 and the fils that choose the fake's answer (decision 5): under the approval threshold, so APPROVED. */
export const ALLOWED = (fils = 0n) => AED(50_000n + fils);

/** AED 200 and the fils: three of them to one supplier still under the approval threshold, its split check included. */
export const SMALL = (fils = 0n) => AED(20_000n + fils);

/** What a handed-off request holds as its payment stands (C3, ADR-006 §10–§11): given back only after a proven failure. */
export const HOLDS_AFTER: Readonly<Record<string, { readonly reservation: string; readonly released: boolean }>> = {
  PROCESSING: { reservation: 'HELD', released: false },
  SUCCEEDED: { reservation: 'FINALISED', released: false },
  UNKNOWN: { reservation: 'BLOCKED_UNKNOWN', released: false },
  FAILED: { reservation: 'RELEASED', released: true },
};

/** The partner's reference for the world's first supplier's payee. */
export const payeeRefOf = (w: World) => `fake-beneficiary-${w.org.slice(-12)}`;

export function handoffWorld({
  app,
  clock,
  ids,
  registry,
  shared,
}: {
  readonly app: () => Database<HandoffWorldTables>;
  readonly clock: () => FixedClock;
  readonly ids: SequentialIds;
  readonly registry: () => MandateRegistry;
  readonly shared: ReturnType<typeof spendWorld>;
}) {
  const { signed, quiet } = shared;

  /**
   * The world's first supplier given a payee, as E2's registration and its
   * admin's confirmation would: a version made from a registration REGISTERED
   * for it, made current with its payee key, its cooling-off already over.
   */
  async function payeeRegistered(w: World): Promise<void> {
    const supplierId = w.suppliers[0] ?? '';
    const key = { orgId: w.org, id: supplierId };
    const registrationId = ids.next();
    const versionId = ids.next();
    await signed(w, async (tx, states) => {
      await supplierOf(tx, states, key, 'change');
      await startRegistration(tx, states, {
        orgId: w.org,
        id: registrationId,
        supplierId,
        versionId,
        partner: 'fake',
        route: 'hosted',
        startedBy: w.admin.membershipId,
        createdAt: clock().now(),
        actor: OPERATOR,
      });
    });
    const registration = await signed(w, async (tx, states) => {
      const found = await registrationOf(tx, states, { orgId: w.org, id: registrationId }, supplierId, 'change');
      if (found.outcome !== 'found') throw new Error(`no registration: ${found.outcome}`);
      return recordRegistered(tx, states, { orgId: w.org, id: registrationId }, found, {
        beneficiary: {
          organizationId: w.org,
          registrationId,
          beneficiaryRef: payeeRefOf(w),
          payeeIdentity: null,
          nameCheck: 'match',
          maskedName: 'G*** O***** S******* L**',
          hint: 'AE…6026',
          registeredAt: clock().now(),
        },
        payee: { key: `fake-payee-${'b'.repeat(32)}`, keyVersion: null },
        actor: OPERATOR,
      });
    });
    await signed(w, async (tx, states) => {
      const found = await supplierOf(tx, states, key, 'change');
      if (found.outcome !== 'found') throw new Error(`no supplier: ${found.outcome}`);
      const current = await versionOf(tx, states, { orgId: w.org, id: found.supplier.currentVersionId }, supplierId);
      if (current.outcome !== 'found') throw new Error(`no version: ${current.outcome}`);
      await addVersion(tx, states, keys, {
        orgId: w.org,
        id: versionId,
        supplierId,
        version: await nextVersionNumber(tx, w.org, supplierId),
        supplier: {
          displayName: 'Gulf Office Supplies LLC',
          contacts: { phone: '+971501234567', email: null, tradeLicence: null },
          source: { kind: 'registry', ref: 'DED-123456' },
        },
        enteredBy: w.admin.membershipId,
        enteredAt: clock().now(),
        actor: OPERATOR,
        of: found,
        follows: current.version,
        registration,
      });
      const made = await versionOf(tx, states, { orgId: w.org, id: versionId }, supplierId);
      if (made.outcome !== 'found') throw new Error(`no new version: ${made.outcome}`);
      const change = { version: made.version, registration, current: current.version };
      const staged = await stagePayeeChange(tx, states, key, found, change, { actor: OPERATOR });
      const restaged = await supplierOf(tx, states, key, 'change');
      if (restaged.outcome !== 'found') throw new Error(`no supplier: ${restaged.outcome}`);
      await confirmPayeeChange(tx, states, key, { supplier: staged, state: restaged.state }, change, {
        actor: OPERATOR,
        coolingOffUntil: new Date(clock().now().getTime() - 1),
      });
    });
  }

  /** A world whose first supplier has a payee, both verified, with a mandate in force and the agent's key. */
  async function ready() {
    const w = await shared.world();
    await payeeRegistered(w);
    for (const id of w.suppliers) await shared.verified(w, id);
    await shared.inForce(registry(), w, { approvalThreshold: AED(100_000n) });
    return { w, acting: await shared.agentKey(w) };
  }

  /** The request's instruction, if one was made, and its transaction. */
  async function paymentOf(w: World, requestId: string) {
    return withSignedStates(app(), w.org, quiet(), async (tx, states) => {
      const instruction = await instructionOfRequest(tx, states, { orgId: w.org, spendRequestId: requestId });
      if (instruction.outcome !== 'found') return { instruction: instruction.outcome };
      const rows = await tx
        .selectFrom('transactions.transactions')
        .select('id')
        .where('instruction_id', '=', instruction.instruction.id)
        .execute();
      const transaction = await transactionOf(tx, states, { orgId: w.org, id: rows[0]?.id ?? '' }, 'share');
      return {
        instruction: instruction.instruction,
        transactions: rows.length,
        transaction: transaction.outcome === 'found' ? transaction.transaction : transaction.outcome,
      };
    });
  }

  return { ready, paymentOf };
}
