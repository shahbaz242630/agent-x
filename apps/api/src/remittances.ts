// A paid supplier's remittance email, as it is sent (Phase 4 C2b; partner
// decisions 8 and 34a–c, S93, S139): read when the email goes, never when the
// payment SUCCEEDED, so a setting turned off since sends nothing, and the
// address is the one the paid version holds then. Every fact is read from its
// verified record in ADR-006's lock order: the supplier's version the
// instruction names and its setting (6), the request (8), then the
// transaction and its instruction (10), each `share`. The organisation's name
// is fixed when it is made (0008: the app never changes it), so it is read
// as it stands. A record that can't be believed raises its alarm through its
// read and throws, so nothing is sent and the notice is tried again.
import { type AuditTables, withSignedStates } from '@agentx/core/modules/audit';
import { instructionOf, type InstructionsTables } from '@agentx/core/modules/instructions';
import type { RemittanceRead, Remittances } from '@agentx/core/modules/notifications';
import type { OrganizationsTables } from '@agentx/core/modules/organizations';
import { requestOf, type SpendRequestsTables } from '@agentx/core/modules/spend-requests';
import { contactsOf, remittanceOf, type SuppliersTables, versionOf } from '@agentx/core/modules/suppliers';
import { transactionOf, type TransactionsTables } from '@agentx/core/modules/transactions';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

export type RemittanceTables = OrganizationsTables &
  SuppliersTables &
  SpendRequestsTables &
  InstructionsTables &
  TransactionsTables &
  AuditTables;

/** A payment's records that can't be believed, or don't name each other: nothing is sent. */
class RemittanceUnbelieved extends Error {
  constructor(transactionId: string, what: string) {
    super(`A paid transaction's ${what} can't be believed: ${transactionId}`);
    this.name = 'RemittanceUnbelieved';
  }
}

export function createRemittances({
  database,
  keys,
  ids,
  logger,
}: {
  readonly database: Database<RemittanceTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly logger: Logger;
}): Remittances {
  return {
    remittanceOf: (orgId, transactionId) =>
      withSignedStates(database, orgId, { keys, ids, logger }, async (tx, states): Promise<RemittanceRead> => {
        const named = await tx
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state below
          .selectFrom('transactions.transactions as t')
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state below
          .innerJoin('instructions.instructions as i', (join) =>
            join.onRef('i.org_id', '=', 't.org_id').onRef('i.id', '=', 't.instruction_id'),
          )
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state below
          .innerJoin('suppliers.supplier_versions as v', (join) =>
            join.onRef('v.org_id', '=', 'i.org_id').onRef('v.id', '=', 'i.supplier_version_id'),
          )
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- its name alone: not sealed, and fixed when it is made (0008)
          .innerJoin('organizations.organizations as o', (join) =>
            join.onRef('o.org_id', '=', 't.org_id').onRef('o.id', '=', 't.org_id'),
          )
          .select([
            't.instruction_id as instructionId',
            'i.spend_request_id as requestId',
            'i.supplier_version_id as versionId',
            'v.supplier_id as supplierId',
            'o.name as payerName',
          ])
          .where('t.org_id', '=', orgId)
          .where('t.id', '=', transactionId)
          .executeTakeFirst();
        if (named === undefined) throw new RemittanceUnbelieved(transactionId, 'records');
        const version = await versionOf(tx, states, { orgId, id: named.versionId }, named.supplierId);
        if (version.outcome !== 'found') throw new RemittanceUnbelieved(transactionId, 'supplier version');
        const setting = await remittanceOf(tx, states, { orgId, supplierId: named.supplierId }, 'share');
        if (setting.outcome === 'tampered') throw new RemittanceUnbelieved(transactionId, 'remittance setting');
        const request = await requestOf(tx, states, { orgId, id: named.requestId });
        if (request.outcome !== 'found') throw new RemittanceUnbelieved(transactionId, 'request');
        const transaction = await transactionOf(tx, states, { orgId, id: transactionId }, 'share');
        const instruction = await instructionOf(tx, states, { orgId, id: named.instructionId });
        if (transaction.outcome !== 'found' || instruction.outcome !== 'found') {
          throw new RemittanceUnbelieved(transactionId, 'transaction or instruction');
        }
        // The sealed rows name each other: the IDs found first must be those.
        const paid = instruction.instruction;
        if (
          transaction.transaction.instructionId !== paid.id ||
          paid.spendRequestId !== request.request.id ||
          paid.supplierVersionId !== version.version.id
        ) {
          throw new RemittanceUnbelieved(transactionId, 'records, which name others,');
        }
        if (transaction.transaction.status !== 'SUCCEEDED') return { outcome: 'not_succeeded' };
        if (setting.remittanceEmail === 'off') return { outcome: 'off' };
        const { email } = await contactsOf(tx, keys, orgId, version.version);
        if (email === null) return { outcome: 'no_email' };
        return {
          outcome: 'send',
          to: email,
          paid: {
            payerName: named.payerName,
            invoiceNumber: request.request.orderReference,
            bankReference: paid.paymentReference,
            amountMinor: paid.amountMinor,
            currency: paid.currency,
          },
        };
      }),
  };
}
