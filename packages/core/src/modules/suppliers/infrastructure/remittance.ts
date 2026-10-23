// Whether a supplier is emailed when it is paid (0061; Phase 4 C2a; partner
// decision 34b): an authority table of the supplier's own, read through its
// signed state and on the product's authority-table list, at the supplier's
// level in the lock order (ADR-006 §6: 6), after its versions. Its row's ID
// is its supplier's.
//
// A supplier added from 0061 is added with its setting, chosen by the admin.
// One added before has no row and reads as `on`, the default the partner
// chose (`unset`), until an admin sets it: the first setting adds the row and
// seals it, a later one changes it.
import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type {
  AuditActor,
  AuditTables,
  AuditDetails,
  SignedStates,
  StateCheck,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import type { SuppliersTables } from './tables.ts';

/** A transaction on the suppliers' and audit tables, as suppliers.ts's (named here: that file adds a supplier with its setting). */
type SettingTransaction = Transaction<SuppliersTables & AuditTables>;

/** Whether the supplier's remittance email is sent: `on` or `off`. */
export const REMITTANCE_EMAILS = ['on', 'off'] as const;
export type RemittanceEmail = (typeof REMITTANCE_EMAILS)[number];

/** A supplier with no setting yet (added before 0061) reads as the partner's default. */
export const REMITTANCE_EMAIL_UNSET: RemittanceEmail = 'on';

/** A supplier's remittance setting, as the signed state reads, records and checks it. */
export const REMITTANCE_SETTINGS = {
  table: 'suppliers.remittance_settings',
  subject: 'supplier_remittance',
  fields: [{ column: 'remittance_email', type: 'text' }],
} as const satisfies SignedStateTable;

/** The supplier's setting, verified (`unset`: added before 0061, read as `on`); or tampered with (its alarm raised). */
export type RemittanceCheck =
  | { readonly outcome: 'set'; readonly remittanceEmail: RemittanceEmail; readonly state: VerifiedState }
  | { readonly outcome: 'unset'; readonly remittanceEmail: RemittanceEmail }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The setting a signed read of the supplier's row holds. */
function remittanceFrom(state: StateCheck): RemittanceCheck {
  if (state.outcome === 'tampered') return state;
  if (state.outcome === 'missing') return { outcome: 'unset', remittanceEmail: REMITTANCE_EMAIL_UNSET };
  // 0061's check holds the column to `on` or `off`, and the seal to what was written.
  const remittanceEmail = state.fields.get('remittance_email') === 'off' ? 'off' : 'on';
  return { outcome: 'set', remittanceEmail, state };
}

/**
 * The supplier's setting, read through its signed state in the caller's
 * transaction, which must be withSignedStates' for the organisation: `share`
 * for a read a send rests on, `change` before setting it.
 */
export async function remittanceOf(
  tx: SettingTransaction,
  states: SignedStates,
  { orgId, supplierId }: { readonly orgId: string; readonly supplierId: string },
  lock: 'share' | 'change',
): Promise<RemittanceCheck> {
  return remittanceFrom(await states.verifiedState(tx, REMITTANCE_SETTINGS, { orgId, id: supplierId }, lock));
}

/** Who sets a supplier's remittance email, and the facts its event names. */
export interface RemittanceSet {
  readonly orgId: string;
  readonly supplierId: string;
  readonly remittanceEmail: RemittanceEmail;
  readonly at: Date;
  readonly actor: AuditActor;
  readonly details?: AuditDetails;
}

/**
 * Sets the supplier's remittance email, in the caller's transaction, which
 * read it with `change` (`read`, not tampered) after the supplier itself: the
 * row added and sealed if it had none (`supplier_remittance.chosen`),
 * otherwise changed (`supplier_remittance.changed`). A change's caller
 * answers a setting already as asked without calling this; addSupplier calls
 * it for every new supplier, `on` too, so each has its row.
 */
export async function setRemittance(
  tx: SettingTransaction,
  states: SignedStates,
  read: Exclude<RemittanceCheck, { readonly outcome: 'tampered' }>,
  { orgId, supplierId, remittanceEmail, at, actor, details = {} }: RemittanceSet,
): Promise<void> {
  const fields = { remittance_email: remittanceEmail };
  const key = { orgId, id: supplierId };
  if (read.outcome === 'set') {
    await states.record(tx, REMITTANCE_SETTINGS, key, read.state, fields, {
      actor,
      action: 'supplier_remittance.changed',
      details,
    });
    return;
  }
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (as a supplier's, suppliers.ts)
    .insertInto(REMITTANCE_SETTINGS.table)
    .values({ org_id: orgId, id: supplierId, ...fields, created_at: at })
    .execute();
  await states.record(tx, REMITTANCE_SETTINGS, key, 'new', fields, {
    actor,
    action: 'supplier_remittance.chosen',
    details,
  });
}
