// Setting policies, the organisation's and each mandate's, and reading them
// (0037; Phase 2 C3; partner decision 5). Every read goes through the audit
// module's verifiedState; every write is a plain insert signed by
// record('new') in the same transaction (agents.ts says why a plain insert is
// safe), or a policy's version in force moved from its state read for change.
//
// A policy is read by its own ID, the organisation's or the mandate's: missing
// means none was ever set (a row deleted past the app is `tampered`, as its
// signed history is in the log). The first change makes it, naming its first
// version (0037's `current_is_its_own`, checked at commit), then that
// version; a later change adds the next version and moves the policy to it,
// in force at once (no acceptance, decision 5).
import { holdTransactionLock } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';
import { createHash } from 'node:crypto';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import { type Money, minorOf, money, oneOf, oneOfOrNull, timeOf, wholeOf } from '../../../shared-kernel/index.ts';
import { OVER_CAP, POLICY_SCOPES, type PolicyRules, type PolicyScope, policyRules } from '../domain/policy.ts';
import { POLICIES, POLICY_VERSIONS } from './mandates.ts';
import type { MandatesTables } from './tables.ts';

type MandatesTransaction = Transaction<MandatesTables & AuditTables>;

interface PolicyKey {
  readonly orgId: string;
  readonly id: string;
}

/** A policy, as its signed state says. */
export interface PolicyRecord {
  /** The organisation's ID for its own, the mandate's for a mandate's. */
  readonly id: string;
  readonly scope: PolicyScope;
  readonly mandateId: string | null;
  readonly currentVersionId: string;
}

/** A version of a policy's rules, as its signed state says. */
export interface PolicyVersionRecord extends PolicyRules {
  readonly id: string;
  readonly policyId: string;
  readonly version: number;
  readonly rulesHash: string;
  /** The membership of the admin who made it, and when. */
  readonly madeBy: string;
  readonly madeAt: Date;
}

type PolicyCheck =
  | { readonly outcome: 'found'; readonly policy: PolicyRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

type PolicyVersionCheck =
  | { readonly outcome: 'found'; readonly version: PolicyVersionRecord }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

type Fields = ReadonlyMap<string, string | null>;

/** A verified row read back into its record, or a throw: the table's checks and the seal make any other a bug. */
function recordOf<Row>(subject: string, id: string, record: Row | undefined): Row {
  if (record === undefined) throw new Error(`A verified ${subject} holds a field that isn't one of its own: ${id}`);
  return record;
}

function policyRecordOf(id: string, fields: Fields): PolicyRecord | undefined {
  const scope = oneOf(POLICY_SCOPES, fields.get('scope'));
  const mandateId = fields.get('mandate_id');
  const currentVersionId = fields.get('current_version_id');
  if (scope === undefined || mandateId === undefined || typeof currentVersionId !== 'string') return undefined;
  return { id, scope, mandateId, currentVersionId };
}

/** An amount that may be unset: null for none, undefined for a field that is neither. */
const amountOf = (value: string | null | undefined, currency: string): Money | null | undefined => {
  if (value === null) return null;
  const minor = minorOf(value);
  return minor === undefined ? undefined : money(minor, currency);
};

function versionRecordOf(id: string, fields: Fields): PolicyVersionRecord | undefined {
  const [policyId, currency, rulesHash, madeBy] = ['policy_id', 'currency', 'rules_hash', 'made_by'].map((column) => {
    const value = fields.get(column);
    return typeof value === 'string' ? value : undefined;
  });
  const version = wholeOf(fields.get('version'));
  const madeAt = timeOf(fields.get('made_at'));
  const over = oneOfOrNull(OVER_CAP, fields.get('over_per_order_cap'));
  const suppliers = fields.get('supplier_ids');
  if (
    policyId === undefined ||
    currency === undefined ||
    rulesHash === undefined ||
    madeBy === undefined ||
    typeof version !== 'number' ||
    !(madeAt instanceof Date) ||
    over === undefined ||
    suppliers === undefined
  ) {
    return undefined;
  }
  const [cap, monthlyCap, approvalThreshold] = [
    'per_order_cap_minor',
    'monthly_cap_minor',
    'approval_threshold_minor',
  ].map((column) => amountOf(fields.get(column), currency));
  // 0037's `a_cap_with_its_outcome`: a cap and its outcome, or neither.
  if (
    cap === undefined ||
    monthlyCap === undefined ||
    approvalThreshold === undefined ||
    (cap === null) !== (over === null)
  ) {
    return undefined;
  }
  return {
    id,
    policyId,
    version,
    currency,
    perOrderCap: cap === null || over === null ? null : { cap, over },
    monthlyCap,
    approvalThreshold,
    supplierIds: suppliers === null ? null : suppliers.split(' '),
    rulesHash,
    madeBy,
    madeAt,
  };
}

/**
 * The policy, by its own ID, read and verified in the caller's transaction,
 * which must be withSignedStates' for its organisation: `share` for a
 * decision, `change` for a change. Missing: never set.
 */
export async function policyOf(
  tx: MandatesTransaction,
  states: SignedStates,
  key: PolicyKey,
  lock: 'share' | 'change',
): Promise<PolicyCheck> {
  const state = await states.verifiedState(tx, POLICIES, key, lock);
  if (state.outcome !== 'verified') return state;
  const id = key.id.toLowerCase();
  return { outcome: 'found', policy: recordOf(POLICIES.subject, id, policyRecordOf(id, state.fields)), state };
}

/** The version, by its ID, read (`share`) and verified: found only as a version of `policyId`. */
export async function policyVersionOf(
  tx: MandatesTransaction,
  states: SignedStates,
  key: PolicyKey,
  policyId: string,
): Promise<PolicyVersionCheck> {
  const state = await states.verifiedState(tx, POLICY_VERSIONS, key, 'share');
  if (state.outcome !== 'verified') return state;
  const id = key.id.toLowerCase();
  const version = recordOf(POLICY_VERSIONS.subject, id, versionRecordOf(id, state.fields));
  if (version.policyId !== policyId.toLowerCase()) return { outcome: 'missing' };
  return { outcome: 'found', version };
}

/** SHA-256 of the rules as canonical JSON, in lower-case hex: what a version keeps, and its step-up is bound to. */
export function rulesHash(rules: PolicyRules): string {
  const minor = (amount: Money | null) => (amount === null ? null : amount.minor.toString());
  const canonical = JSON.stringify([
    'agentx.policy_rules.v1',
    rules.currency,
    minor(rules.perOrderCap?.cap ?? null),
    rules.perOrderCap?.over ?? null,
    minor(rules.monthlyCap),
    minor(rules.approvalThreshold),
    rules.supplierIds?.join(' ') ?? null,
  ]);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/** A change of a policy, as a use case makes it. */
interface PolicyChange {
  readonly orgId: string;
  /** The policy as read for change in this transaction, or null for one never set. */
  readonly existing: { readonly policy: PolicyRecord; readonly state: VerifiedState } | null;
  /** What a new one is a policy of: the organisation's own, or the mandate's (its ID then the mandate's). */
  readonly scope: PolicyScope;
  readonly mandateId: string | null;
  /** The new version's ID, made by the server. */
  readonly versionId: string;
  /** As policyRules keeps them (checked again here); the use case has checked them against the mandate and the organisation. */
  readonly rules: PolicyRules;
  /** The membership of the admin who made it, checked active by the use case. */
  readonly madeBy: string;
  readonly madeAt: Date;
  readonly actor: AuditActor;
  /** More facts for its event, such as the step-up's evidence. */
  readonly details: AuditDetails;
}

/**
 * The policy's new version, in force at once, in the caller's transaction
 * (withSignedStates' for its organisation): the policy made first when it
 * was never set, otherwise moved to the version. Rules a policy can't have
 * are `PolicyRulesRefused`, before any SQL runs. Gives the version's signed
 * state.
 */
export async function setPolicy(
  tx: MandatesTransaction,
  states: SignedStates,
  change: PolicyChange,
): Promise<RecordedState> {
  const rules = policyRules(change.rules);
  const { orgId, versionId, actor, details } = change;
  const id = change.scope === 'organization' ? orgId : change.mandateId;
  if (id === null) throw new RangeError('A mandate’s policy names its mandate');
  const key = { orgId, id };
  let version = 1;
  if (change.existing === null) {
    const fields = { scope: change.scope, mandate_id: change.mandateId, current_version_id: versionId };
    await tx
      // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
      .insertInto(POLICIES.table)
      .values({ org_id: orgId, id, ...fields, created_at: change.madeAt })
      .execute();
    await states.record(tx, POLICIES, key, 'new', fields, { actor, action: 'policy.set', details: { versionId } });
  } else {
    version = await nextVersionNumber(tx, orgId, id);
    await states.record(
      tx,
      POLICIES,
      key,
      change.existing.state,
      { current_version_id: versionId },
      { actor, action: 'policy.changed', details: { versionId, replaced: change.existing.policy.currentVersionId } },
    );
  }
  const fields = {
    policy_id: id,
    version,
    currency: rules.currency,
    per_order_cap_minor: rules.perOrderCap?.cap.minor ?? null,
    over_per_order_cap: rules.perOrderCap?.over ?? null,
    monthly_cap_minor: rules.monthlyCap?.minor ?? null,
    approval_threshold_minor: rules.approvalThreshold?.minor ?? null,
    supplier_ids: rules.supplierIds?.join(' ') ?? null,
    rules_hash: rulesHash(rules),
    made_by: change.madeBy,
    made_at: change.madeAt,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(POLICY_VERSIONS.table)
    .values({ org_id: orgId, id: versionId, ...fields })
    .execute();
  return states.record(tx, POLICY_VERSIONS, { orgId, id: versionId }, 'new', fields, {
    actor,
    action: 'policy_version.made',
    details: { ...details, policyId: id, version, rulesHash: fields.rules_hash },
  });
}

/** The policy's next version number, in one statement. */
async function nextVersionNumber(tx: MandatesTransaction, orgId: string, policyId: string): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a number alone, never an authority field; the table's key refuses one taken
    .selectFrom(POLICY_VERSIONS.table)
    .select(sql<number>`coalesce(pg_catalog.max(version), 0)::int + 1`.as('next'))
    .where('org_id', '=', orgId)
    .where('policy_id', '=', policyId)
    .executeTakeFirstOrThrow();
  return row.next;
}

/** The most policy versions an organisation may make in any 24 hours (partner, S91): their records are never retired. */
export const MOST_POLICY_CHANGES_A_DAY = 100;

/**
 * Takes the organisation's lock for changing policies until the transaction
 * ends, so two changes at once can't both take the last of the day's budget,
 * nor both make a policy never set. Taken right after the idempotency key's
 * claim, before any row lock.
 */
export async function onePolicyChangeAtATime(tx: MandatesTransaction, orgId: string): Promise<void> {
  await holdTransactionLock(tx, 'policies', orgId);
}

/** How many policy versions the organisation made after `since`: the day's budget's count, in one statement. */
export async function policyChangesSince(tx: MandatesTransaction, orgId: string, since: Date): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a budget; no policy is decided on from it
    .selectFrom(POLICY_VERSIONS.table)
    .select(sql<number>`pg_catalog.count(*)::int`.as('made'))
    .where('org_id', '=', orgId)
    .where('made_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.made;
}

/** Whether the deployment takes the currency (0035's `allowed_currencies`: AED in the Pilot), in one statement. */
export async function currencyAllowed(tx: MandatesTransaction, code: string): Promise<boolean> {
  const row = await tx
    .selectFrom('mandates.allowed_currencies')
    .select('code')
    .where('code', '=', code)
    .executeTakeFirst();
  return row !== undefined;
}
