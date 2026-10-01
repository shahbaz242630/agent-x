// Beneficiary registrations (0033): a supplier's payee registered with the
// partner, as ADR-014 §3 orders it. An authority table (ADR-012 §2), so its
// status, its supplier and the version it was started for, the partner, the
// route, who started it, and how it ended (the partner's reference, the payee
// key and its key's version, the name check, the masked name, the hint and
// when, or why it failed) must equal its latest signed event, and every read
// goes through the audit module's verifiedState with the description below.
// On the product's authority-table list (packages/core/src/authority-tables.ts)
// after its supplier and before its versions (ADR-006 §6: 6).
//
// Tx 1 adds it STARTED (startRegistration), within the organisation's day's
// budget, under its lock for payee changes. The partner is then called with
// our ID, outside any transaction. Tx 2 records its answer, server to server
// only (SEC-PAY-08): REGISTERED (recordRegistered), FAILED (recordFailed), or
// UNKNOWN for a call lost on the way (recordLost), until the partner is asked
// again by our ID. A registered one gives the new version its reference
// (suppliers.ts's addVersion), put in waiting (stagePayeeChange), and once
// the admin's step-up confirms it, the supplier its payee key
// (confirmPayeeChange). The insert is the only query on the table outside the
// audit module's steps but for the budget's count, as for a supplier's row.
// The seals are MACs, so the masked name is never put in an event.
import type { SignedStateTable } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import { type BeneficiaryState, PARTNER_NAME } from '../../providers/index.ts';
import {
  BENEFICIARY_REGISTRATION,
  NAME_CHECKS,
  type NameCheck,
  REGISTRATION_FAILURES,
  REGISTRATION_ROUTES,
  type RegistrationFailure,
  type RegistrationRoute,
  type RegistrationStatus,
} from '../domain/registration.ts';
import { oneOf, oneOfOrNull, timeOf, wholeOf } from './fields.ts';
import { noAccountNumberIn, type PayeeKey } from './payee-key.ts';
import type { SuppliersTables } from './tables.ts';

/** A registration's row, as the signed state reads, records and moves it. */
export const BENEFICIARY_REGISTRATIONS = {
  table: 'suppliers.beneficiary_registrations',
  subject: 'beneficiary_registration',
  fields: [
    { column: 'status', type: 'text' },
    { column: 'supplier_id', type: 'uuid' },
    { column: 'version_id', type: 'uuid' },
    { column: 'partner', type: 'text' },
    { column: 'route', type: 'text' },
    { column: 'started_by', type: 'uuid' },
    { column: 'beneficiary_ref', type: 'text' },
    { column: 'payee_key', type: 'text' },
    { column: 'payee_key_version', type: 'integer' },
    { column: 'name_check', type: 'text' },
    { column: 'masked_name', type: 'text' },
    { column: 'payee_hint', type: 'text' },
    { column: 'registered_at', type: 'timestamptz' },
    { column: 'failure', type: 'text' },
  ],
  rules: BENEFICIARY_REGISTRATION,
  // What each end needs (0033): CI's A3c allows these two checks over the status with other columns.
  statusConditions: ['registered_with_its_reference', 'failed_with_its_reason'],
} as const satisfies SignedStateTable & {
  readonly rules: typeof BENEFICIARY_REGISTRATION;
  readonly statusConditions: readonly string[];
};

/** A transaction on the suppliers' tables, opened by withSignedStates for their organisation. */
type RegistrationsTransaction = Transaction<SuppliersTables & AuditTables>;

interface RegistrationKey {
  readonly orgId: string;
  readonly id: string;
}

/** A registration as Tx 1 starts it. */
export interface NewRegistration {
  readonly orgId: string;
  /** Our ID, made by the server: the partner's idempotency key for it. */
  readonly id: string;
  readonly supplierId: string;
  /** The ID of the version Tx 2 makes with its reference, made by the server. */
  readonly versionId: string;
  readonly partner: string;
  readonly route: RegistrationRoute;
  /** The membership of the member who started it, checked active by the use case. */
  readonly startedBy: string;
  readonly createdAt: Date;
  /** Who is starting it. */
  readonly actor: AuditActor;
  /** More facts for its event. */
  readonly details?: AuditDetails;
}

/**
 * Adds the registration, STARTED, in the caller's transaction (Tx 1), which
 * must be withSignedStates' for its organisation and have read its supplier
 * (the lock order). A partner's name or a route that isn't one is refused
 * (RangeError) before any SQL runs; a supplier of no organisation's, or a
 * version already started for, by the table. Gives its first signed state.
 */
export async function startRegistration(
  tx: RegistrationsTransaction,
  states: SignedStates,
  { orgId, id, supplierId, versionId, partner, route, startedBy, createdAt, actor, details = {} }: NewRegistration,
): Promise<RecordedState> {
  if (!PARTNER_NAME.test(partner)) throw new RangeError('A partner is named in lower-case words');
  if (!REGISTRATION_ROUTES.includes(route)) {
    throw new RangeError('A registration goes by the hosted form or pass-through');
  }
  const fields = {
    status: BENEFICIARY_REGISTRATION.initial,
    supplier_id: supplierId,
    version_id: versionId,
    partner,
    route,
    started_by: startedBy,
    beneficiary_ref: null,
    payee_key: null,
    payee_key_version: null,
    name_check: null,
    masked_name: null,
    payee_hint: null,
    registered_at: null,
    failure: null,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(BENEFICIARY_REGISTRATIONS.table)
    .values({ org_id: orgId, id, ...fields, created_at: createdAt })
    .execute();
  return states.record(tx, BENEFICIARY_REGISTRATIONS, { orgId, id }, 'new', fields, {
    actor,
    action: 'beneficiary_registration.started',
    details: { ...details, supplierId, versionId, partner, route },
  });
}

/** A registration, as its signed state says. */
export interface RegistrationRecord {
  readonly id: string;
  readonly supplierId: string;
  /** The version it was started for. */
  readonly versionId: string;
  readonly partner: string;
  readonly route: RegistrationRoute;
  /** The membership of the member who started it. */
  readonly startedBy: string;
  readonly status: RegistrationStatus;
  /** How it ended, once REGISTERED: the partner's reference, the payee key and its key's version, and the rest, else null. */
  readonly beneficiaryRef: string | null;
  readonly payeeKey: string | null;
  readonly payeeKeyVersion: number | null;
  readonly nameCheck: NameCheck | null;
  readonly maskedName: string | null;
  readonly payeeHint: string | null;
  readonly registeredAt: Date | null;
  /** Why it failed, once FAILED, else null. */
  readonly failure: RegistrationFailure | null;
}

/** A registration read by its ID and verified, of the supplier asked about, with the state a change records from; missing; or tampered with. */
export type RegistrationCheck =
  | { readonly outcome: 'found'; readonly registration: RegistrationRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The registration's record from its verified fields, or undefined when one isn't of its kind. */
function registrationRecordOf(id: string, fields: ReadonlyMap<string, string | null>): RegistrationRecord | undefined {
  const status = oneOf(BENEFICIARY_REGISTRATION.states, fields.get('status'));
  const supplierId = fields.get('supplier_id');
  const versionId = fields.get('version_id');
  const partner = fields.get('partner');
  const route = oneOf(REGISTRATION_ROUTES, fields.get('route'));
  const startedBy = fields.get('started_by');
  const beneficiaryRef = fields.get('beneficiary_ref');
  const payeeKey = fields.get('payee_key');
  const payeeKeyVersion = wholeOf(fields.get('payee_key_version'));
  const nameCheck = oneOfOrNull(NAME_CHECKS, fields.get('name_check'));
  const maskedName = fields.get('masked_name');
  const payeeHint = fields.get('payee_hint');
  const registeredAt = timeOf(fields.get('registered_at'));
  const failure = oneOfOrNull(REGISTRATION_FAILURES, fields.get('failure'));
  if (
    status === undefined ||
    typeof supplierId !== 'string' ||
    typeof versionId !== 'string' ||
    typeof partner !== 'string' ||
    route === undefined ||
    typeof startedBy !== 'string' ||
    beneficiaryRef === undefined ||
    payeeKey === undefined ||
    payeeKeyVersion === undefined ||
    nameCheck === undefined ||
    maskedName === undefined ||
    payeeHint === undefined ||
    registeredAt === undefined ||
    failure === undefined
  ) {
    return undefined;
  }
  return {
    id,
    supplierId,
    versionId,
    partner,
    route,
    startedBy,
    status,
    beneficiaryRef,
    payeeKey,
    payeeKeyVersion,
    nameCheck,
    maskedName,
    payeeHint,
    registeredAt,
    failure,
  };
}

/**
 * The registration, by its ID, read and verified in the caller's
 * transaction, which must be withSignedStates' for its organisation: `share`
 * for a decision, `change` for a change (its state then what `record`
 * takes); found only as a registration of `supplierId`, so another
 * supplier's is none of this one's. Taken after its supplier, before the
 * versions, as the lock order has it. Tampered with, the alarm is raised and
 * the organisation held; anything but `found` grants nothing.
 */
export async function registrationOf(
  tx: RegistrationsTransaction,
  states: SignedStates,
  key: RegistrationKey,
  supplierId: string,
  lock: 'share' | 'change',
): Promise<RegistrationCheck> {
  const state = await states.verifiedState(tx, BENEFICIARY_REGISTRATIONS, key, lock);
  if (state.outcome !== 'verified') return state;
  const registration = registrationRecordOf(key.id.toLowerCase(), state.fields);
  // The table's checks hold each field to its kind, and the seal to what was written.
  if (registration === undefined) {
    throw new Error(`A verified beneficiary registration holds a field that isn't one of its own: ${key.id}`);
  }
  if (registration.supplierId !== supplierId.toLowerCase()) return { outcome: 'missing' };
  return { outcome: 'found', registration, state };
}

/** Who moves a registration, and the facts their events name. */
interface RegistrationChange {
  readonly actor: AuditActor;
  readonly details?: AuditDetails;
}

/** A registration read with `change`, as each of the moves below takes it. */
interface FoundRegistration {
  readonly registration: RegistrationRecord;
  readonly state: VerifiedState;
}

/** Refuses an `event` the registration's machine doesn't allow from where it stands, before any SQL runs. */
function mayMove(registration: RegistrationRecord, event: 'registered' | 'failed' | 'lost'): void {
  if (!BENEFICIARY_REGISTRATION.transition(registration.status, event).ok) {
    throw new RangeError(`A beneficiary registration can't be ${event} from ${registration.status}`);
  }
}

/** Moves the registration by `event`, which its machine must allow from where it stands. */
async function move(
  tx: RegistrationsTransaction,
  states: SignedStates,
  key: RegistrationKey,
  event: 'registered' | 'failed' | 'lost',
  { actor, details = {} }: RegistrationChange,
): Promise<void> {
  const moved = await states.changeStatus(tx, BENEFICIARY_REGISTRATIONS, key, event, {
    actor,
    action: `beneficiary_registration.${event}`,
    details,
  });
  if (moved.outcome !== 'changed') throw new RangeError(`A beneficiary registration can't be ${event}: ${key.id}`);
}

/**
 * Records the partner's registered payee (Tx 2), in the caller's transaction,
 * which read the registration with `change` (`found`): the reference, the
 * payee key (payeeKeyOf's, from the partner's one source), the name check,
 * the masked name, the hint and when, then STARTED or UNKNOWN > REGISTERED.
 * The partner's answer must name this organisation and this registration,
 * and the registration must be one that may be registered, or it is refused
 * (RangeError); a hint holding an account number is refused too
 * (AccountNumberLeak, never naming it, ADR-014 §3); each before any SQL
 * runs. Gives the registration as it now stands.
 */
export async function recordRegistered(
  tx: RegistrationsTransaction,
  states: SignedStates,
  key: RegistrationKey,
  found: FoundRegistration,
  {
    beneficiary,
    payee,
    ...change
  }: RegistrationChange & { readonly beneficiary: BeneficiaryState; readonly payee: PayeeKey },
): Promise<RegistrationRecord> {
  const { registration } = found;
  // A reference is accepted only from the partner's answer for this registration of this organisation (SEC-PAY-08).
  if (
    beneficiary.organizationId.toLowerCase() !== key.orgId.toLowerCase() ||
    beneficiary.registrationId.toLowerCase() !== registration.id
  ) {
    throw new RangeError("The partner's answer is for another registration");
  }
  mayMove(registration, 'registered');
  const ended = {
    beneficiary_ref: beneficiary.beneficiaryRef,
    // A partner's identity (no key version) is checked here too, whoever built the key; our fingerprint is a MAC.
    payee_key: payee.key !== null && payee.keyVersion === null ? noAccountNumberIn(payee.key) : payee.key,
    payee_key_version: payee.keyVersion,
    name_check: beneficiary.nameCheck,
    masked_name: beneficiary.maskedName,
    payee_hint: noAccountNumberIn(beneficiary.hint),
    registered_at: beneficiary.registeredAt,
  };
  // The fields first: 0033's `registered_with_its_reference` holds a REGISTERED row to them.
  await states.record(tx, BENEFICIARY_REGISTRATIONS, key, found.state, ended, {
    actor: change.actor,
    action: 'beneficiary_registration.answered',
    details: { ...change.details, nameCheck: beneficiary.nameCheck },
  });
  await move(tx, states, key, 'registered', change);
  return {
    ...registration,
    status: 'REGISTERED',
    beneficiaryRef: beneficiary.beneficiaryRef,
    payeeKey: payee.key,
    payeeKeyVersion: payee.keyVersion,
    nameCheck: beneficiary.nameCheck,
    maskedName: beneficiary.maskedName,
    payeeHint: beneficiary.hint,
    registeredAt: beneficiary.registeredAt,
  };
}

/**
 * Records why the partner refused the registration (Tx 2), in the caller's
 * transaction, which read it with `change` (`found`): the reason, then
 * STARTED or UNKNOWN > FAILED. A reason that isn't one, or a registration that
 * may not fail, is refused (RangeError) before any SQL runs.
 */
export async function recordFailed(
  tx: RegistrationsTransaction,
  states: SignedStates,
  key: RegistrationKey,
  found: FoundRegistration,
  { reason, ...change }: RegistrationChange & { readonly reason: RegistrationFailure },
): Promise<void> {
  if (!REGISTRATION_FAILURES.includes(reason)) throw new RangeError('Not a reason a registration fails for');
  mayMove(found.registration, 'failed');
  // The reason first: 0033's `failed_with_its_reason` holds a FAILED row to it.
  await states.record(
    tx,
    BENEFICIARY_REGISTRATIONS,
    key,
    found.state,
    { failure: reason },
    { actor: change.actor, action: 'beneficiary_registration.refused', details: { ...change.details, reason } },
  );
  await move(tx, states, key, 'failed', change);
}

/**
 * Records a call to the partner lost on the way (a timeout): STARTED >
 * UNKNOWN, in the caller's transaction, which read it with `change`. The
 * partner is then asked by our ID, never registered with again blindly
 * (ADR-014 §3). One not STARTED is refused (RangeError).
 */
export async function recordLost(
  tx: RegistrationsTransaction,
  states: SignedStates,
  key: RegistrationKey,
  change: RegistrationChange,
): Promise<void> {
  await move(tx, states, key, 'lost', change);
}

/** The most payee registrations an organisation may start in any 24 hours (partner, S71): they are never retired (the B8-1 lesson). */
export const MOST_PAYEE_REGISTRATIONS_A_DAY = 100;

/**
 * Takes the organisation's lock for changing payees until the transaction
 * ends, so two registrations at once can't both take the last of the day's
 * budget. Taken right after the idempotency key's claim, before any row lock.
 */
export async function onePayeeChangeAtATime(tx: RegistrationsTransaction, orgId: string): Promise<void> {
  const key = `agentx.payees:${orgId.toLowerCase()}`;
  await sql`select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(${key}, 0))`.execute(tx);
}

/** How many registrations the organisation started after `since`: the day's budget's count, in one statement. */
export async function registrationsStartedSince(
  tx: RegistrationsTransaction,
  orgId: string,
  since: Date,
): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a budget; no registration is decided on from it
    .selectFrom(BENEFICIARY_REGISTRATIONS.table)
    .select(sql<number>`pg_catalog.count(*)::int`.as('started'))
    .where('org_id', '=', orgId)
    .where('created_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.started;
}

/**
 * The ID of one of the supplier's registrations still open (STARTED or
 * UNKNOWN), or null, in one statement: where to look alone, so a start
 * carries on with it rather than opening another (E2-2a's review). The caller
 * reads it through its signed state before deciding anything of it.
 */
export async function openRegistrationOf(
  tx: RegistrationsTransaction,
  orgId: string,
  supplierId: string,
): Promise<string | null> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look alone; the registration is then read through its signed state
    .selectFrom(BENEFICIARY_REGISTRATIONS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('supplier_id', '=', supplierId)
    .where('status', 'in', ['STARTED', 'UNKNOWN'])
    .orderBy('created_at')
    .executeTakeFirst();
  return row?.id ?? null;
}

/**
 * The ID of the organisation's supplier holding `payeeKey`, or null, in one
 * statement: where to look alone, for telling a member which supplier already
 * pays that account. The caller reads that supplier through its signed state
 * before saying anything of it. Tx 2's early word alone, binding nothing:
 * the index refuses the key at confirmPayeeChange.
 */
export async function supplierWithPayeeKey(
  tx: RegistrationsTransaction,
  orgId: string,
  payeeKey: string,
): Promise<string | null> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- where to look alone; the supplier is then read through its signed state
    .selectFrom('suppliers.suppliers')
    .select('id')
    // Redundant under RLS (a mutation pass found it so), but kept so the lookup uses one_supplier_a_payee's (org_id, payee_key).
    .where('org_id', '=', orgId)
    .where('payee_key', '=', payeeKey)
    .executeTakeFirst();
  return row?.id ?? null;
}

/**
 * Whether an error is 0033's `one_supplier_a_payee` refusing a payee key
 * another supplier of the organisation holds (confirmPayeeChange): that index
 * alone, so no other key's refusal is taken for it.
 */
export const isPayeeTaken = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  (error as { code?: unknown }).code === '23505' &&
  (error as { constraint?: unknown }).constraint === 'one_supplier_a_payee';
