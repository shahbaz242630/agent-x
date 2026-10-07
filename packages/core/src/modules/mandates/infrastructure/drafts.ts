// Drafting mandates and new versions of them, and reading them (Phase 2 B2).
// Every read goes through the audit module's verifiedState; every write is a
// plain insert signed by record('new') in the same transaction (agents.ts says
// why a plain insert is safe), or a change of the mandate's waiting draft
// recorded from a state read for change.
//
// A mandate is drafted with its first version: the mandate's row, waiting for
// acceptance and naming the draft, then the version's, then their signed
// states, the mandate's first (lock order: the mandate before its versions).
// A later version is drafted from the mandate read for change: the version,
// then the mandate's waiting draft moved to it. A draft waiting already is
// replaced, never accepted after; acceptance (B3) takes whichever waits.
//
// Each version's terms are hashed with the facts of the mandate they bind
// (its ID, agent, zone and window) and the version's number, as canonical
// JSON: what an acceptance is bound to (B3), so an admin accepts these very
// terms and nothing else.
import type { SignedStateTable } from '@agentx/platform/db';
import { holdTransactionLock } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';
import { createHash } from 'node:crypto';

import {
  type AuditActor,
  type AuditDetails,
  type AuditTables,
  type PageAsked,
  type PageRead,
  type RecordedState,
  type SignedStates,
  type TamperSign,
  verifiedPage,
  type VerifiedState,
} from '../../audit/index.ts';
import { minorOf, money, oneOf, timeOf, wholeOf } from '../../../shared-kernel/index.ts';
import { CONSENT_LIMITS, isEnded, MANDATE, type MandateStatus, OPEN_STATES } from '../domain/mandate.ts';
import { type MandateTerms, mandateTerms } from '../domain/terms.ts';
import { MANDATE_VERSIONS, MANDATES } from './mandates.ts';
import type { MandatesTables } from './tables.ts';

/** A transaction on the tables mandates are drafted and read in, opened by withSignedStates for their organisation. */
type MandatesTransaction = Transaction<MandatesTables & AuditTables>;

interface MandateKey {
  readonly orgId: string;
  readonly id: string;
}

/** A mandate, as its signed state says. */
export interface MandateRecord {
  readonly id: string;
  readonly agentId: string;
  readonly timeZone: string;
  readonly splitWindowHours: number;
  readonly status: MandateStatus;
  /** The version in force, with who accepted it and when; null until one is. */
  readonly currentVersionId: string | null;
  readonly acceptedBy: string | null;
  readonly acceptedAt: Date | null;
  /** A draft waiting for acceptance, or null. */
  readonly pendingVersionId: string | null;
}

/** A version of a mandate's terms, as its signed state says. */
export interface MandateVersionRecord extends MandateTerms {
  readonly id: string;
  readonly mandateId: string;
  readonly version: number;
  readonly termsHash: string;
  /** The membership of the member who drafted it, and when. */
  readonly draftedBy: string;
  readonly draftedAt: Date;
}

/** A mandate read by its ID and verified, with the state a change records from; missing; or tampered with. */
type MandateCheck =
  | { readonly outcome: 'found'; readonly mandate: MandateRecord; readonly state: VerifiedState }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** A version read by its ID and verified as one of its mandate's; missing; or tampered with. */
type MandateVersionCheck =
  | { readonly outcome: 'found'; readonly version: MandateVersionRecord }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

type Fields = ReadonlyMap<string, string | null>;

/** The mandate's record from its verified fields, or undefined when one isn't of its kind. */
function mandateRecordOf(id: string, fields: Fields): MandateRecord | undefined {
  const agentId = fields.get('agent_id');
  const timeZone = fields.get('time_zone');
  const splitWindowHours = wholeOf(fields.get('split_window_hours'));
  const status = oneOf(MANDATE.states, fields.get('status'));
  const currentVersionId = fields.get('current_version_id');
  const pendingVersionId = fields.get('pending_version_id');
  const acceptedBy = fields.get('accepted_by');
  const acceptedAt = timeOf(fields.get('accepted_at'));
  if (
    typeof agentId !== 'string' ||
    typeof timeZone !== 'string' ||
    typeof splitWindowHours !== 'number' ||
    status === undefined ||
    currentVersionId === undefined ||
    pendingVersionId === undefined ||
    acceptedBy === undefined ||
    acceptedAt === undefined
  ) {
    return undefined;
  }
  return {
    id,
    agentId,
    timeZone,
    splitWindowHours,
    status,
    currentVersionId,
    pendingVersionId,
    acceptedBy,
    acceptedAt,
  };
}

/** The version's record from its verified fields, or undefined when one isn't of its kind. */
function versionRecordOf(id: string, fields: Fields): MandateVersionRecord | undefined {
  const text = (column: string) => {
    const value = fields.get(column);
    return typeof value === 'string' ? value : undefined;
  };
  const [mandateId, purpose, currency, supplierIds, fundingSourceId, termsHash, draftedBy] = [
    'mandate_id',
    'purpose',
    'currency',
    'supplier_ids',
    'funding_source_id',
    'terms_hash',
    'drafted_by',
  ].map(text);
  const version = wholeOf(fields.get('version'));
  const [perOrder, monthly, threshold] = [
    'per_order_limit_minor',
    'monthly_limit_minor',
    'approval_threshold_minor',
  ].map((column) => minorOf(fields.get(column)));
  const splitCheck = oneOf(['on', 'off'], fields.get('split_check'));
  const consentLimits = oneOf(CONSENT_LIMITS, fields.get('consent_limits'));
  const endsAt = timeOf(fields.get('ends_at'));
  const draftedAt = timeOf(fields.get('drafted_at'));
  if (
    mandateId === undefined ||
    purpose === undefined ||
    currency === undefined ||
    supplierIds === undefined ||
    fundingSourceId === undefined ||
    termsHash === undefined ||
    draftedBy === undefined ||
    typeof version !== 'number' ||
    perOrder === undefined ||
    monthly === undefined ||
    threshold === undefined ||
    splitCheck === undefined ||
    consentLimits === undefined ||
    endsAt === undefined ||
    !(draftedAt instanceof Date)
  ) {
    return undefined;
  }
  return {
    id,
    mandateId,
    version,
    purpose,
    perOrderLimit: money(perOrder, currency),
    monthlyLimit: money(monthly, currency),
    approvalThreshold: money(threshold, currency),
    supplierIds: supplierIds.split(' '),
    fundingSourceId,
    splitCheck: splitCheck === 'on',
    consentLimits,
    endsAt,
    termsHash,
    draftedBy,
    draftedAt,
  };
}

/** A verified row read back into its record, or a throw: the table's checks and the seal make any other a bug. */
function recordOf<Row>(table: SignedStateTable, id: string, record: Row | undefined): Row {
  if (record === undefined)
    throw new Error(`A verified ${table.subject} holds a field that isn't one of its own: ${id}`);
  return record;
}

/**
 * The mandate, by its ID, read and verified in the caller's transaction,
 * which must be withSignedStates' for its organisation: `share` for a
 * decision, `change` for a change (its state then what `record` takes).
 * Tampered with, the alarm is raised and the organisation held; anything but
 * `found` grants nothing.
 */
export async function mandateOf(
  tx: MandatesTransaction,
  states: SignedStates,
  key: MandateKey,
  lock: 'share' | 'change',
): Promise<MandateCheck> {
  const state = await states.verifiedState(tx, MANDATES, key, lock);
  if (state.outcome !== 'verified') return state;
  const id = key.id.toLowerCase();
  return { outcome: 'found', mandate: recordOf(MANDATES, id, mandateRecordOf(id, state.fields)), state };
}

/**
 * The version, by its ID, read (`share`) and verified: found only as a
 * version of `mandateId`, so another mandate's version is none of this one's.
 * Taken after its mandate, as the lock order has it.
 */
export async function mandateVersionOf(
  tx: MandatesTransaction,
  states: SignedStates,
  key: MandateKey,
  mandateId: string,
): Promise<MandateVersionCheck> {
  const state = await states.verifiedState(tx, MANDATE_VERSIONS, key, 'share');
  if (state.outcome !== 'verified') return state;
  const id = key.id.toLowerCase();
  const version = recordOf(MANDATE_VERSIONS, id, versionRecordOf(id, state.fields));
  if (version.mandateId !== mandateId.toLowerCase()) return { outcome: 'missing' };
  return { outcome: 'found', version };
}

/** The facts of a mandate a version's terms are bound to: they never change (0035's `fixed_at_creation`). */
type Binding = Pick<MandateRecord, 'id' | 'agentId' | 'timeZone' | 'splitWindowHours'>;

/** SHA-256 of the version's terms with the mandate's facts and its number, as canonical JSON, in lower-case hex. */
export function termsHash(of: Binding, version: number, terms: MandateTerms): string {
  const canonical = JSON.stringify([
    'agentx.mandate_terms.v1',
    of.id.toLowerCase(),
    of.agentId.toLowerCase(),
    of.timeZone,
    of.splitWindowHours,
    version,
    terms.purpose,
    terms.perOrderLimit.currency,
    terms.perOrderLimit.minor.toString(),
    terms.monthlyLimit.minor.toString(),
    terms.approvalThreshold.minor.toString(),
    terms.supplierIds.join(' '),
    terms.fundingSourceId,
    terms.splitCheck,
    terms.consentLimits,
    terms.endsAt?.toISOString() ?? null,
  ]);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/** A version of a mandate's terms, as a use case drafts it. */
interface NewVersion {
  readonly orgId: string;
  /** Its ID, made by the server. */
  readonly id: string;
  /** Its number: the mandate's next. A number taken is refused by the table's key. */
  readonly version: number;
  /** As mandateTerms keeps them (checked again by draftMandate or draftVersion); the use case has checked the suppliers and source are the organisation's. */
  readonly terms: MandateTerms;
  /** The membership of the member who drafted it, checked active by the use case. */
  readonly draftedBy: string;
  readonly draftedAt: Date;
  /** Who is drafting it. */
  readonly actor: AuditActor;
  /** More facts for its events, such as warnings past the bank consent. */
  readonly details?: AuditDetails;
}

/** Adds the version's row and records its first signed state. */
async function addVersion(
  tx: MandatesTransaction,
  states: SignedStates,
  of: Binding,
  { orgId, id, version, terms, draftedBy, draftedAt, actor, details = {} }: NewVersion,
): Promise<RecordedState> {
  const fields = {
    mandate_id: of.id,
    version,
    purpose: terms.purpose,
    currency: terms.perOrderLimit.currency,
    per_order_limit_minor: terms.perOrderLimit.minor,
    monthly_limit_minor: terms.monthlyLimit.minor,
    approval_threshold_minor: terms.approvalThreshold.minor,
    supplier_ids: terms.supplierIds.join(' '),
    funding_source_id: terms.fundingSourceId,
    split_check: terms.splitCheck ? 'on' : 'off',
    consent_limits: terms.consentLimits,
    ends_at: terms.endsAt,
    terms_hash: termsHash(of, version, terms),
    drafted_by: draftedBy,
    drafted_at: draftedAt,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(MANDATE_VERSIONS.table)
    .values({ org_id: orgId, id, ...fields })
    .execute();
  return states.record(tx, MANDATE_VERSIONS, { orgId, id }, 'new', fields, {
    actor,
    action: 'mandate_version.drafted',
    details: { ...details, mandateId: of.id, version, termsHash: fields.terms_hash },
  });
}

/** A new mandate, as a use case drafts it, with its first version. */
interface NewMandate extends Omit<NewVersion, 'version' | 'id'> {
  /** Its ID and its first version's, made by the server. */
  readonly id: string;
  readonly versionId: string;
  /** The agent it gives authority to, checked active by the use case. */
  readonly agentId: string;
  /** As the runtime names it (timeZoneOf), and the split window's hours (1–744). */
  readonly timeZone: string;
  readonly splitWindowHours: number;
}

/**
 * Drafts the mandate, waiting for acceptance, with its first version, in the
 * caller's transaction, which must be withSignedStates' for its organisation.
 * Terms it can't have are `MandateTermsRefused`, before any SQL runs. Gives
 * the mandate's first signed state, then the version's.
 */
export async function draftMandate(
  tx: MandatesTransaction,
  states: SignedStates,
  { id, versionId, agentId, timeZone, splitWindowHours, ...first }: NewMandate,
): Promise<{ readonly mandate: RecordedState; readonly version: RecordedState }> {
  const terms = mandateTerms(first.terms, first.draftedAt);
  const binding = { id: id.toLowerCase(), agentId: agentId.toLowerCase(), timeZone, splitWindowHours };
  const mandateFields = {
    agent_id: binding.agentId,
    time_zone: timeZone,
    split_window_hours: splitWindowHours,
    status: MANDATE.initial,
    current_version_id: null,
    pending_version_id: versionId,
    accepted_by: null,
    accepted_at: null,
  };
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below (see the top of this file)
    .insertInto(MANDATES.table)
    .values({ org_id: first.orgId, id, ...mandateFields, created_at: first.draftedAt })
    .execute();
  const mandate = await states.record(tx, MANDATES, { orgId: first.orgId, id }, 'new', mandateFields, {
    actor: first.actor,
    action: 'mandate.drafted',
    details: { agentId: binding.agentId, versionId },
  });
  return { mandate, version: await addVersion(tx, states, binding, { ...first, terms, id: versionId, version: 1 }) };
}

/**
 * Drafts a later version of the mandate, read for change in this transaction
 * (`of`), and makes it the draft waiting for acceptance, replacing any that
 * waited. A mandate ended (revoked or expired) takes none: a RangeError, as
 * the use case refuses it first.
 */
export async function draftVersion(
  tx: MandatesTransaction,
  states: SignedStates,
  of: { readonly mandate: MandateRecord; readonly state: VerifiedState },
  version: Omit<NewVersion, 'version'>,
): Promise<RecordedState> {
  if (isEnded(of.mandate.status)) throw new RangeError('An ended mandate takes no new version');
  const terms = mandateTerms(version.terms, version.draftedAt);
  const number = await nextVersionNumber(tx, version.orgId, of.mandate.id);
  const recorded = await addVersion(tx, states, of.mandate, { ...version, terms, version: number });
  await states.record(
    tx,
    MANDATES,
    { orgId: version.orgId, id: of.mandate.id },
    of.state,
    { pending_version_id: version.id },
    {
      actor: version.actor,
      action: 'mandate.redrafted',
      details: { versionId: version.id, replaced: of.mandate.pendingVersionId },
    },
  );
  return recorded;
}

/** The mandate's next version number, in one statement: one past the highest it has, a replaced draft's included. */
async function nextVersionNumber(tx: MandatesTransaction, orgId: string, mandateId: string): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a number alone, never an authority field; the table's key refuses one taken
    .selectFrom(MANDATE_VERSIONS.table)
    .select(sql<number>`coalesce(pg_catalog.max(version), 0)::int + 1`.as('next'))
    .where('org_id', '=', orgId)
    .where('mandate_id', '=', mandateId)
    .executeTakeFirstOrThrow();
  return row.next;
}

/**
 * The agent's open mandate (OPEN_STATES), read (`share`) and verified, or
 * missing when it has none, in one statement however long its history: the
 * row's status picks it, 0035's `one_open_mandate_an_agent` keeps it to one,
 * and the verified read means that status is the signed one.
 */
export async function openMandateOfAgent(
  tx: MandatesTransaction,
  states: SignedStates,
  orgId: string,
  agentId: string,
): Promise<MandateCheck> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- an ID alone, read through its signed state just below
    .selectFrom(MANDATES.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('agent_id', '=', agentId)
    .where('status', 'in', OPEN_STATES)
    .executeTakeFirst();
  return row === undefined ? { outcome: 'missing' } : mandateOf(tx, states, { orgId, id: row.id }, 'share');
}

/** A mandate as a list shows it: its signed state, with the purpose of the version in force, or else the waiting draft's. */
export interface MandateShown extends MandateRecord {
  readonly purpose: string;
}

/** The most mandates a page gives. */
export const MOST_MANDATES_A_PAGE = 50;

/**
 * A page of the organisation's mandates, in order of ID, each read (`share`)
 * and verified with the version it shows, in the caller's transaction, which
 * must be withSignedStates' for it; or tampered with, at the first that is.
 */
export async function mandatesPage(
  tx: MandatesTransaction,
  states: SignedStates,
  orgId: string,
  page: PageAsked,
): Promise<
  | { readonly outcome: 'listed'; readonly mandates: readonly MandateShown[]; readonly next: string | null }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const listed = await verifiedPage(
    tx,
    MANDATES,
    orgId,
    page,
    { most: MOST_MANDATES_A_PAGE, rows: 'mandates' },
    async (id): Promise<PageRead<MandateShown>> => {
      const read = await mandateOf(tx, states, { orgId, id }, 'share');
      if (read.outcome !== 'found') return read;
      const shown = read.mandate.currentVersionId ?? read.mandate.pendingVersionId;
      // A revoked draft keeps the version it waited with, so every mandate has one to show (0035's checks).
      if (shown === null) throw new Error(`A verified mandate has no version to show: ${id}`);
      const version = await mandateVersionOf(tx, states, { orgId, id: shown }, id);
      if (version.outcome === 'tampered') return version;
      if (version.outcome === 'missing') throw new Error(`A verified mandate's version is not its own: ${id}`);
      return { outcome: 'found', item: { ...read.mandate, purpose: version.version.purpose } };
    },
  );
  return listed.outcome === 'tampered' ? listed : { outcome: 'listed', mandates: listed.items, next: listed.next };
}

/** The most mandate versions an organisation may draft in any 24 hours: their records are never retired (the B8-1 lesson). */
export const MOST_DRAFTS_A_DAY = 100;

/**
 * Takes the organisation's lock for drafting mandates until the transaction
 * ends, so two drafts at once can't both take the last of the day's budget,
 * nor both find the agent with no mandate open. Taken right after the
 * idempotency key's claim, before any row lock.
 */
export async function oneDraftAtATime(tx: MandatesTransaction, orgId: string): Promise<void> {
  await holdTransactionLock(tx, 'mandates', orgId);
}

/** How many versions the organisation drafted after `since`: the day's budget's count, in one statement. */
export async function draftsSince(tx: MandatesTransaction, orgId: string, since: Date): Promise<number> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a count alone, for a budget; no mandate is decided on from it
    .selectFrom(MANDATE_VERSIONS.table)
    .select(sql<number>`pg_catalog.count(*)::int`.as('drafted'))
    .where('org_id', '=', orgId)
    .where('drafted_at', '>', since)
    .executeTakeFirstOrThrow();
  return row.drafted;
}
