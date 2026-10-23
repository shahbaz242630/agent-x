// The one logical instruction a spend request hands to the partner (0058;
// PRD §3 `ProviderInstruction`; ADR-007 §7; ADR-014 §1–§3; Phase 4 B3): the
// approved intent exactly as it went, made once in the hand-off's Tx A and
// never changed, an authority table read and recorded through the audit
// module's signed states (the product's authority-table list,
// packages/core/src/authority-tables.ts).
//
// - `makeInstruction`: adds it, signs it (`instruction.made`, its intent's
//   SHA-256 among the facts sealed), and enters its ID in the directory so a
//   partner's event naming only our ID finds its organisation (ADR-005). A
//   second instruction for the same request is refused by the table's key
//   (`one_instruction_a_request`): the caller's Tx A, which moved the request
//   to HANDED_OFF first, never reaches it (ADR-007 §7).
// - `instructionOf` / `instructionOfRequest`: read through the signed state.
// - `intentHashOf`: the SHA-256 of the intent's every field, in a fixed order,
//   as evidence names it (PRD §8 "normalized instruction hash").
import { createHash } from 'node:crypto';

import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type {
  AuditActor,
  AuditDetails,
  AuditTables,
  RecordedState,
  SignedStates,
  TamperSign,
} from '../../audit/index.ts';
import type { InstructionsTables } from './tables.ts';

/** An instruction's row, as the signed state reads and records it: made once, never moved (0058's `made_once`). */
export const INSTRUCTIONS = {
  table: 'instructions.instructions',
  subject: 'instruction',
  fields: [
    { column: 'spend_request_id', type: 'uuid' },
    { column: 'route', type: 'text' },
    { column: 'route_reason', type: 'text' },
    { column: 'funding_source_id', type: 'uuid' },
    { column: 'partner', type: 'text' },
    { column: 'partner_legal_entity_id', type: 'text' },
    { column: 'partner_licence_ref', type: 'text' },
    { column: 'account_consent_id', type: 'text' },
    { column: 'beneficiary_ref', type: 'text' },
    { column: 'supplier_version_id', type: 'uuid' },
    { column: 'amount_minor', type: 'integer' },
    { column: 'currency', type: 'text' },
    { column: 'payment_reference', type: 'text' },
    { column: 'intent_hash', type: 'text' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  madeOnce: true,
} as const satisfies SignedStateTable & { readonly madeOnce: true };

/** A transaction on the instructions, the directory's entry for them and the audit tables, withSignedStates' for its organisation. */
export type InstructionsTransaction = Transaction<InstructionsTables & AuditTables>;

/** The one rail Agent X routes to in the Pilot (BR-12: one partner rail, a push payment). */
type Route = 'push';

/** An instruction as the hand-off makes it: every field from what it verified in its Tx A. */
export interface NewInstruction {
  readonly orgId: string;
  /** Ours, and the partner's idempotency key: a UUIDv7, 36 characters, within the rail's 40. */
  readonly id: string;
  readonly spendRequestId: string;
  readonly route: Route;
  /** Why this route, in words of its own (BR-12: the route still records an explainable reason). */
  readonly routeReason: string;
  readonly fundingSourceId: string;
  readonly partner: string;
  readonly partnerLegalEntityId: string;
  readonly partnerLicenceRef: string;
  readonly accountConsentId: string;
  readonly beneficiaryRef: string;
  readonly supplierVersionId: string;
  readonly amountMinor: bigint;
  readonly currency: string;
  readonly paymentReference: string;
  readonly createdAt: Date;
}

/** An instruction as its signed state holds it, its intent's hash with it. */
interface InstructionRecord extends Omit<NewInstruction, 'orgId' | 'createdAt'> {
  readonly intentHash: string;
  readonly createdAt: Date;
}

/** The instruction, verified; none; or tampered with (its alarm raised). */
export type InstructionCheck =
  | { readonly outcome: 'found'; readonly instruction: InstructionRecord }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** The fields an intent is hashed over, in this order, IDs in lower case. */
const hashed = (instruction: Omit<NewInstruction, 'createdAt'>): readonly string[] => [
  'agentx-instruction',
  instruction.orgId.toLowerCase(),
  instruction.id.toLowerCase(),
  instruction.spendRequestId.toLowerCase(),
  instruction.route,
  instruction.routeReason,
  instruction.fundingSourceId.toLowerCase(),
  instruction.partner,
  instruction.partnerLegalEntityId,
  instruction.partnerLicenceRef,
  instruction.accountConsentId,
  instruction.beneficiaryRef,
  instruction.supplierVersionId.toLowerCase(),
  instruction.amountMinor.toString(),
  instruction.currency,
  instruction.paymentReference,
];

/** The intent's SHA-256, in lower-case hex: each field length-prefixed, so no two intents' texts run together alike. */
export function intentHashOf(instruction: Omit<NewInstruction, 'createdAt'>): string {
  const hash = createHash('sha256');
  for (const part of hashed(instruction)) hash.update(`${String(Buffer.byteLength(part))}:${part}\n`);
  return hash.digest('hex');
}

/**
 * Adds the instruction, signs it, and enters it in the directory, in the
 * caller's transaction (withSignedStates' for its organisation), whose
 * request is locked for its hand-off (ADR-006 §6: 8, then this at 10). The
 * signed event is recorded at the head's place, which the caller keeps last.
 */
export async function makeInstruction(
  tx: InstructionsTransaction,
  states: SignedStates,
  instruction: NewInstruction,
  change: { readonly actor: AuditActor; readonly details: AuditDetails },
): Promise<RecordedState & { readonly intentHash: string }> {
  const intentHash = intentHashOf(instruction);
  const { orgId, id } = instruction;
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by record('new') just below
    .insertInto(INSTRUCTIONS.table)
    .values({
      org_id: orgId,
      id,
      spend_request_id: instruction.spendRequestId,
      route: instruction.route,
      route_reason: instruction.routeReason,
      funding_source_id: instruction.fundingSourceId,
      partner: instruction.partner,
      partner_legal_entity_id: instruction.partnerLegalEntityId,
      partner_licence_ref: instruction.partnerLicenceRef,
      account_consent_id: instruction.accountConsentId,
      beneficiary_ref: instruction.beneficiaryRef,
      supplier_version_id: instruction.supplierVersionId,
      amount_minor: instruction.amountMinor.toString(),
      currency: instruction.currency,
      payment_reference: instruction.paymentReference,
      intent_hash: intentHash,
      created_at: instruction.createdAt,
    })
    .execute();
  // With its consent (0063, E1b): a partner's message naming the consent alone finds its payments.
  await tx
    .insertInto('directory.instructions')
    .values({ instruction_id: id, org_id: orgId, account_consent_id: instruction.accountConsentId })
    .execute();
  const recorded = await states.record(
    tx,
    INSTRUCTIONS,
    { orgId, id },
    'new',
    {
      spend_request_id: instruction.spendRequestId,
      route: instruction.route,
      route_reason: instruction.routeReason,
      funding_source_id: instruction.fundingSourceId,
      partner: instruction.partner,
      partner_legal_entity_id: instruction.partnerLegalEntityId,
      partner_licence_ref: instruction.partnerLicenceRef,
      account_consent_id: instruction.accountConsentId,
      beneficiary_ref: instruction.beneficiaryRef,
      supplier_version_id: instruction.supplierVersionId,
      amount_minor: instruction.amountMinor,
      currency: instruction.currency,
      payment_reference: instruction.paymentReference,
      intent_hash: intentHash,
      created_at: instruction.createdAt,
    },
    {
      actor: change.actor,
      action: 'instruction.made',
      details: { ...change.details, spendRequestId: instruction.spendRequestId.toLowerCase(), intentHash },
    },
  );
  return { ...recorded, intentHash };
}

/** The instruction its verified state holds: 0058's checks hold every field to its kind (none null), and the seal to what was written. */
function recordOf(id: string, fields: ReadonlyMap<string, string | null>): InstructionRecord {
  const text = (column: string): string => String(fields.get(column));
  return {
    id,
    spendRequestId: text('spend_request_id'),
    // 0058's check holds the route to the one the Pilot has.
    route: text('route') as Route,
    routeReason: text('route_reason'),
    fundingSourceId: text('funding_source_id'),
    partner: text('partner'),
    partnerLegalEntityId: text('partner_legal_entity_id'),
    partnerLicenceRef: text('partner_licence_ref'),
    accountConsentId: text('account_consent_id'),
    beneficiaryRef: text('beneficiary_ref'),
    supplierVersionId: text('supplier_version_id'),
    amountMinor: BigInt(text('amount_minor')),
    currency: text('currency'),
    paymentReference: text('payment_reference'),
    intentHash: text('intent_hash'),
    createdAt: new Date(text('created_at')),
  };
}

/** The instruction, read through its signed state (`share`), in the caller's transaction (withSignedStates'). */
export async function instructionOf(
  tx: InstructionsTransaction,
  states: SignedStates,
  key: { readonly orgId: string; readonly id: string },
): Promise<InstructionCheck> {
  const state = await states.verifiedState(tx, INSTRUCTIONS, key, 'share');
  if (state.outcome === 'tampered') return state;
  if (state.outcome === 'missing') return state;
  return { outcome: 'found', instruction: recordOf(key.id.toLowerCase(), state.fields) };
}

/**
 * The request's instruction, if it has one, read through its signed state:
 * its ID found by the request's (the table's key), then the row verified, so
 * a row changed past the app is caught as any is.
 */
export async function instructionOfRequest(
  tx: InstructionsTransaction,
  states: SignedStates,
  { orgId, spendRequestId }: { readonly orgId: string; readonly spendRequestId: string },
): Promise<InstructionCheck> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- its ID alone, the row then read through its signed state
    .selectFrom(INSTRUCTIONS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('spend_request_id', '=', spendRequestId)
    .executeTakeFirst();
  // Its request is a signed field: a row whose request was changed past the app reads as tampered.
  return row === undefined ? { outcome: 'missing' } : instructionOf(tx, states, { orgId, id: row.id });
}

/** The organisation an instruction is in, from the directory: a partner's event names our ID alone (ADR-005). */
export async function organizationOfInstruction(
  db: Pick<Transaction<InstructionsTables>, 'selectFrom'>,
  instructionId: string,
): Promise<string | undefined> {
  const row = await db
    .selectFrom('directory.instructions')
    .select('org_id')
    .where('instruction_id', '=', instructionId)
    .executeTakeFirst();
  return row?.org_id;
}

/**
 * The organisation a consent's payments are in, from the directory (E1b): a
 * partner's message naming the consent alone (rail map §1.8) is routed there,
 * and the bank check finds the payments under it inside that organisation.
 * A consent is one organisation's; none where no payment was made under it.
 */
export async function organizationOfConsent(
  db: Pick<Transaction<InstructionsTables>, 'selectFrom'>,
  consentId: string,
): Promise<string | undefined> {
  const row = await db
    .selectFrom('directory.instructions')
    .select('org_id')
    .where('account_consent_id', '=', consentId)
    .orderBy('instruction_id')
    .limit(1)
    .executeTakeFirst();
  return row?.org_id;
}
