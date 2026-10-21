// The fake partner's payments (Phase 4 B2; rail map §3–§4; PRD §11's fake
// adapter: success, decline, timeout on submit, duplicate and unknown;
// partner decision 5, S135): what the rail does with a payment Agent X hands
// it, shaped on the UAE Open Finance rail.
//
// - A payment is the partner's record of our instruction, by our instruction
//   ID (the rail's `x-idempotency-key`), its own reference the record's alias.
//   The same key again within 24 hours answers as the first did, whatever the
//   body: the rail's window. Past it, the key isn't protected: the rail makes
//   a second payment (kept beside the first, `ref:2`…), which is why Agent X
//   never resends (ADR-007 §10) and the lookup by key gives the newest.
// - The consent must be the organisation's, in use (Authorized), in the
//   payment's currency, not past its expiry, and within its per-payment
//   limit, the amount above nothing; otherwise the rail refuses with a 4xx
//   that creates nothing (a code, no record). Not checked by the fake: the
//   payee (it keeps no index of its references) and the consent's limits per
//   period (it keeps no index of payments by consent); the free sandboxes
//   check both before Phase 5.
// - What the rail answers is chosen by the amount's fils, so anyone can show
//   every outcome on staging (decision 5): `.01` declined (refused, no
//   payment made: FAILED); `.02` the submission's answer lost (a timeout: the
//   payment was made, the caller can't know); `.03` the rail's 409 for a key
//   it is already working on (a duplicate: made too, the caller can't know
//   either); `.04` an outcome that can't be known (rejected after the
//   business's account was debited: UNKNOWN); anything else succeeds.
// - A payment moves on as time passes, read whenever it is looked up: Pending,
//   then AcceptedSettlementCompleted after a minute, then the creditor's
//   account credited (AcceptedCreditSettlementCompleted) after two; `.04`'s
//   ends Rejected instead, with no proof the money never left.
import type { Clock } from '../../../shared-kernel/index.ts';
import type {
  ApprovedPaymentIntent,
  ExecutionLookup,
  PartnerExecutionRef,
  PaymentExecution,
  ProviderStatus,
  SubmissionResult,
} from '../domain/payments.ts';
import { availabilityOf } from '../domain/uae-consent.ts';
import type { FakeRecord, FakeRecords, PaymentBody } from './fake-records.ts';

/** The rail's idempotency window (rail map §1.6). */
const KEY_WINDOW_MS = 24 * 60 * 60_000;
/** How long the fake's payment waits before each next status. */
const STEP_MS = 60_000;

/** The reject codes the fake gives (`AANI.` codes, as Aani's), each proving no debit but the last. */
export const FAKE_REJECT_CODES = {
  /** Insufficient funds: refused before any debit. */
  declined: 'AANI.AM04',
  /** The consent isn't in use for this payment. */
  consent: 'AANI.AG01',
  /** Over the consent's limit per payment. */
  overLimit: 'AANI.AM02',
  /** A rejection after the account was debited: proves nothing. */
  afterDebit: 'AANI.FF01',
} as const;

/** What the amount's fils ask of the fake (decision 5): a payment made keeps the one it was made by. */
type Scripted = 'declined' | PaymentBody['script'];

const SCRIPTS: Readonly<Record<string, Scripted>> = { '1': 'declined', '2': 'lost', '3': 'duplicate', '4': 'unknown' };

/** The amount's last two digits in minor units, as fils: `.01` to `.04` choose an outcome, anything else succeeds. */
export const scriptOf = (amountMinor: bigint): Scripted => SCRIPTS[String(amountMinor % 100n)] ?? 'succeeds';

/** A submission as the fake did it: the rail's answer, and whether that answer is lost on the way back. */
export interface FakeSubmission {
  readonly result: SubmissionResult;
  readonly lost: boolean;
}

export interface FakePayments {
  submit(held: FakeRecords, intent: ApprovedPaymentIntent): Promise<FakeSubmission>;
  lookup(held: FakeRecords, ref: PartnerExecutionRef): Promise<ExecutionLookup>;
}

export function createFakePayments({ clock }: { readonly clock: Clock }): FakePayments {
  /** The payment's status now: moved on by the time passed since it was made. */
  const statusOf = (body: PaymentBody): { status: ProviderStatus; changedAt: Date } => {
    const made = new Date(body.submittedAt).getTime();
    const steps = Math.min(2, Math.floor((clock.now().getTime() - made) / STEP_MS));
    const changedAt = new Date(made + steps * STEP_MS);
    if (steps === 0) return { status: 'Pending', changedAt };
    if (steps === 1) return { status: 'AcceptedSettlementCompleted', changedAt };
    return { status: body.script === 'unknown' ? 'Rejected' : 'AcceptedCreditSettlementCompleted', changedAt };
  };

  const executionOf = (
    organizationId: string,
    instructionId: string,
    record: FakeRecord<'payment'>,
  ): PaymentExecution => {
    const { status, changedAt } = statusOf(record.body);
    return {
      organizationId,
      instructionId,
      paymentInstructionRef: record.alias,
      providerStatus: status,
      rejectCode: status === 'Rejected' ? FAKE_REJECT_CODES.afterDebit : null,
      // Rejected only after the account was debited: never proof that the money stayed.
      noDebitProven: false,
      statusChangedAt: changedAt,
      amountMinor: BigInt(record.body.amountMinor),
      currency: record.body.currency,
    };
  };

  /** The payments made under our key, oldest first: the first is the key itself, a resend past the window `key:2`… */
  const madeUnder = async (held: FakeRecords, key: string): Promise<FakeRecord<'payment'>[]> => {
    const made: FakeRecord<'payment'>[] = [];
    for (let n = 1; ; n += 1) {
      const record = await held.get('payment', n === 1 ? key : `${key}:${String(n)}`);
      if (record === undefined) return made;
      made.push(record);
    }
  };

  /** Why the rail refuses this payment before making it (a 4xx that creates nothing), or undefined. */
  const refusalOf = async (held: FakeRecords, intent: ApprovedPaymentIntent): Promise<string | undefined> => {
    if (intent.amountMinor <= 0n) return FAKE_REJECT_CODES.overLimit;
    const source = await held.byAlias('source', intent.accountConsentId);
    // Its stored status, and its expiry as the rail would by now have moved it (fake-rail's `brought`).
    const inUse =
      source !== undefined &&
      availabilityOf(source.body.status) === 'ACTIVE' &&
      clock.now() < new Date(source.body.expiresAt);
    if (!inUse) return FAKE_REJECT_CODES.consent;
    const { currency, maxPaymentMinor } = source.body.controls;
    if (currency !== intent.currency) return FAKE_REJECT_CODES.consent;
    if (intent.amountMinor > BigInt(maxPaymentMinor)) return FAKE_REJECT_CODES.overLimit;
    return scriptOf(intent.amountMinor) === 'declined' ? FAKE_REJECT_CODES.declined : undefined;
  };

  return {
    async submit(held, intent) {
      const made = await madeUnder(held, intent.instructionId);
      const newest = made.at(-1);
      const now = clock.now();
      // Within the window, the same key answers as the first did, whatever the body (rail map §1.6).
      if (newest !== undefined && now.getTime() - new Date(newest.body.submittedAt).getTime() < KEY_WINDOW_MS) {
        return {
          result: { kind: 'accepted', execution: executionOf(held.organizationId, intent.instructionId, newest) },
          lost: false,
        };
      }
      const refused = await refusalOf(held, intent);
      if (refused !== undefined) return { result: { kind: 'refused', code: refused }, lost: false };
      // Declined was refused above: what is left is a payment's.
      const script = scriptOf(intent.amountMinor) as PaymentBody['script'];
      const record: FakeRecord<'payment'> = {
        ref: made.length === 0 ? intent.instructionId : `${intent.instructionId}:${String(made.length + 1)}`,
        alias: `fake-payment-${intent.instructionId}-${String(made.length + 1)}`,
        body: {
          accountConsentId: intent.accountConsentId,
          beneficiaryRef: intent.beneficiaryRef,
          amountMinor: intent.amountMinor.toString(),
          currency: intent.currency,
          paymentReference: intent.paymentReference,
          submittedAt: now.toISOString(),
          script,
        },
      };
      // Another submission of the same key at once made it first (the second's add waits for its step, then adds
      // nothing): the rail answers with that payment, as within the window.
      const stored = (await held.add('payment', record)) ? record : await held.get('payment', record.ref);
      if (stored === undefined) throw new Error('A payment the fake partner just made is gone');
      return {
        result: { kind: 'accepted', execution: executionOf(held.organizationId, intent.instructionId, stored) },
        lost: stored === record && (script === 'lost' || script === 'duplicate'),
      };
    },

    async lookup(held, { organizationId, instructionId }) {
      const newest = (await madeUnder(held, instructionId)).at(-1);
      return newest === undefined
        ? { kind: 'not_found' }
        : { kind: 'found', execution: executionOf(organizationId, instructionId, newest) };
    },
  };
}
