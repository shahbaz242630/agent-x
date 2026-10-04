// Registering a supplier's payee with the payment partner (ADR-014 §3,
// PRD §6, BR-04, SEC-PAY-05, SEC-PAY-06, SEC-PAY-08; Phase 1 E2-2a, E2-2d),
// through the partner's hosted form, so the bank details never touch Agent
// X, or passed through (E2-2d), held in one request's memory alone. Composed
// here, in the API, as ADR-004 §7 has it: the partner is the providers
// module's adapter, the supplier and its registrations the suppliers
// module's, the member identity's.
//
// 1. `start` (`suppliers.payee.start`), an admin: the partner's offer read
//    first (a partner with no hosted form, or one whose payee key must come
//    from pass-through, PAYEE_ROUTE_NOT_OFFERED). Tx 1: the key claimed; the
//    organisation's lock for payee changes; the admin read again; the day's
//    supplier, with no change already waiting (SUPPLIER_CHANGE_WAITING); one
//    of its registrations still open carried on with, rather than another
//    opened; otherwise the day's budget (PAYEE_REGISTRATIONS_SPENT: never
//    retired, the B8-1 lesson) and the registration, STARTED, naming the
//    version Tx 2 will make, with no bank data. Then the partner, outside any transaction, with our ID as its
//    idempotency key: its form, held to the partner's own form origin over
//    HTTPS (`isPartnerPage`), is where the admin is sent. A call lost on the
//    way leaves the registration UNKNOWN, and from then on the partner is
//    asked by our ID, never registered with blindly again. A retry of the same
//    write answers the same registration, asking the partner again by its ID.
// 2. The admin fills in the partner's form. Nothing that comes back through
//    the browser is believed.
// 3. `check` (`suppliers.payee.check`), an admin: the partner is asked,
//    server to server, how the registration Agent X started for this
//    organisation and supplier stands (SEC-PAY-08). Tx 2: the key claimed;
//    the admin read again; the supplier and the registration read for
//    change; then: still waiting at the form, left as it is (202) and the
//    key's claim rolled back, so asking again with the same key asks the
//    partner again; refused, recorded FAILED with why (but `unknown` for one
//    still STARTED: the partner may not have been asked yet, and a start
//    carries it on); registered, the partner's reference recorded with the
//    payee key from the partner's one source, and, unless another supplier is
//    paid to it (then SUPPLIER_PAYEE_TAKEN, the registration ended), a
//    verified supplier taken back to UNVERIFIED (a supplier is verified only
//    on the version verified, 0032), the new version made with the current
//    details and the registration's reference, numbered past any withdrawn
//    one, and put in waiting: inert, the supplier still paying the version it
//    paid, until the admin's step-up confirms it (E2-2b). A registration
//    already ended answers as it stands. An answer the partner's contract
//    forbids (an account number, or a stable identity that can't be kept)
//    is never kept: the registration FAILED, logged by IDs.
// 4. `passThrough` (`suppliers.payee.pass-through`), an admin, the name and
//    IBAN in the body (E2-2d): Tx 1 as a start's, but never carrying on with
//    a registration still open, as the partner answers a registration's ID as
//    it first did, whatever details come with it, so another request's IBAN
//    could be keyed to another account. Then the partner registers the
//    payee with the details, outside any transaction, and its answer is kept
//    at once, as a check's (Tx 2, the key already spent by Tx 1): where the
//    partner's one source is ours, our fingerprint of the IBAN
//    (payeeFingerprint) is the payee key. The IBAN goes no further than this
//    request: not stored, not logged, and the idempotency key's hash of it is
//    keyed. A call lost on the way leaves it UNKNOWN; the same request sent
//    again with the same key (the same IBAN, as its hash holds it) asks the
//    partner by our ID and keeps the answer. A check can't take our
//    fingerprint, so one it finds registered is left open for that request,
//    logged by IDs. Two at once for one supplier: the second's Tx 2 finds the
//    first's change waiting (SUPPLIER_CHANGE_WAITING) and leaves its own open,
//    inert at the partner, as a check does.
//
// Lock order (ADR-006 §6): the idempotency key, the payee-change lock (a
// start's alone, for its budget: the supplier's row, read for change by a
// check, serialises the rest), the member's membership (2a), the supplier
// (6), its registration; the chain
// head with the first event recorded, after which only new version rows are
// written, which wait on nothing.
import type { SignedStates } from '@agentx/core/modules/audit';
import {
  AccountNumberLeak,
  type BeneficiaryOutcome,
  type FinancialRailAdapter,
  isPartnerPage,
  type PayeeDetails,
  type RailCapabilities,
} from '@agentx/core/modules/providers';
import {
  addVersion,
  contactsOf,
  MOST_PAYEE_REGISTRATIONS_A_DAY,
  nextVersionNumber,
  onePayeeChangeAtATime,
  openRegistrationOf,
  payeeFingerprint,
  type PayeeKey,
  payeeKeyOf,
  payeeKeySource,
  recordFailed,
  recordLost,
  recordRegistered,
  registrationOf,
  type RegistrationRecord,
  type RegistrationRoute,
  registrationsStartedSince,
  stagePayeeChange,
  startRegistration,
  type SupplierRecord,
  UnusablePayeeIdentity,
  supplierWithPayeeKey,
  unverifySupplier,
  versionOf,
} from '@agentx/core/modules/suppliers';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { asked, orStillWaiting, PARTNER_UNAVAILABLE, StillWaiting } from './funding-source-work.ts';
import type { Refused } from './refused.ts';
import {
  createSupplierWork,
  type SupplierMember,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
} from './supplier-work.ts';

/** Starting a payee registration through the partner's form. */
export const PAYEE_START_OPERATION = 'suppliers.payee.start';
/** Asking the partner how it stands, and keeping its answer. */
export const PAYEE_CHECK_OPERATION = 'suppliers.payee.check';
/** Registering a payee with the details passed through (E2-2d). */
export const PAYEE_PASS_THROUGH_OPERATION = 'suppliers.payee.pass-through';

/** Who may register a supplier's payee: the admins (partner, S69). */
export const REGISTERING_ROLES = ['admin'] as const;

/** The partner's form a person is sent to, and until when it is open. */
interface PayeeForm {
  readonly url: string;
  readonly expiresAt: Date;
}

/** A registration as the routes answer it, with the partner's form while it is open. */
export interface PayeeRegistrationView {
  readonly registration: RegistrationRecord;
  readonly form: PayeeForm | null;
}

export type PayeeWrite =
  ({ readonly outcome: 'started' | 'checked' | 'waiting' } & PayeeRegistrationView) | PayeeRefusal;

/** A payee write not done: a refusal, or its key's outcome. */
type PayeeRefusal = { readonly outcome: 'conflict' } | { readonly outcome: 'busy' } | Refused;

const ROUTE_NOT_OFFERED: Refused = { outcome: 'refused', status: 409, code: 'PAYEE_ROUTE_NOT_OFFERED' };

export interface SupplierPayees {
  start(
    member: SupplierMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    correlationId: string,
  ): Promise<PayeeWrite>;
  check(
    member: SupplierMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    registrationId: string,
    correlationId: string,
  ): Promise<PayeeWrite>;
  passThrough(
    member: SupplierMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    payee: PayeeDetails,
    correlationId: string,
  ): Promise<PayeeWrite>;
}

/** A registration the partner may still answer: neither registered nor failed. */
const isOpen = (registration: RegistrationRecord): boolean =>
  registration.status === 'STARTED' || registration.status === 'UNKNOWN';

/** A registration read and verified, with the state a change records from. */
type RegistrationFound = Extract<Awaited<ReturnType<typeof registrationOf>>, { outcome: 'found' }>;

export function createSupplierPayees({
  database,
  keys,
  ids,
  clock,
  rail,
  partner,
  logger,
}: {
  readonly database: Database<SupplierTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** The partner, or undefined where none is set up (config.partner): then every call answers PARTNER_UNAVAILABLE. */
  readonly rail: FinancialRailAdapter | undefined;
  /** The partner's name, as a registration keeps it. */
  readonly partner: string;
  readonly logger: Logger;
}): SupplierPayees {
  const work = createSupplierWork({ database, keys, ids, logger });

  /** The registration, of this supplier, read and verified: NOT_FOUND, or INTEGRITY_FAILED for one that can't be believed. */
  const registrationIn = async (
    tx: SupplierTx,
    states: SignedStates,
    orgId: string,
    supplierId: string,
    registrationId: string,
    lock: 'share' | 'change',
  ): Promise<RegistrationFound> => {
    const read = await registrationOf(tx, states, { orgId, id: registrationId }, supplierId, lock);
    if (read.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new SupplierRefused(404, 'NOT_FOUND');
    return read;
  };

  /** The supplier, then its registration, read (`share`) in a transaction of their own. */
  const registrationNow = (orgId: string, supplierId: string, registrationId: string, correlationId: string) =>
    work.answered(orgId, correlationId, async (tx, states) => {
      const { supplier } = await work.supplierIn(tx, states, { orgId, id: supplierId }, 'share');
      return (await registrationIn(tx, states, orgId, supplier.id, registrationId, 'share')).registration;
    });

  /** The form the partner answered, if it may be sent to a person's browser: logged and PARTNER_UNAVAILABLE otherwise. */
  const formOf = (
    outcome: BeneficiaryOutcome,
    { formOrigin }: FinancialRailAdapter,
    correlationId: string,
  ): PayeeForm | null | Refused => {
    if (outcome.kind !== 'waiting') return null;
    if (!isPartnerPage(outcome.formUrl, formOrigin)) {
      logger.child({ correlationId }).error('suppliers.partner_page_refused', { partner });
      return PARTNER_UNAVAILABLE;
    }
    return { url: outcome.formUrl, expiresAt: outcome.expiresAt };
  };

  /** A payee change refused inside Tx 2, answered as such; still waiting, answered with nothing of it kept. */
  const write = (
    member: SupplierMember,
    idempotent: IdempotentRequest,
    correlationId: string,
    change: (tx: SupplierTx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => orStillWaiting(() => work.write(member, idempotent, correlationId, change));

  /** Refused past the day's budget of payee registrations (PAYEE_REGISTRATIONS_SPENT). */
  const withinBudget = async (tx: SupplierTx, orgId: string): Promise<void> => {
    const since = new Date(clock.now().getTime() - DAY_MS);
    if ((await registrationsStartedSince(tx, orgId, since)) >= MOST_PAYEE_REGISTRATIONS_A_DAY) {
      throw new SupplierRefused(409, 'PAYEE_REGISTRATIONS_SPENT');
    }
  };

  /**
   * The registration's payee, from the partner's registered answer (Tx 2):
   * its reference and payee key recorded, then, unless another supplier is
   * paid to that payee (left REGISTERED with no version, which the answer
   * reads as SUPPLIER_PAYEE_TAKEN), the new version made with the current
   * details and put in waiting. An answer naming an account number is
   * refused (AccountNumberLeak) before anything is written. The registration
   * was read for change after its supplier, as the lock order has it.
   */
  const keepRegistered = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SupplierMember,
    {
      supplierId,
      found,
      beneficiary,
      offer,
      enteredBy,
      fingerprint,
    }: {
      readonly supplierId: string;
      readonly found: RegistrationFound;
      readonly beneficiary: Extract<BeneficiaryOutcome, { kind: 'registered' }>['beneficiary'];
      readonly offer: RailCapabilities;
      readonly enteredBy: string;
      readonly fingerprint: PayeeKey | null;
    },
  ): Promise<void> => {
    const { orgId } = member;
    const supplierKey = { orgId, id: supplierId };
    const actor = { type: 'user' as const, id: member.userId };
    const payee = payeeKeyOf(payeeKeySource(offer, found.registration.route), beneficiary, fingerprint);
    // The early word: the index refuses the key again at the confirmation, whoever takes it first.
    const holder = payee.key === null ? null : await supplierWithPayeeKey(tx, orgId, payee.key);
    const registration = await recordRegistered(tx, states, { orgId, id: found.registration.id }, found, {
      beneficiary,
      payee,
      actor,
    });
    if (holder !== null && holder !== supplierId) return;
    // VERIFIED only on the version verified with nothing waiting (0032): a payee change is verified again (E3).
    let read = await work.supplierIn(tx, states, supplierKey, 'change');
    if (read.supplier.status === 'VERIFIED') {
      await unverifySupplier(tx, states, supplierKey, read, { actor });
      read = await work.supplierIn(tx, states, supplierKey, 'change');
    }
    const current = await work.versionIn(tx, states, orgId, supplierId, read.supplier.currentVersionId);
    const { displayName, source } = current;
    await addVersion(tx, states, keys, {
      orgId,
      id: registration.versionId,
      supplierId,
      version: await nextVersionNumber(tx, orgId, supplierId),
      supplier: { displayName, contacts: await contactsOf(tx, keys, orgId, current), source },
      enteredBy,
      enteredAt: clock.now(),
      actor,
      of: read,
      follows: current,
      registration,
    });
    const made = await versionOf(tx, states, { orgId, id: registration.versionId }, supplierId);
    if (made.outcome !== 'found') throw new Error(`a version just made isn't there: ${registration.versionId}`);
    await stagePayeeChange(
      tx,
      states,
      supplierKey,
      read,
      { version: made.version, registration, current: current },
      { actor },
    );
  };

  /**
   * The answer after a write: the registration as it now stands, with the
   * partner's form if it gave one; a registration REGISTERED with no version
   * made from it, SUPPLIER_PAYEE_TAKEN (keepRegistered left it so).
   */
  const answer = (
    outcome: 'started' | 'checked' | 'waiting',
    member: SupplierMember,
    supplierId: string,
    registrationId: string,
    form: PayeeForm | null,
    correlationId: string,
  ): Promise<PayeeWrite> =>
    work.answered(member.orgId, correlationId, async (tx, states) => {
      const { orgId } = member;
      const { supplier } = await work.supplierIn(tx, states, { orgId, id: supplierId }, 'share');
      const { registration } = await registrationIn(tx, states, orgId, supplier.id, registrationId, 'share');
      if (registration.status === 'REGISTERED') {
        const made = await versionOf(tx, states, { orgId, id: registration.versionId }, supplier.id);
        if (made.outcome === 'tampered') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
        if (made.outcome === 'missing') throw new SupplierRefused(409, 'SUPPLIER_PAYEE_TAKEN');
      }
      return { outcome, registration, form: isOpen(registration) ? form : null };
    });

  /**
   * Asks the partner about a registration Tx 1 added or carried on with:
   * STARTED, registered under our ID (the same ID answers the same);
   * UNKNOWN, asked by it alone. A call lost on the way is recorded (STARTED >
   * UNKNOWN) and answered PARTNER_UNAVAILABLE; a refusal ends it as a check
   * would (keepRefusal), so a start carried on with one whose form ran out
   * answers it FAILED, and the next start opens another. Gives the form to
   * send the admin to, or none.
   */
  const askAfterStart = async (
    partnerRail: FinancialRailAdapter,
    member: SupplierMember,
    supplierId: string,
    registration: RegistrationRecord,
    correlationId: string,
  ): Promise<PayeeForm | null | Refused> => {
    if (!isOpen(registration)) return null;
    const outcome = await askedAbout(partnerRail, member.orgId, registration, { route: 'hosted' });
    if (outcome !== 'unavailable' && outcome.kind !== 'refused') return formOf(outcome, partnerRail, correlationId);
    // The supplier's row lock serialises this with a check, as with a start.
    await work.inOrganisation(member.orgId, correlationId, async (tx, states) => {
      await work.supplierIn(tx, states, { orgId: member.orgId, id: supplierId }, 'share');
      const found = await registrationIn(tx, states, member.orgId, supplierId, registration.id, 'change');
      if (outcome !== 'unavailable') {
        if (isOpen(found.registration)) await keepRefusal(tx, states, member, found, outcome);
        return;
      }
      await lostIfStarted(tx, states, member, found);
    });
    return outcome === 'unavailable' ? PARTNER_UNAVAILABLE : null;
  };

  /**
   * The partner asked about a registration a start added or carried on with:
   * STARTED, registered under our ID (the same ID answers the same); UNKNOWN,
   * asked by it alone, never registered blindly again (ADR-014 §3).
   */
  const askedAbout = (
    partnerRail: FinancialRailAdapter,
    orgId: string,
    registration: RegistrationRecord,
    by: { readonly route: 'hosted' } | { readonly route: 'pass_through'; readonly payee: PayeeDetails },
  ) => {
    const ref = { organizationId: orgId, registrationId: registration.id };
    return asked(() =>
      registration.status === 'STARTED'
        ? partnerRail.registerBeneficiary({ ...by, ...ref })
        : partnerRail.getBeneficiaryState(ref),
    );
  };

  /** A call lost on the way recorded (STARTED > UNKNOWN); one lost twice, or answered by a check meanwhile, stands. */
  const lostIfStarted = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SupplierMember,
    found: RegistrationFound,
  ) => {
    if (found.registration.status !== 'STARTED') return;
    await recordLost(
      tx,
      states,
      { orgId: member.orgId, id: found.registration.id },
      {
        actor: { type: 'user', id: member.userId },
      },
    );
  };

  /**
   * The partner's refusal of an open registration, read for change: FAILED
   * with why, but an `unknown` for one STARTED, which the partner may not
   * have been asked about yet (a start carries it on).
   */
  const keepRefusal = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SupplierMember,
    found: RegistrationFound,
    outcome: Extract<BeneficiaryOutcome, { kind: 'refused' }>,
  ): Promise<void> => {
    if (outcome.reason === 'unknown' && found.registration.status === 'STARTED') return;
    await recordFailed(tx, states, { orgId: member.orgId, id: found.registration.id }, found, {
      reason: outcome.reason,
      actor: { type: 'user', id: member.userId },
    });
  };

  /**
   * Keeps the partner's answer for an open registration (Tx 2), in the
   * write's transaction: refused, as keepRefusal has it; registered, its
   * payee kept (keepRegistered), or, for an answer the partner's contract
   * forbids (an account number, or a stable identity that can't be kept),
   * FAILED and logged by IDs alone.
   */
  const keepAnswer = async (
    tx: SupplierTx,
    states: SignedStates,
    member: SupplierMember,
    {
      supplier,
      found,
      outcome,
      offer,
      enteredBy,
      correlationId,
      fingerprint = null,
    }: {
      readonly supplier: SupplierRecord;
      readonly found: RegistrationFound;
      readonly outcome: Exclude<BeneficiaryOutcome, { kind: 'waiting' }>;
      readonly offer: RailCapabilities | undefined;
      readonly enteredBy: string;
      readonly correlationId: string;
      /** Our fingerprint of the IBAN a pass-through holds in memory (E2-2d), else null. */
      readonly fingerprint?: PayeeKey | null;
    },
  ): Promise<void> => {
    const key = { orgId: member.orgId, id: found.registration.id };
    const actor = { type: 'user' as const, id: member.userId };
    if (outcome.kind === 'refused') {
      await keepRefusal(tx, states, member, found, outcome);
      return;
    }
    if (supplier.pendingVersionId !== null) throw new SupplierRefused(409, 'SUPPLIER_CHANGE_WAITING');
    if (offer === undefined) throw new Error('a registered payee was answered without the partner’s offer');
    if (payeeKeySource(offer, found.registration.route) === 'fingerprint' && fingerprint === null) {
      // Our fingerprint is taken only in the request that passed the IBAN through, which a check never has: left
      // open for that request, sent again with its key, to keep (the review of E2-2d: never ended here, so a payee
      // the partner holds is never lost).
      logger.child({ correlationId }).warn('suppliers.fingerprint_unavailable', { registrationId: key.id });
      return;
    }
    try {
      await keepRegistered(tx, states, member, {
        supplierId: supplier.id,
        found,
        beneficiary: outcome.beneficiary,
        offer,
        enteredBy,
        fingerprint,
      });
    } catch (error) {
      // Thrown before anything is written (payeeKeyOf, recordRegistered), so the registration's state still holds.
      if (!(error instanceof AccountNumberLeak || error instanceof UnusablePayeeIdentity)) throw error;
      logger.child({ correlationId }).error('suppliers.partner_answer_refused', { registrationId: key.id });
      await recordFailed(tx, states, key, found, { reason: 'unknown', actor });
    }
  };

  /** The partner's offer, if it takes payees by `route`: PAYEE_ROUTE_NOT_OFFERED otherwise, PARTNER_UNAVAILABLE without an answer. */
  const offering = async (partnerRail: FinancialRailAdapter, route: RegistrationRoute) => {
    const offer = await asked(() => partnerRail.capabilities());
    if (offer === 'unavailable') return PARTNER_UNAVAILABLE;
    try {
      payeeKeySource(offer, route);
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      return ROUTE_NOT_OFFERED;
    }
    return offer;
  };

  /**
   * Tx 1, for either route: the registration the write added, or the hosted
   * one it carried on with (never a pass-through's: see the top of this
   * file), read again in a transaction of its own.
   */
  const opened = async (
    member: SupplierMember,
    idempotent: IdempotentRequest,
    supplierId: string,
    route: RegistrationRoute,
    correlationId: string,
  ): Promise<RegistrationRecord | PayeeRefusal> => {
    const done = await write(member, idempotent, correlationId, async (tx, states) => {
      const { orgId } = member;
      await onePayeeChangeAtATime(tx, orgId);
      const admin = await work.memberIn(tx, states, member, REGISTERING_ROLES);
      const { supplier } = await work.supplierIn(tx, states, { orgId, id: supplierId }, 'share');
      if (supplier.pendingVersionId !== null) throw new SupplierRefused(409, 'SUPPLIER_CHANGE_WAITING');
      // One open at a time for a supplier's form: a start carries on with it, starting nothing new.
      const open =
        route === 'hosted' ? await openRegistrationOf(tx, orgId, { supplierId: supplier.id, partner, route }) : null;
      if (open !== null && isOpen((await registrationIn(tx, states, orgId, supplier.id, open, 'share')).registration)) {
        return { status: 201, resourceId: open };
      }
      await withinBudget(tx, orgId);
      const id = ids.next();
      await startRegistration(tx, states, {
        orgId,
        id,
        supplierId: supplier.id,
        versionId: ids.next(),
        partner,
        route,
        startedBy: admin.id,
        createdAt: clock.now(),
        actor: { type: 'user', id: member.userId },
      });
      return { status: 201, resourceId: id };
    });
    if (isUnwritten(done)) return done;
    // Only a check can find a registration still waiting inside its write.
    if (done.outcome === 'waiting') throw new Error('a payee start answered as still waiting');
    return registrationNow(member.orgId, supplierId, done.result.resourceId, correlationId);
  };

  /**
   * Passes the payee's details to the partner for a pass-through Tx 1 added
   * (STARTED), or asks it by our ID alone (UNKNOWN), then keeps its answer at
   * once, as a check would (Tx 2), with our fingerprint of the IBAN where
   * that is the partner's one source. A call lost on the way is recorded
   * (STARTED > UNKNOWN) and answered PARTNER_UNAVAILABLE. One ended already
   * is left as it stands.
   */
  const passedThrough = async (
    partnerRail: FinancialRailAdapter,
    offer: RailCapabilities,
    member: SupplierMember,
    registration: RegistrationRecord,
    payee: PayeeDetails,
    correlationId: string,
  ): Promise<Refused | null> => {
    if (!isOpen(registration)) return null;
    const { orgId } = member;
    const outcome = await askedAbout(partnerRail, orgId, registration, { route: 'pass_through', payee });
    const fingerprint =
      payeeKeySource(offer, 'pass_through') === 'fingerprint' ? payeeFingerprint(keys, orgId, payee.iban) : null;
    // A refusal here (another change staged first: SUPPLIER_CHANGE_WAITING, the registration left open for the
    // same request sent again) is answered, as a check's would be. The admin's role isn't read again: Tx 1 read it
    // moments ago, and the change stays inert until an admin's passkey confirms it (E2-2b; the mutation pass).
    const kept = await work.answered(orgId, correlationId, async (tx, states) => {
      const { supplier } = await work.supplierIn(tx, states, { orgId, id: registration.supplierId }, 'change');
      const found = await registrationIn(tx, states, orgId, supplier.id, registration.id, 'change');
      // `{}`: nothing to answer. Ended meanwhile, by a check of it: as it stands.
      if (!isOpen(found.registration)) return {};
      if (outcome === 'unavailable') {
        await lostIfStarted(tx, states, member, found);
        return {};
      }
      if (outcome.kind === 'waiting') throw new Error('A pass-through registration is never left waiting');
      await keepAnswer(tx, states, member, {
        supplier,
        found,
        outcome,
        offer,
        enteredBy: registration.startedBy,
        correlationId,
        fingerprint,
      });
      return {};
    });
    if ('outcome' in kept) return kept;
    return outcome === 'unavailable' ? PARTNER_UNAVAILABLE : null;
  };

  return {
    async start(member, idempotent, supplierId, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      const offer = await offering(rail, 'hosted');
      if ('outcome' in offer) return offer;
      const registration = await opened(member, idempotent, supplierId, 'hosted', correlationId);
      if ('outcome' in registration) return registration;
      const form = await askAfterStart(rail, member, supplierId, registration, correlationId);
      if (form !== null && 'outcome' in form) return form;
      return answer('started', member, supplierId, registration.id, form, correlationId);
    },

    async passThrough(member, idempotent, supplierId, payee, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      const offer = await offering(rail, 'pass_through');
      if ('outcome' in offer) return offer;
      const registration = await opened(member, idempotent, supplierId, 'pass_through', correlationId);
      if ('outcome' in registration) return registration;
      const refused = await passedThrough(rail, offer, member, registration, payee, correlationId);
      if (refused !== null) return refused;
      return answer('started', member, supplierId, registration.id, null, correlationId);
    },

    async check(member, idempotent, supplierId, registrationId, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      // Only a registration the organisation started for this supplier is asked about, never an ID from anywhere else.
      const known = await registrationNow(member.orgId, supplierId, registrationId, correlationId);
      if ('outcome' in known) return known;
      if (known.partner !== partner) {
        // Started with another partner than this process talks to: never asked of this one.
        logger.child({ correlationId }).error('suppliers.registration_partner_differs', { registrationId });
        return PARTNER_UNAVAILABLE;
      }
      const ref = { organizationId: member.orgId, registrationId: known.id };
      const outcome = isOpen(known) ? await asked(() => rail.getBeneficiaryState(ref)) : undefined;
      const offer =
        outcome !== undefined && outcome !== 'unavailable' && outcome.kind === 'registered'
          ? await asked(() => rail.capabilities())
          : undefined;
      if (outcome === 'unavailable' || offer === 'unavailable') return PARTNER_UNAVAILABLE;
      const form = outcome === undefined ? null : formOf(outcome, rail, correlationId);
      if (form !== null && 'outcome' in form) return form;
      // No payee-change lock: the supplier's row, read for change, serialises every check and start of it.
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, REGISTERING_ROLES);
        const { supplier } = await work.supplierIn(tx, states, { orgId: member.orgId, id: supplierId }, 'change');
        const found = await registrationIn(tx, states, member.orgId, supplier.id, known.id, 'change');
        const resourceId = found.registration.id;
        // Ended already, by this write's retry or another check (the lock waits for one at once): as it stands.
        if (!isOpen(found.registration) || outcome === undefined) return { status: 200, resourceId };
        if (outcome.kind === 'waiting') throw new StillWaiting();
        // Whoever started it entered the details at the partner's form, whoever checks (E3-2a's review: the two-person rule).
        await keepAnswer(tx, states, member, {
          supplier,
          found,
          outcome,
          offer,
          enteredBy: found.registration.startedBy,
          correlationId,
        });
        return { status: 200, resourceId };
      });
      if (isUnwritten(done)) return done;
      return answer(
        done.outcome === 'waiting' ? 'waiting' : 'checked',
        member,
        supplierId,
        known.id,
        form,
        correlationId,
      );
    },
  };
}
