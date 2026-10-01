// Registering a supplier's payee with the payment partner (ADR-014 §3,
// PRD §6, BR-04, SEC-PAY-06, SEC-PAY-08; Phase 1 E2-2a), through the
// partner's hosted form, so the bank details never touch Agent X. Composed
// here, in the API, as ADR-004 §7 has it: the partner is the providers
// module's adapter, the supplier and its registrations the suppliers
// module's, the member identity's.
//
// 1. `start` (`suppliers.payee.start`), an admin: the partner's offer read
//    first (a partner with no hosted form, or one whose payee key must come
//    from pass-through, PAYEE_ROUTE_NOT_OFFERED). Tx 1: the key claimed; the
//    organisation's lock for payee changes; the admin read again; the day's
//    budget (PAYEE_REGISTRATIONS_SPENT: never retired, the B8-1 lesson); the
//    supplier, with no change already waiting (SUPPLIER_CHANGE_WAITING); then
//    the registration, STARTED, naming the version Tx 2 will make, with no
//    bank data. Then the partner, outside any transaction, with our ID as its
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
//    the lock; the admin read again; the supplier and the registration read
//    for change; then: still waiting at the form, left as it is (202) and the
//    key's claim rolled back, so asking again with the same key asks the
//    partner again; refused, recorded FAILED with why; registered, the
//    partner's reference recorded with the payee key from the partner's one
//    source (refused while another supplier holds it, SUPPLIER_PAYEE_TAKEN),
//    a verified supplier taken back to UNVERIFIED (a supplier is verified only
//    on the version verified, 0032), the new version made with the current
//    details and the registration's reference, numbered past any withdrawn
//    one, and put in waiting: inert, the supplier still paying the version it
//    paid, until the admin's step-up confirms it (E2-2b). A registration
//    already ended answers as it stands.
//
// Lock order (ADR-006 §6): the idempotency key, the payee-change lock, the
// member's membership (2a), the supplier (6), its registration, its
// versions, the chain head last.
import type { SignedStates } from '@agentx/core/modules/audit';
import {
  type BeneficiaryOutcome,
  type FinancialRailAdapter,
  isPartnerPage,
  type RailCapabilities,
} from '@agentx/core/modules/providers';
import {
  addVersion,
  contactsOf,
  MOST_PAYEE_REGISTRATIONS_A_DAY,
  nextVersionNumber,
  onePayeeChangeAtATime,
  payeeKeyOf,
  payeeKeySource,
  recordFailed,
  recordLost,
  recordRegistered,
  registrationOf,
  type RegistrationRecord,
  registrationsStartedSince,
  stagePayeeChange,
  startRegistration,
  supplierWithPayeeKey,
  unverifySupplier,
  versionOf,
} from '@agentx/core/modules/suppliers';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, IdempotentRequest } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { asked, PARTNER_UNAVAILABLE, StillWaiting } from './funding-source-work.ts';
import {
  createSupplierWork,
  type Refused,
  type SupplierMember,
  SupplierRefused,
  type SupplierTables,
  type SupplierTx,
} from './supplier-work.ts';

/** Starting a payee registration through the partner's form. */
export const PAYEE_START_OPERATION = 'suppliers.payee.start';
/** Asking the partner how it stands, and keeping its answer. */
export const PAYEE_CHECK_OPERATION = 'suppliers.payee.check';

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
  | ({ readonly outcome: 'started' | 'checked' | 'waiting' } & PayeeRegistrationView)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

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
}

const DAY_MS = 86_400_000;

/** A registration the partner may still answer: neither registered nor failed. */
const isOpen = (registration: RegistrationRecord): boolean =>
  registration.status === 'STARTED' || registration.status === 'UNKNOWN';

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
  ) => {
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

  /** The form the partner answered, if it may be sent to a person's browser: logged and refused otherwise. */
  const formOf = (
    outcome: BeneficiaryOutcome,
    { formOrigin }: FinancialRailAdapter,
    correlationId: string,
  ): PayeeForm | null | 'refused' => {
    if (outcome.kind !== 'waiting') return null;
    if (!isPartnerPage(outcome.formUrl, formOrigin)) {
      logger.child({ correlationId }).error('suppliers.partner_page_refused', { partner });
      return 'refused';
    }
    return { url: outcome.formUrl, expiresAt: outcome.expiresAt };
  };

  /** A payee change refused inside Tx 2, answered as such; still waiting, answered with nothing of it kept. */
  const write = async (
    member: SupplierMember,
    idempotent: IdempotentRequest,
    correlationId: string,
    change: (tx: SupplierTx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    try {
      return await work.write(member, idempotent, correlationId, change);
    } catch (error) {
      if (error instanceof StillWaiting) return { outcome: 'waiting' as const };
      throw error;
    }
  };

  /** Refused past the day's budget of payee registrations (PAYEE_REGISTRATIONS_SPENT). */
  const withinBudget = async (tx: SupplierTx, orgId: string): Promise<void> => {
    const since = new Date(clock.now().getTime() - DAY_MS);
    if ((await registrationsStartedSince(tx, orgId, since)) >= MOST_PAYEE_REGISTRATIONS_A_DAY) {
      throw new SupplierRefused(409, 'PAYEE_REGISTRATIONS_SPENT');
    }
  };

  /**
   * The registration's payee, from the partner's registered answer (Tx 2):
   * its reference and payee key recorded, then the new version made with the
   * current details and put in waiting. The registration was read for change
   * after its supplier, as the lock order has it.
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
    }: {
      readonly supplierId: string;
      readonly found: Extract<Awaited<ReturnType<typeof registrationOf>>, { outcome: 'found' }>;
      readonly beneficiary: Extract<BeneficiaryOutcome, { kind: 'registered' }>['beneficiary'];
      readonly offer: RailCapabilities;
      readonly enteredBy: string;
    },
  ): Promise<void> => {
    const { orgId } = member;
    const supplierKey = { orgId, id: supplierId };
    const actor = { type: 'user' as const, id: member.userId };
    // The hosted form takes no fingerprint: the key is the partner's identity, or none (R-13).
    const payee = payeeKeyOf(payeeKeySource(offer, found.registration.route), beneficiary, null);
    // The early word: the index refuses the key again at the confirmation, whoever takes it first.
    const holder = payee.key === null ? null : await supplierWithPayeeKey(tx, orgId, payee.key);
    if (holder !== null && holder !== supplierId) throw new SupplierRefused(409, 'SUPPLIER_PAYEE_TAKEN');
    const registration = await recordRegistered(tx, states, { orgId, id: found.registration.id }, found, {
      beneficiary,
      payee,
      actor,
    });
    // VERIFIED only on the version verified with nothing waiting (0032): a payee change is verified again (E3).
    let read = await work.supplierIn(tx, states, supplierKey, 'change');
    if (read.supplier.status === 'VERIFIED') {
      await unverifySupplier(tx, states, supplierKey, read, { actor });
      read = await work.supplierIn(tx, states, supplierKey, 'change');
    }
    const current = await versionOf(tx, states, { orgId, id: read.supplier.currentVersionId }, supplierId);
    if (current.outcome !== 'found') throw new SupplierRefused(503, 'INTEGRITY_FAILED');
    const { displayName, source } = current.version;
    await addVersion(tx, states, keys, {
      orgId,
      id: registration.versionId,
      supplierId,
      version: await nextVersionNumber(tx, orgId, supplierId),
      supplier: { displayName, contacts: await contactsOf(tx, keys, orgId, current.version), source },
      enteredBy,
      enteredAt: clock.now(),
      actor,
      of: read,
      follows: current.version,
      registration,
    });
    const made = await versionOf(tx, states, { orgId, id: registration.versionId }, supplierId);
    if (made.outcome !== 'found') throw new Error(`a version just made isn't there: ${registration.versionId}`);
    await stagePayeeChange(
      tx,
      states,
      supplierKey,
      read,
      { version: made.version, registration, current: current.version },
      { actor },
    );
  };

  /** The answer after a write: the registration as it now stands, with the partner's form if it gave one. */
  const answer = async (
    outcome: 'started' | 'checked' | 'waiting',
    member: SupplierMember,
    supplierId: string,
    registrationId: string,
    form: PayeeForm | null,
    correlationId: string,
  ): Promise<PayeeWrite> => {
    const registration = await registrationNow(member.orgId, supplierId, registrationId, correlationId);
    if ('outcome' in registration) return registration;
    return { outcome, registration, form: isOpen(registration) ? form : null };
  };

  /**
   * Asks the partner about a registration Tx 1 added: STARTED, registered
   * under our ID (the same ID answers the same); UNKNOWN, asked by it alone.
   * A call lost on the way is recorded (STARTED > UNKNOWN) and answered
   * PARTNER_UNAVAILABLE. Gives the form to send the admin to, or none.
   */
  const askAfterStart = async (
    partnerRail: FinancialRailAdapter,
    member: SupplierMember,
    supplierId: string,
    registration: RegistrationRecord,
    correlationId: string,
  ): Promise<PayeeForm | null | Refused> => {
    if (!isOpen(registration)) return null;
    const ref = { organizationId: member.orgId, registrationId: registration.id };
    const outcome = await asked(() =>
      registration.status === 'STARTED'
        ? partnerRail.registerBeneficiary({ route: 'hosted', ...ref })
        : partnerRail.getBeneficiaryState(ref),
    );
    if (outcome !== 'unavailable') {
      const form = formOf(outcome, partnerRail, correlationId);
      return form === 'refused' ? PARTNER_UNAVAILABLE : form;
    }
    await work.inOrganisation(member.orgId, correlationId, async (tx, states) => {
      await onePayeeChangeAtATime(tx, member.orgId);
      await work.supplierIn(tx, states, { orgId: member.orgId, id: supplierId }, 'share');
      const found = await registrationIn(tx, states, member.orgId, supplierId, registration.id, 'change');
      // Lost twice, or answered by a check meanwhile: as it stands.
      if (found.registration.status === 'STARTED') {
        await recordLost(
          tx,
          states,
          { orgId: member.orgId, id: registration.id },
          {
            actor: { type: 'user', id: member.userId },
          },
        );
      }
    });
    return PARTNER_UNAVAILABLE;
  };

  return {
    async start(member, idempotent, supplierId, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      const offer = await asked(() => rail.capabilities());
      if (offer === 'unavailable') return PARTNER_UNAVAILABLE;
      try {
        payeeKeySource(offer, 'hosted');
      } catch (error) {
        if (!(error instanceof RangeError)) throw error;
        return { outcome: 'refused', status: 409, code: 'PAYEE_ROUTE_NOT_OFFERED' };
      }
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        await onePayeeChangeAtATime(tx, member.orgId);
        const admin = await work.memberIn(tx, states, member, REGISTERING_ROLES);
        await withinBudget(tx, member.orgId);
        const { supplier } = await work.supplierIn(tx, states, { orgId: member.orgId, id: supplierId }, 'share');
        if (supplier.pendingVersionId !== null) throw new SupplierRefused(409, 'SUPPLIER_CHANGE_WAITING');
        const id = ids.next();
        await startRegistration(tx, states, {
          orgId: member.orgId,
          id,
          supplierId: supplier.id,
          versionId: ids.next(),
          partner,
          route: 'hosted',
          startedBy: admin.id,
          createdAt: clock.now(),
          actor: { type: 'user', id: member.userId },
        });
        return { status: 201, resourceId: id };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      // Only a check can find a registration still waiting inside its write.
      if (done.outcome === 'waiting') throw new Error('a payee start answered as still waiting');
      const registrationId = done.result.resourceId;
      const registration = await registrationNow(member.orgId, supplierId, registrationId, correlationId);
      if ('outcome' in registration) return registration;
      const form = await askAfterStart(rail, member, supplierId, registration, correlationId);
      if (form !== null && 'outcome' in form) return form;
      return answer('started', member, supplierId, registrationId, form, correlationId);
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
      if (form === 'refused') return PARTNER_UNAVAILABLE;
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        await onePayeeChangeAtATime(tx, member.orgId);
        const admin = await work.memberIn(tx, states, member, REGISTERING_ROLES);
        const { supplier } = await work.supplierIn(tx, states, { orgId: member.orgId, id: supplierId }, 'change');
        const found = await registrationIn(tx, states, member.orgId, supplier.id, known.id, 'change');
        const resourceId = found.registration.id;
        // Ended already, by this write's retry or another check (the lock waits for one at once): as it stands.
        if (!isOpen(found.registration) || outcome === undefined) return { status: 200, resourceId };
        if (outcome.kind === 'waiting') throw new StillWaiting();
        const key = { orgId: member.orgId, id: resourceId };
        const actor = { type: 'user' as const, id: member.userId };
        if (outcome.kind === 'refused') {
          await recordFailed(tx, states, key, found, { reason: outcome.reason, actor });
          return { status: 200, resourceId };
        }
        if (supplier.pendingVersionId !== null) throw new SupplierRefused(409, 'SUPPLIER_CHANGE_WAITING');
        if (offer === undefined) throw new Error('a registered payee was answered without the partner’s offer');
        await keepRegistered(tx, states, member, {
          supplierId: supplier.id,
          found,
          beneficiary: outcome.beneficiary,
          offer,
          enteredBy: admin.id,
        });
        return { status: 200, resourceId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
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
