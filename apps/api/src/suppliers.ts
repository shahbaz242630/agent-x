// The organisation's suppliers (PRD §7.1, ADR-012 §1, BR-04, BR-21,
// SEC-AG-05; Phase 1 E1-2).
//
// - `POST /v1/suppliers`: adds a supplier, UNVERIFIED, with its name, its
//   phone (an email and a trade licence number if known) and the independent
//   source its details were checked against: 201 with the supplier. Admins;
//   100 a day (409 SUPPLIER_ADDS_SPENT).
// - `GET /v1/suppliers?after=&limit=` and `/v1/suppliers/:id`: the suppliers
//   as Agent X holds them, each verified against its signed state; one with
//   its contacts. Every member.
// - `POST /v1/suppliers/:id/suspend`: the brake, at once and with no step-up:
//   200 with the supplier, SUSPENDED; one suspended already is answered as it
//   is. Admins and finance approvers.
// - `POST /v1/suppliers/:id/reactivate`, then `…/reactivate/confirm` with the
//   step-up's ID once signed in again (a passkey): 202 with the step-up, then
//   200 with the supplier, VERIFIED again only if nothing changed while it
//   was suspended. 409 SUPPLIER_NOT_SUSPENDED otherwise. Admins.
// - `POST /v1/suppliers/:id/payee-registrations`: starts registering the
//   supplier's bank details with the payment partner, through the partner's
//   own form: 201 with the registration and the form to send the admin to.
//   Admins; 100 a day (409 PAYEE_REGISTRATIONS_SPENT); 409
//   SUPPLIER_CHANGE_WAITING while another change waits; 409
//   PAYEE_ROUTE_NOT_OFFERED where the partner has no form for it.
// - `POST /v1/suppliers/:id/payee-registrations/:registrationId/check`,
//   once the form is filled in: the partner asked how it stands, server to
//   server: 202 with the form while it waits, otherwise 200 with the
//   registration, FAILED with why, or REGISTERED, the new details then
//   waiting for the admin's confirmation (409 SUPPLIER_PAYEE_TAKEN while
//   another supplier is paid to that account). Admins. 503
//   PARTNER_UNAVAILABLE when the partner doesn't answer.
// - `POST /v1/suppliers/:id/payee-registrations/pass-through`, with the
//   account holder's name and the IBAN (E2-2d): the details passed to the
//   payment partner within this request alone, never kept or logged: 201
//   with the registration, REGISTERED (the new details then waiting for the
//   admin's confirmation) or FAILED with why. Admins; the same budget and
//   refusals as the form's, and 503 PARTNER_UNAVAILABLE when the partner's
//   answer is lost: the same request sent again with the same key asks it.
// - `POST /v1/suppliers/:id/payee-change/approve`, then `…/approve/confirm`
//   with the step-up's ID once signed in again (a passkey): 202 with the
//   step-up, then 200 with the supplier paying the new details, its 24 hours
//   of cooling-off begun, and every member and counting contact told. The
//   admin who registered them alone (403 PAYEE_CHANGE_NOT_YOURS); 409
//   SUPPLIER_NO_CHANGE_WAITING with none waiting; 409 SUPPLIER_PAYEE_TAKEN
//   when another supplier was paid to that account first.
// - `POST /v1/suppliers/:id/payee-change/withdraw`: the change waiting
//   dropped, at once and with no step-up: 200 with the supplier, its payee
//   as it was. Admins and finance approvers.
// A supplier's details show its payee, and the change waiting, as the
// partner described them (the masked hint, the name check, the masked
// name): what the call-back confirms, never an account number.
// - `GET /v1/agent/suppliers?after=&limit=` (SEC-AG-05): for an agent's key
//   with `suppliers:read`, the VERIFIED suppliers, each by ID and name alone:
//   never a contact, a source or a payment detail.
// Refusals: 404 NOT_FOUND for a supplier not the organisation's; 503
// INTEGRITY_FAILED when the caller's membership, a supplier or its version
// can't be verified. The use cases are supplier-registry.ts,
// supplier-changes.ts and supplier-payees.ts.
import type { PayeeDetails } from '@agentx/core/modules/providers';
import { visibleName } from '@agentx/core/shared-kernel';
import {
  CALL_NOTE_MOST,
  callNote,
  MOST_SUPPLIERS_A_PAGE,
  NAME_CHECKS,
  normalisedIban,
  REGISTRATION_FAILURES,
  REGISTRATION_ROUTES,
  SOURCE_KINDS,
  type SupplierDetails,
  SUPPLIER_NAME_MOST,
  SupplierDetailsRefused,
  supplierDetails,
  type SupplierRecord,
} from '@agentx/core/modules/suppliers';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { agentOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';
import {
  CHALLENGE_BODY_LIMIT,
  NEXT,
  NOTHING,
  NOTHING_BODY_LIMIT,
  pageQuery,
  STEP_UP_SIGNED_IN,
  STEP_UP_TO_SIGN_IN,
} from './route-schemas.ts';
import {
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  REACTIVATING_ROLES,
  type SupplierChanges,
  SUSPEND_OPERATION,
  SUSPENDING_ROLES,
} from './supplier-changes.ts';
import {
  PAYEE_CHECK_OPERATION,
  PAYEE_PASS_THROUGH_OPERATION,
  PAYEE_START_OPERATION,
  type PayeeRegistrationView,
  type PayeeWrite,
  REGISTERING_ROLES,
  type SupplierPayees,
} from './supplier-payees.ts';
import { ADD_OPERATION, ADDING_ROLES, type SupplierRegistry } from './supplier-registry.ts';
import {
  PAYEE_APPROVE_CONFIRM_OPERATION,
  PAYEE_APPROVE_OPERATION,
  PAYEE_WITHDRAW_OPERATION,
  type SupplierPayeeChanges,
  WITHDRAWING_ROLES,
} from './supplier-payee-changes.ts';
import { DETAILS_CONFIRM_OPERATION, DETAILS_OPERATION, type SupplierDetailsChanges } from './supplier-details.ts';
import {
  type SupplierVerifications,
  VERIFY_CONFIRM_OPERATION,
  VERIFY_OPERATION,
  VERIFYING_ROLES,
} from './supplier-verifications.ts';
import type { PayeeShown, SupplierChangeWrite, SupplierView } from './supplier-work.ts';

/** Every member may see the organisation's suppliers. */
const READING_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;

/**
 * The most an add's body may be: a name, kept as at most 100 code points
 * once composed (NFC, visibleName) and sent decomposed as at most 4 each
 * (Unicode's longest canonical decomposition), astral at worst: 800 UTF-16
 * units, each sent as a `\uXXXX` escape (6 bytes); a phone of 16, an email of
 * 254, a trade licence of 50 and a source's reference of 200, each ASCII
 * character escaped too; with room to spare (the review of #221: a name sent
 * decomposed is longer than it is kept). Fastify refuses a body past it
 * before the schema is read (the B8-3 lesson), so it must fit every body the
 * schema allows.
 */
const ADD_BODY_LIMIT = 12_288;
/**
 * The most a verification's body may be: a call-back note of at most 500
 * code points once composed, sent decomposed as at most 4 each, astral at
 * worst, each UTF-16 unit as a `\uXXXX` escape (500 × 4 × 2 × 6 bytes), with
 * the tick, a challenge's ID and room to spare (the B8-3 lesson: it must fit
 * every body the schema allows).
 */
const VERIFY_BODY_LIMIT = 24_576;

const STATUS = z
  .enum(['UNVERIFIED', 'VERIFIED', 'SUSPENDED'])
  .describe(
    'UNVERIFIED until a second person verifies it; only a VERIFIED supplier can be paid. SUSPENDED by the business.',
  );

const SUPPLIER = z
  .object({
    id: z.uuid().describe('The supplier, by its ID.'),
    status: STATUS,
    displayName: z.string().describe('Its name, as its current details give it.'),
    changeWaiting: z.boolean().describe('Whether a change of its details is waiting to be confirmed.'),
    coolingOffUntil: z.iso.datetime().nullable().describe('When its cooling-off ends, or null.'),
    verifiedBy: z.uuid().nullable().describe('The membership of the member who verified it, or null.'),
  })
  .register(API_SCHEMAS, { id: 'Supplier', description: 'A supplier of the organisation, as Agent X holds it.' });

const PAYEE = z
  .object({
    registrationId: z.uuid().describe('The registration with the payment partner that gave it.'),
    payeeHint: z
      .string()
      .nullable()
      .describe('The country and last four characters of the account, as the partner gives them: never the number.'),
    nameCheck: z
      .enum(NAME_CHECKS)
      .nullable()
      .describe('The partner’s check of the supplier’s name against the account’s holder, or null.'),
    maskedName: z.string().nullable().describe('The account holder’s name as the bank masks it, or null.'),
  })
  .register(API_SCHEMAS, {
    id: 'SupplierPayee',
    description: 'A supplier’s bank account as the payment partner described it: what the call-back confirms.',
  });

const SUPPLIER_DETAILS = SUPPLIER.extend({
  version: z.int().describe('Its current details’ version, from 1.'),
  phone: z.string().describe('Its phone, in international form: the call-back contact.'),
  phoneSince: z.iso.datetime().describe('Since when that phone has been its own.'),
  email: z.string().nullable().describe('Its email, or null.'),
  tradeLicence: z.string().nullable().describe('Its trade licence number, or null.'),
  source: z
    .object({
      kind: z.enum(SOURCE_KINDS).describe('Where its details were checked: a registry or its official website.'),
      ref: z.string().describe('The registry number, or the website’s address.'),
    })
    .describe('The independent source its details were checked against.'),
  enteredBy: z.uuid().describe('The membership of the member who entered its current details.'),
  enteredAt: z.iso.datetime().describe('When they were entered.'),
  payee: PAYEE.nullable().describe('The bank account it is paid to, or null before one is registered.'),
  pendingChange: z
    .object({
      version: z.int().describe('The details’ version waiting.'),
      enteredAt: z.iso.datetime().describe('When it was made.'),
      payee: PAYEE.nullable().describe('The bank account it would be paid to.'),
    })
    .nullable()
    .describe(
      'A change of its bank details waiting for the admin who registered them to confirm it, or null. Nothing is paid to it.',
    ),
}).register(API_SCHEMAS, {
  id: 'SupplierDetails',
  description: 'A supplier with its current details: never a payment detail.',
});

/** A supplier's details as a body sends them: what adding one (E1-2) and changing its details (E3-2b) take. */
const DETAIL_FIELDS = {
  displayName: z.string().describe('Its name: 1 to 100 visible characters, with a letter or digit.'),
  phone: z.string().describe('Its phone, in international form, such as +971501234567.'),
  email: z.string().nullish().describe('Its email, if known.'),
  tradeLicence: z.string().nullish().describe('Its trade licence number, if known: letters, digits, - and /.'),
  source: z
    .strictObject({
      kind: z.enum(SOURCE_KINDS).describe('Where you checked its details: a registry or its official website.'),
      ref: z.string().describe('The registry number, or the website’s address: printable ASCII, at most 200.'),
    })
    .describe('The independent source you checked its details against.'),
};

type DetailFields = z.infer<z.ZodObject<typeof DETAIL_FIELDS>>;

/** The details as a version keeps them, or the problems that keep them from being one. */
const detailsKept = (body: DetailFields, context: z.RefinementCtx): SupplierDetails => {
  const details = {
    displayName: body.displayName,
    contacts: { phone: body.phone, email: body.email ?? null, tradeLicence: body.tradeLicence ?? null },
    source: body.source,
  };
  try {
    return supplierDetails(details);
  } catch (error) {
    if (!(error instanceof SupplierDetailsRefused)) throw error;
    for (const problem of error.problems) context.addIssue({ code: 'custom', message: problem });
    return z.NEVER;
  }
};

const DETAILS_BODY = z.strictObject(DETAIL_FIELDS).transform(detailsKept);

/** A step-up asked: the 202's body, under its own name in the document. */
const stepUpAsked = (id: string, description: string) =>
  z
    .object({
      stepUpChallengeId: STEP_UP_TO_SIGN_IN,
    })
    .register(API_SCHEMAS, { id, description });

const ADD_SCHEMA = {
  summary: 'Add a supplier, unverified',
  body: DETAILS_BODY.describe('The supplier to add, UNVERIFIED.'),
  response: { 201: SUPPLIER_DETAILS.describe('The supplier, added UNVERIFIED.') },
};

const PAGE = pageQuery(MOST_SUPPLIERS_A_PAGE);

const LIST_SCHEMA = {
  summary: "Your organisation's suppliers",
  querystring: PAGE,
  response: {
    200: z
      .object({ suppliers: z.array(SUPPLIER).describe('The suppliers, in order of ID.'), next: NEXT })
      .describe('A page of suppliers, each as its signed state says.'),
  },
};

const SUPPLIER_ID = z.object({ id: z.uuid().describe('The supplier, by its ID.') });

const SHOW_SCHEMA = {
  summary: 'One of your organisation’s suppliers, with its details',
  params: SUPPLIER_ID,
  response: { 200: SUPPLIER_DETAILS },
};

const SUPPLIER_CHANGED = SUPPLIER_DETAILS.describe('The supplier, as the change left it.');

const DETAILS_SCHEMA = {
  summary: 'Ask to change a supplier’s details: its name, contacts or source, never its bank details',
  params: SUPPLIER_ID,
  body: DETAILS_BODY.describe('Its new details, every field: the supplier is UNVERIFIED once they are confirmed.'),
  response: {
    202: stepUpAsked(
      'SupplierDetailsChangeAsked',
      'Changing a supplier’s details, waiting for the admin to sign in again.',
    ),
  },
};

const DETAILS_CONFIRM_SCHEMA = {
  summary: 'Change a supplier’s details, once signed in again for it',
  params: SUPPLIER_ID,
  body: z
    .strictObject({
      ...DETAIL_FIELDS,
      stepUpChallengeId: STEP_UP_SIGNED_IN,
    })
    .transform((body, context) => ({ stepUpChallengeId: body.stepUpChallengeId, details: detailsKept(body, context) }))
    .describe('The step-up signed in again for, with the same details as the ask.'),
  response: {
    200: SUPPLIER_CHANGED.describe(
      'The supplier with its new details: UNVERIFIED until a second person verifies it again, and everyone told.',
    ),
  },
};

const SUSPEND_SCHEMA = {
  summary: 'Suspend a supplier: the brake, at once and with no step-up',
  params: SUPPLIER_ID,
  body: NOTHING,
  response: { 200: SUPPLIER_CHANGED },
};

const REACTIVATE_SCHEMA = {
  summary: 'Ask to reactivate a suspended supplier',
  params: SUPPLIER_ID,
  body: NOTHING,
  response: {
    202: stepUpAsked('SupplierReactivationAsked', 'Reactivating a supplier, waiting for the admin to sign in again.'),
  },
};

const REACTIVATE_CONFIRM_SCHEMA = {
  summary: 'Reactivate the supplier, once signed in again for it',
  params: SUPPLIER_ID,
  body: z.strictObject({ stepUpChallengeId: STEP_UP_SIGNED_IN }).describe('The step-up signed in again for.'),
  response: { 200: SUPPLIER_CHANGED },
};

const PAYEE_APPROVE_SCHEMA = {
  summary: 'Ask to confirm a supplier’s new bank details, waiting since you registered them',
  params: SUPPLIER_ID,
  body: NOTHING,
  response: {
    202: stepUpAsked(
      'SupplierPayeeApprovalAsked',
      'Confirming a supplier’s new bank details, waiting for the admin to sign in again.',
    ),
  },
};

const PAYEE_APPROVE_CONFIRM_SCHEMA = {
  summary: 'Confirm a supplier’s new bank details, once signed in again for it',
  params: SUPPLIER_ID,
  body: z.strictObject({ stepUpChallengeId: STEP_UP_SIGNED_IN }).describe('The step-up signed in again for.'),
  response: {
    200: SUPPLIER_CHANGED.describe(
      'The supplier, paying the new details once verified: unverified, its cooling-off begun, and everyone told.',
    ),
  },
};

/** The verifier's call-back (partner, S74): the tick, always; the note when the name check isn't a match. */
const CALL_BACK = {
  calledBack: z
    .literal(true)
    .describe('Ticked: you called the supplier on the number on file, and they confirmed these details.'),
  note: z
    .string()
    // UTF-16 units: each of its 500 characters sent as up to 4 code points, each astral (VERIFY_BODY_LIMIT).
    .max(CALL_NOTE_MOST * 8)
    .transform((note, context) => {
      const { note: kept, problems } = callNote(note);
      for (const problem of problems) context.addIssue({ code: 'custom', message: problem });
      return problems.length > 0 ? z.NEVER : kept;
    })
    .optional()
    .describe(
      'Your note of the call: who you spoke to and what they confirmed, at most 500 characters on one line, with no phone or account numbers (it is kept for good). Needed when the bank’s name check was not a full match.',
    ),
};

const VERIFY_SCHEMA = {
  summary: 'Ask to verify a supplier, once you have called it back',
  params: SUPPLIER_ID,
  body: z.strictObject(CALL_BACK).describe('The call-back you made.'),
  response: {
    202: stepUpAsked('SupplierVerificationAsked', 'Verifying a supplier, waiting for the verifier to sign in again.'),
  },
};

const VERIFY_CONFIRM_SCHEMA = {
  summary: 'Verify a supplier, once signed in again for it',
  params: SUPPLIER_ID,
  body: z
    .strictObject({
      stepUpChallengeId: STEP_UP_SIGNED_IN,
      ...CALL_BACK,
    })
    .describe('The step-up signed in again for, with the same call-back as the ask.'),
  response: {
    200: SUPPLIER_CHANGED.describe(
      'The supplier, VERIFIED: its AI agents may now ask to pay it, and everyone was told.',
    ),
  },
};

const PAYEE_WITHDRAW_SCHEMA = {
  summary: 'Withdraw a supplier’s new bank details waiting: at once, with no step-up',
  params: SUPPLIER_ID,
  body: NOTHING,
  response: { 200: SUPPLIER_CHANGED.describe('The supplier, its bank details as they were.') },
};

const REGISTRATION = z
  .object({
    id: z.uuid().describe('The registration, by its ID: the partner knows it by this ID too.'),
    supplierId: z.uuid().describe('The supplier it registers bank details for.'),
    route: z.enum(REGISTRATION_ROUTES).describe('How the details reach the partner: its own form, or passed through.'),
    status: z
      .enum(['STARTED', 'REGISTERED', 'FAILED', 'UNKNOWN'])
      .describe(
        'STARTED until the partner has the details; REGISTERED once it does, the new details then waiting for the admin’s confirmation; FAILED with why; UNKNOWN when the partner’s answer was lost, until it is asked again.',
      ),
    nameCheck: z
      .enum(NAME_CHECKS)
      .nullable()
      .describe('The partner’s check of the name against the account’s holder, once registered, else null.'),
    maskedName: z.string().nullable().describe('The account holder’s name as the bank masks it, or null.'),
    payeeHint: z
      .string()
      .nullable()
      .describe('The country and last four characters of the account, once registered, else null: never the number.'),
    failure: z.enum(REGISTRATION_FAILURES).nullable().describe('Why it failed, once FAILED, else null.'),
    form: z
      .object({
        url: z.url().describe('The partner’s own page, where the admin enters the bank details.'),
        expiresAt: z.iso.datetime().describe('When the form closes.'),
      })
      .nullable()
      .describe('The partner’s form, while the registration waits for it, else null.'),
  })
  .register(API_SCHEMAS, {
    id: 'PayeeRegistration',
    description: 'A registration of a supplier’s bank details with the payment partner: never the account number.',
  });

/**
 * The most a pass-through's body may be: a name as an add's (at most 800
 * UTF-16 units sent decomposed, each a 6-byte escape) and an IBAN of at most
 * 64 ASCII characters, each escaped too, with room to spare. Fastify refuses
 * a body past it before the schema is read (the B8-3 lesson).
 */
const PASS_THROUGH_BODY_LIMIT = 6144;

/** The IBAN as the partner is given it (normalisedIban), or null for one that isn't a UAE one with valid check digits. */
function ibanOrNull(text: string): string | null {
  try {
    return normalisedIban(text);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    return null;
  }
}

/** The details passed through, checked: the name a visible one, the IBAN a UAE one with valid check digits. */
const PASSED = z
  .strictObject({
    name: z.string().describe('The account holder’s name, as the bank holds it: 1 to 100 visible characters.'),
    iban: z
      .string()
      .max(64)
      .describe('The account’s UAE IBAN, spaces allowed: passed to the payment partner, never kept or logged.'),
  })
  .transform((body, context): PayeeDetails => {
    const name = visibleName(body.name, SUPPLIER_NAME_MOST);
    const iban = ibanOrNull(body.iban);
    // The messages never name what was sent.
    const problems =
      iban === null ? [...name.problems, 'The IBAN must be a UAE IBAN with valid check digits.'] : name.problems;
    for (const message of problems) context.addIssue({ code: 'custom', message });
    return iban === null || problems.length > 0 ? z.NEVER : { name: name.name, iban };
  })
  .describe('The supplier’s bank details, for the partner alone.');

const PAYEE_PASS_THROUGH_SCHEMA = {
  summary: 'Register a supplier’s bank details with the payment partner, passed through within this request',
  params: SUPPLIER_ID,
  body: PASSED,
  response: { 201: REGISTRATION.describe('The registration, as the partner answered it.') },
};

const PAYEE_START_SCHEMA = {
  summary: 'Start registering a supplier’s bank details with the payment partner, through its own form',
  params: SUPPLIER_ID,
  body: NOTHING,
  response: { 201: REGISTRATION.describe('The registration, started, with the partner’s form.') },
};

const PAYEE_CHECK_SCHEMA = {
  summary: 'Ask the payment partner how a registration of a supplier’s bank details stands, and keep its answer',
  params: SUPPLIER_ID.extend({ registrationId: z.uuid().describe('The registration, by its ID.') }),
  body: NOTHING,
  response: {
    200: REGISTRATION.describe('The registration, as the partner’s answer left it.'),
    202: REGISTRATION.describe('The registration, still waiting for the partner’s form: nothing was changed.'),
  },
};

const AGENT_SUPPLIER = z
  .object({
    id: z.uuid().describe('The supplier, by its ID.'),
    displayName: z.string().describe('Its name.'),
  })
  .register(API_SCHEMAS, {
    id: 'AgentSupplier',
    description: 'A verified supplier the agent’s organisation may pay: its ID and name alone (SEC-AG-05).',
  });

const AGENT_LIST_SCHEMA = {
  summary: 'The verified suppliers your organisation may pay',
  querystring: PAGE,
  response: {
    200: z
      .object({
        suppliers: z.array(AGENT_SUPPLIER).describe('Those of this page that are verified, in order of ID.'),
        next: NEXT,
      })
      .describe('A page of suppliers: it may hold fewer than asked for, and `next` still leads on.'),
  },
};

/** The route's own caller: a member the access hook found. The hooks let no one else through. */
function memberOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('a suppliers route ran without a member');
  return { orgId: member.orgId, userId: person.userId };
}

/** The route's caller in the session a step-up challenge is bound to. */
function inSessionOf(request: FastifyRequest) {
  const { person } = request;
  if (person === null) throw new Error('a suppliers route ran without a person');
  return { ...memberOf(request), sessionId: person.sessionId };
}

const supplierOf = (supplier: SupplierRecord, displayName: string) => ({
  id: supplier.id,
  status: supplier.status,
  displayName,
  changeWaiting: supplier.pendingVersionId !== null,
  coolingOffUntil: supplier.coolingOffUntil === null ? null : supplier.coolingOffUntil.toISOString(),
  verifiedBy: supplier.verifiedBy,
});

// Field by field, as the rest of this file's bodies: nothing more of a payee can ever reach an answer.
const payeeBodyOf = (payee: PayeeShown | null) =>
  payee === null
    ? null
    : {
        registrationId: payee.registrationId,
        payeeHint: payee.payeeHint,
        nameCheck: payee.nameCheck,
        maskedName: payee.maskedName,
      };

const detailsOf = ({ supplier, version, contacts, payee, pending }: SupplierView) => ({
  ...supplierOf(supplier, version.displayName),
  version: version.version,
  phone: contacts.phone,
  phoneSince: version.phoneSince.toISOString(),
  email: contacts.email,
  tradeLicence: contacts.tradeLicence,
  source: version.source,
  enteredBy: version.enteredBy,
  enteredAt: version.enteredAt.toISOString(),
  payee: payeeBodyOf(payee),
  pendingChange:
    pending === null
      ? null
      : {
          version: pending.version.version,
          enteredAt: pending.version.enteredAt.toISOString(),
          payee: payeeBodyOf(pending.payee),
        },
});

const registrationBodyOf = ({ registration, form }: PayeeRegistrationView) => ({
  id: registration.id,
  supplierId: registration.supplierId,
  route: registration.route,
  status: registration.status,
  nameCheck: registration.nameCheck,
  maskedName: registration.maskedName,
  payeeHint: registration.payeeHint,
  failure: registration.failure,
  form: form === null ? null : { url: form.url, expiresAt: form.expiresAt.toISOString() },
});

/** The routes. Each use case does its own; without one they are still documented, and no one reaches them. */
export function registerSuppliers(
  app: FastifyInstance,
  {
    registry,
    changes,
    payees,
    payeeChanges,
    verifications,
    details,
  }: {
    registry: SupplierRegistry | undefined;
    changes: SupplierChanges | undefined;
    payees: SupplierPayees | undefined;
    payeeChanges: SupplierPayeeChanges | undefined;
    verifications: SupplierVerifications | undefined;
    details: SupplierDetailsChanges | undefined;
  },
) {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const refused = (
    answer: { outcome: 'refused'; status: number; code: Parameters<typeof sendErrorBody>[2] },
    request: FastifyRequest,
    reply: FastifyReply,
  ) => sendErrorBody(reply, answer.status, answer.code, request.id);

  /** Answers a change: the supplier as it now stands, a step-up asked, or a refusal. */
  const answerChange = (written: SupplierChangeWrite, request: FastifyRequest, reply: FastifyReply) => {
    if (written.outcome === 'changed') return reply.code(200).send(detailsOf(written));
    if (written.outcome === 'asked') return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    if (written.outcome === 'refused') return refused(written, request, reply);
    return answerRefusedWrite(written, request, reply);
  };

  /** Answers a payee registration: as it now stands, still waiting, or a refusal. */
  const answerPayee = (written: PayeeWrite, request: FastifyRequest, reply: FastifyReply) => {
    if (written.outcome === 'refused') return refused(written, request, reply);
    if (written.outcome === 'conflict' || written.outcome === 'busy') {
      return answerRefusedWrite(written, request, reply);
    }
    const status = { started: 201, checked: 200, waiting: 202 }[written.outcome];
    return reply.code(status).send(registrationBodyOf(written));
  };

  const pageOf = (query: { after?: string | undefined; limit?: number | undefined }) => ({
    after: query.after ?? null,
    limit: query.limit ?? MOST_SUPPLIERS_A_PAGE,
  });

  routes.post(
    '/v1/suppliers',
    {
      schema: ADD_SCHEMA,
      bodyLimit: ADD_BODY_LIMIT,
      config: { access: [...ADDING_ROLES], operation: ADD_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(registry).add(
        member,
        idempotentRequest(request, member.orgId),
        request.body,
        request.id,
      );
      if (written.outcome === 'refused') return refused(written, request, reply);
      if (written.outcome === 'conflict' || written.outcome === 'busy') {
        return answerRefusedWrite(written, request, reply);
      }
      return reply.code(201).send(detailsOf(written));
    },
  );

  routes.get(
    '/v1/suppliers',
    { schema: LIST_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const listed = await need(registry).list(orgId, pageOf(request.query), request.id);
      if (listed.outcome === 'refused') return refused(listed, request, reply);
      return {
        suppliers: listed.suppliers.map((supplier) => supplierOf(supplier, supplier.displayName)),
        next: listed.next,
      };
    },
  );

  routes.get(
    '/v1/suppliers/:id',
    { schema: SHOW_SCHEMA, config: { access: [...READING_ROLES] } },
    async (request, reply) => {
      const { orgId } = memberOf(request);
      const found = await need(registry).show(orgId, request.params.id, request.id);
      if (found.outcome === 'refused') return refused(found, request, reply);
      return detailsOf(found);
    },
  );

  routes.post(
    '/v1/suppliers/:id/suspend',
    {
      schema: SUSPEND_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...SUSPENDING_ROLES], operation: SUSPEND_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(changes).suspend(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/details',
    {
      schema: DETAILS_SCHEMA,
      bodyLimit: ADD_BODY_LIMIT,
      config: { access: [...ADDING_ROLES], operation: DETAILS_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(details).change(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/details/confirm',
    {
      schema: DETAILS_CONFIRM_SCHEMA,
      bodyLimit: ADD_BODY_LIMIT + CHALLENGE_BODY_LIMIT,
      config: { access: [...ADDING_ROLES], operation: DETAILS_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(details).changeConfirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/reactivate',
    {
      schema: REACTIVATE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(changes).reactivate(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/reactivate/confirm',
    {
      schema: REACTIVATE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...REACTIVATING_ROLES], operation: REACTIVATE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(changes).reactivateConfirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/payee-registrations',
    {
      schema: PAYEE_START_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REGISTERING_ROLES], operation: PAYEE_START_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(payees).start(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerPayee(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/payee-registrations/pass-through',
    {
      schema: PAYEE_PASS_THROUGH_SCHEMA,
      bodyLimit: PASS_THROUGH_BODY_LIMIT,
      config: { access: [...REGISTERING_ROLES], operation: PAYEE_PASS_THROUGH_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(payees).passThrough(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body,
        request.id,
      );
      return answerPayee(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/payee-registrations/:registrationId/check',
    {
      schema: PAYEE_CHECK_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REGISTERING_ROLES], operation: PAYEE_CHECK_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(payees).check(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.params.registrationId,
        request.id,
      );
      return answerPayee(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/payee-change/approve',
    {
      schema: PAYEE_APPROVE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...REGISTERING_ROLES], operation: PAYEE_APPROVE_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(payeeChanges).approve(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/payee-change/approve/confirm',
    {
      schema: PAYEE_APPROVE_CONFIRM_SCHEMA,
      bodyLimit: CHALLENGE_BODY_LIMIT,
      config: { access: [...REGISTERING_ROLES], operation: PAYEE_APPROVE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(payeeChanges).approveConfirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/verify',
    {
      schema: VERIFY_SCHEMA,
      bodyLimit: VERIFY_BODY_LIMIT,
      config: { access: [...VERIFYING_ROLES], operation: VERIFY_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(verifications).verify(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        { note: request.body.note ?? null },
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/verify/confirm',
    {
      schema: VERIFY_CONFIRM_SCHEMA,
      bodyLimit: VERIFY_BODY_LIMIT,
      config: { access: [...VERIFYING_ROLES], operation: VERIFY_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const member = inSessionOf(request);
      const written = await need(verifications).verifyConfirm(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        { stepUpChallengeId: request.body.stepUpChallengeId, note: request.body.note ?? null },
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.post(
    '/v1/suppliers/:id/payee-change/withdraw',
    {
      schema: PAYEE_WITHDRAW_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...WITHDRAWING_ROLES], operation: PAYEE_WITHDRAW_OPERATION },
    },
    async (request, reply) => {
      const member = memberOf(request);
      const written = await need(payeeChanges).withdraw(
        member,
        idempotentRequest(request, member.orgId),
        request.params.id,
        request.id,
      );
      return answerChange(written, request, reply);
    },
  );

  routes.get(
    '/v1/agent/suppliers',
    { schema: AGENT_LIST_SCHEMA, config: { access: ['agent'], agentScopes: ['suppliers:read'] } },
    async (request, reply) => {
      const { orgId } = agentOf(request);
      const listed = await need(registry).usableByAgent(orgId, pageOf(request.query), request.id);
      if (listed.outcome === 'refused') return refused(listed, request, reply);
      // The ID and name alone, field by field: nothing else of the supplier can reach an agent.
      return {
        suppliers: listed.suppliers.map((supplier) => ({ id: supplier.id, displayName: supplier.displayName })),
        next: listed.next,
      };
    },
  );
}
