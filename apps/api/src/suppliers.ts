// The organisation's suppliers (PRD §7.1, ADR-012 §1, BR-04, BR-21,
// SEC-AG-05; Phase 1 E1-2).
//
// - `POST /v1/suppliers`: adds a supplier, UNVERIFIED, with its name, its
//   phone (an email and a trade licence number if known) and the independent
//   source its details were checked against: 201 with the supplier. Admins;
//   20 a day (409 SUPPLIER_ADDS_SPENT).
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
// - `GET /v1/agent/suppliers?after=&limit=` (SEC-AG-05): for an agent's key
//   with `suppliers:read`, the VERIFIED suppliers, each by ID and name alone:
//   never a contact, a source or a payment detail.
// Refusals: 404 NOT_FOUND for a supplier not the organisation's; 503
// INTEGRITY_FAILED when the caller's membership, a supplier or its version
// can't be verified. The use cases are supplier-registry.ts and
// supplier-changes.ts.
import {
  MOST_SUPPLIERS_A_PAGE,
  SOURCE_KINDS,
  type SupplierDetails,
  SupplierDetailsRefused,
  supplierDetails,
  type SupplierRecord,
} from '@agentx/core/modules/suppliers';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { agentOf } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';
import {
  REACTIVATE_CONFIRM_OPERATION,
  REACTIVATE_OPERATION,
  REACTIVATING_ROLES,
  type SupplierChanges,
  type SupplierChangeWrite,
  SUSPEND_OPERATION,
  SUSPENDING_ROLES,
} from './supplier-changes.ts';
import { ADD_OPERATION, ADDING_ROLES, type SupplierRegistry } from './supplier-registry.ts';
import type { SupplierView } from './supplier-work.ts';

/** Every member may see the organisation's suppliers. */
const READING_ROLES = ['admin', 'approver', 'developer', 'viewer'] as const;

/**
 * The most UTF-16 units a name may be sent as: it is kept as at most 100
 * code points once composed (NFC, visibleName), each sent decomposed as at
 * most 4 (Unicode's longest canonical decomposition), every one astral at
 * worst: 800, with room to spare. More can't be a name, so it is refused
 * unread.
 */
const NAME_UNITS = 1000;

/**
 * The most an add's body may be: a name of NAME_UNITS, each sent as a
 * `\uXXXX` escape (6 bytes), a phone of 16, an email of 254, a trade licence
 * of 50 and a source's reference of 200, each ASCII character escaped too,
 * with room to spare (the review of #221: a name sent decomposed is longer
 * than it is kept). Fastify refuses a body past it before the schema is read
 * (the B8-3 lesson), so it must fit every body the schema allows.
 */
const ADD_BODY_LIMIT = 12_288;
/** The most a bodyless write may be sent with: an empty object, with room to spare. */
const NOTHING_BODY_LIMIT = 64;
/** The most a confirm's body may be: a challenge's ID, with room to spare. */
const CHALLENGE_BODY_LIMIT = 128;

const NOTHING = z
  .strictObject({})
  // Fastify gives a request sent with no body a null one.
  .nullish()
  .describe('Nothing. An empty object, or no body at all.');

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
}).register(API_SCHEMAS, {
  id: 'SupplierDetails',
  description: 'A supplier with its current details: never a payment detail.',
});

/** The details as a version keeps them, or the problems that keep them from being one. */
const ADDED = z
  .strictObject({
    displayName: z.string().max(NAME_UNITS).describe('Its name: 1 to 100 visible characters, with a letter or digit.'),
    phone: z.string().describe('Its phone, in international form, such as +971501234567.'),
    email: z.string().nullish().describe('Its email, if known.'),
    tradeLicence: z.string().nullish().describe('Its trade licence number, if known: letters, digits, - and /.'),
    source: z
      .strictObject({
        kind: z.enum(SOURCE_KINDS).describe('Where you checked its details: a registry or its official website.'),
        ref: z.string().describe('The registry number, or the website’s address: printable ASCII, at most 200.'),
      })
      .describe('The independent source you checked its details against.'),
  })
  .transform((body, context): SupplierDetails => {
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
  })
  .describe('The supplier to add, UNVERIFIED.');

const ADD_SCHEMA = {
  summary: 'Add a supplier, unverified',
  body: ADDED,
  response: { 201: SUPPLIER_DETAILS.describe('The supplier, added UNVERIFIED.') },
};

const PAGE = z.strictObject({
  after: z.uuid().optional().describe('The ID the page starts after: the last page’s `next`.'),
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(MOST_SUPPLIERS_A_PAGE)
    .optional()
    .describe(`How many at most, ${String(MOST_SUPPLIERS_A_PAGE)} unless fewer are asked for.`),
});

const NEXT = z.uuid().nullable().describe('The ID to ask the next page after; null at the end.');

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
    202: z
      .object({
        stepUpChallengeId: z
          .uuid()
          .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming.'),
      })
      .register(API_SCHEMAS, {
        id: 'SupplierReactivationAsked',
        description: 'Reactivating a supplier, waiting for the admin to sign in again.',
      }),
  },
};

const REACTIVATE_CONFIRM_SCHEMA = {
  summary: 'Reactivate the supplier, once signed in again for it',
  params: SUPPLIER_ID,
  body: z
    .strictObject({ stepUpChallengeId: z.uuid().describe('The step-up the ask answered with, signed in again for.') })
    .describe('The step-up signed in again for.'),
  response: { 200: SUPPLIER_CHANGED },
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

const detailsOf = ({ supplier, version, contacts }: SupplierView) => ({
  ...supplierOf(supplier, version.displayName),
  version: version.version,
  phone: contacts.phone,
  phoneSince: version.phoneSince.toISOString(),
  email: contacts.email,
  tradeLicence: contacts.tradeLicence,
  source: version.source,
  enteredBy: version.enteredBy,
  enteredAt: version.enteredAt.toISOString(),
});

/** The routes. Each use case does its own; without one they are still documented, and no one reaches them. */
export function registerSuppliers(
  app: FastifyInstance,
  { registry, changes }: { registry: SupplierRegistry | undefined; changes: SupplierChanges | undefined },
) {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const need = <T>(useCase: T | undefined): T => {
    if (useCase === undefined) throw new Error('a suppliers route ran without its use case');
    return useCase;
  };
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
