// An organisation's registered contacts (ADR-012 §1, §8; SEC-OPS-06; B6-1c):
// its trust anchor, told of the changes that matter and, from B6-3, asked to
// confirm a lost second factor's reset. Admins only, in the organisation the
// request names; every change with a step-up (ADR-003 §8), told to the
// admins and the contacts.
//
// 1. `GET /v1/registered-contacts`: the ACTIVE contacts, each with its
//    address, when it starts to count and whether it counts now.
// 2. `POST /v1/registered-contacts` with an address keeps it as a DRAFT: 202
//    with the contact and the step-up to sign in again for, at
//    `GET /v1/auth/step-up?challenge=…`.
// 3. `POST /v1/registered-contacts/{id}/confirm`, once signed in again, makes
//    it ACTIVE: it counts 7 days from now (SEC-OPS-06).
// 4. `POST /v1/registered-contacts/{id}/remove` opens a step-up bound to it:
//    202 with its ID; `…/remove/confirm` with that ID, once signed in again,
//    removes it.
// Refusals: 409 CONTACT_EXISTS for an address one of its ACTIVE contacts has;
// 409 CONTACTS_FULL past MOST_CONTACTS; 409 CONTACT_ADDS_SPENT past the
// organisation's contacts started in 24 hours (B8-2); 409 TOO_MANY_CONTACTS
// past the records the list reads; 409 CONTACT_CLOSED for a contact
// confirmed already; 409 CONTACT_NOT_ACTIVE for one removed or never
// confirmed; 404 for one not in the organisation; 403 STEP_UP_FAILED for
// another change than the one signed in again for; 503 INTEGRITY_FAILED when
// a record it rests on can't be verified. The use case is the identity
// module's contact-changes.ts.
import {
  CONTACT_ADD_CONFIRM_OPERATION,
  CONTACT_ADD_OPERATION,
  CONTACT_REMOVE_CONFIRM_OPERATION,
  CONTACT_REMOVE_OPERATION,
  type ContactChanges,
  type ContactChangeWrite,
  type ContactWithAddress,
  countsNow,
  EMAIL_MAX,
  MOST_CONTACTS,
  TooManyContacts,
} from '@agentx/core/modules/identity';
import { systemClock } from '@agentx/core/shared-kernel';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { answerRefusedWrite, idempotentRequest } from './idempotent-writes.ts';

/** The organisation's ACTIVE contacts, verified, for the request with this correlation ID. */
export type ListContacts = (
  orgId: string,
  correlationId: string,
) => Promise<
  { readonly outcome: 'listed'; readonly contacts: readonly ContactWithAddress[] } | { readonly outcome: 'tampered' }
>;

/** The most an add's body may be: an address, with room to spare. */
const ADD_BODY_LIMIT = 512;
/** The most a body that names nothing may be. */
const NOTHING_BODY_LIMIT = 64;
/** The most a removal's confirmation may be: a challenge's ID, with room to spare. */
const REMOVE_CONFIRM_BODY_LIMIT = 128;

const CONTACT = z
  .object({
    id: z.uuid().describe('The registered contact, by its ID.'),
    email: z.string().describe('Its email address.'),
    status: z
      .enum(['DRAFT', 'ACTIVE', 'REMOVED'])
      .describe('DRAFT until the admin who asked signs in again and confirms it; ACTIVE once confirmed; REMOVED.'),
    countsFrom: z.iso
      .datetime()
      .nullable()
      .describe(
        'When it starts to count for confirming sensitive changes: 7 days after it was confirmed. Null for a DRAFT.',
      ),
    counts: z.boolean().describe('Whether it counts now: ACTIVE, and its cooling-off over.'),
  })
  .register(API_SCHEMAS, { id: 'RegisteredContact', description: "One of the organisation's registered contacts." });

const ID = z.object({ id: z.uuid().describe('The registered contact, by its ID.') });
const NOTHING = z
  .strictObject({})
  // Fastify gives a request sent with no body a null one.
  .nullish()
  .describe('Nothing. An empty object, or no body at all.');

const CHANGED = z
  .object({ contact: CONTACT })
  .register(API_SCHEMAS, { id: 'RegisteredContactChanged', description: 'The registered contact, as it now stands.' });

const LIST_SCHEMA = {
  summary: "Your organisation's registered contacts",
  response: {
    200: z.object({ contacts: z.array(CONTACT) }).register(API_SCHEMAS, {
      id: 'RegisteredContacts',
      description: `The organisation's ACTIVE registered contacts, at most ${String(MOST_CONTACTS)}, in order of ID.`,
    }),
  },
};

const ADD_SCHEMA = {
  summary: 'Add a registered contact',
  body: z
    .strictObject({ email: z.email().max(EMAIL_MAX).describe("The contact's email address.") })
    .describe('The contact to add.'),
  response: {
    202: z
      .object({
        contact: CONTACT,
        stepUpChallengeId: z
          .uuid()
          .optional()
          .describe(
            'While the contact is a DRAFT: the step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming it.',
          ),
      })
      .register(API_SCHEMAS, {
        id: 'RegisteredContactDrafted',
        description: 'The contact kept as a draft, waiting for the admin who asked to sign in again and confirm it.',
      }),
  },
};

const CONFIRM_SCHEMA = {
  summary: 'Confirm a registered contact, once signed in again for it',
  params: ID,
  body: NOTHING,
  response: { 200: CHANGED },
};

const REMOVE_SCHEMA = {
  summary: 'Ask to remove a registered contact',
  params: ID,
  body: NOTHING,
  response: {
    202: z
      .object({
        stepUpChallengeId: z
          .uuid()
          .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming.'),
      })
      .register(API_SCHEMAS, {
        id: 'RegisteredContactRemovalAsked',
        description: "A contact's removal, waiting for the admin to sign in again.",
      }),
  },
};

const REMOVE_CONFIRM_SCHEMA = {
  summary: 'Remove a registered contact, once signed in again for it',
  params: ID,
  body: z
    .strictObject({ stepUpChallengeId: z.uuid().describe('The step-up the ask answered with.') })
    .describe('The step-up signed in again for.'),
  response: { 200: CHANGED },
};

/** A contact as the API answers it. */
const contactOf = (contact: ContactWithAddress, now: Date) => ({
  id: contact.id,
  email: contact.email,
  status: contact.status,
  countsFrom: contact.countsFrom?.toISOString() ?? null,
  counts: countsNow(contact, now),
});

/** The route's own caller: an admin the access hook found, with their session. The hooks let no one else through. */
function adminOf(request: FastifyRequest) {
  const { member, person } = request;
  if (member === null || person === null) throw new Error('a registered contact route ran without an admin');
  return { orgId: member.orgId, userId: person.userId, sessionId: person.sessionId };
}

/** Answers a write's refusal; undefined for the route to answer. */
const refusalOf = (written: ContactChangeWrite, request: FastifyRequest, reply: FastifyReply) => {
  if (written.outcome === 'refused') return sendErrorBody(reply, written.status, written.code, request.id);
  if (written.outcome === 'conflict' || written.outcome === 'busy') return answerRefusedWrite(written, request, reply);
  return undefined;
};

/** The written contact, which every answer but a refusal and a removal's ask holds. */
const writtenOf = (written: ContactChangeWrite) => {
  if (written.outcome !== 'written') throw new Error("a contact's change answered without its contact");
  return written;
};

/**
 * The registered contacts' routes. `listContacts` and `changes` do them;
 * without them the routes are still documented, and no one reaches them, as
 * no one holds a role.
 */
export function registerRegisteredContacts(
  app: FastifyInstance,
  { listContacts, changes }: { listContacts: ListContacts | undefined; changes: ContactChanges | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const changesOf = (): ContactChanges => {
    if (changes === undefined) throw new Error('the registered contact routes ran without their writes');
    return changes;
  };

  routes.get(
    '/v1/registered-contacts',
    { schema: LIST_SCHEMA, config: { access: ['admin'] } },
    async (request, reply) => {
      const admin = adminOf(request);
      if (listContacts === undefined) throw new Error('the registered contacts route ran without its list');
      const list = await listContacts(admin.orgId, request.id).catch((error: unknown) => {
        if (error instanceof TooManyContacts) return { outcome: 'too_many' } as const;
        throw error;
      });
      if (list.outcome === 'too_many') return sendErrorBody(reply, 409, 'TOO_MANY_CONTACTS', request.id);
      if (list.outcome === 'tampered') return sendErrorBody(reply, 503, 'INTEGRITY_FAILED', request.id);
      const now = systemClock.now();
      return { contacts: list.contacts.map((contact) => contactOf(contact, now)) };
    },
  );

  routes.post(
    '/v1/registered-contacts',
    { schema: ADD_SCHEMA, bodyLimit: ADD_BODY_LIMIT, config: { access: ['admin'], operation: CONTACT_ADD_OPERATION } },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await changesOf().add(
        admin,
        idempotentRequest(request, admin.orgId),
        request.body.email,
        request.id,
      );
      const refused = refusalOf(written, request, reply);
      if (refused !== undefined) return refused;
      const { contact, stepUpChallengeId } = writtenOf(written);
      return reply.code(202).send({
        contact: contactOf(contact, systemClock.now()),
        ...(stepUpChallengeId !== undefined && { stepUpChallengeId }),
      });
    },
  );

  routes.post(
    '/v1/registered-contacts/:id/confirm',
    {
      schema: CONFIRM_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: ['admin'], operation: CONTACT_ADD_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await changesOf().confirm(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      return (
        refusalOf(written, request, reply) ?? { contact: contactOf(writtenOf(written).contact, systemClock.now()) }
      );
    },
  );

  routes.post(
    '/v1/registered-contacts/:id/remove',
    {
      schema: REMOVE_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: ['admin'], operation: CONTACT_REMOVE_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await changesOf().remove(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.id,
      );
      const refused = refusalOf(written, request, reply);
      if (refused !== undefined) return refused;
      if (written.outcome !== 'asked') throw new Error('a removal answered without its challenge');
      return reply.code(202).send({ stepUpChallengeId: written.stepUpChallengeId });
    },
  );

  routes.post(
    '/v1/registered-contacts/:id/remove/confirm',
    {
      schema: REMOVE_CONFIRM_SCHEMA,
      bodyLimit: REMOVE_CONFIRM_BODY_LIMIT,
      config: { access: ['admin'], operation: CONTACT_REMOVE_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      const admin = adminOf(request);
      const written = await changesOf().removeConfirm(
        admin,
        idempotentRequest(request, admin.orgId),
        request.params.id,
        request.body.stepUpChallengeId,
        request.id,
      );
      return (
        refusalOf(written, request, reply) ?? { contact: contactOf(writtenOf(written).contact, systemClock.now()) }
      );
    },
  );
}
