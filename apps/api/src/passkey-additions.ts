// A passkey added inside Agent X (SA6; ADR-012 §8, SEC-OPS-04, B6-3d): the person's own routes, and the add-a-passkey
// page's, on a host of its own (add-passkey-page.ts). The identity module's passkey-additions.ts does the work.
//
// The person's, on the app's own host, with their session:
// - `POST /v1/auth/passkeys/additions`, with an Idempotency-Key (kept under the person's own keys): 202 with the
//   step-up to sign in again for, at `GET /v1/auth/step-up?challenge=…`, with a passkey they already hold. A password,
//   or an app's code, is refused there (STEP_UP_FAILED, `no_passkey`).
// - `POST /v1/auth/passkeys/additions/{id}/confirm`, with an Idempotency-Key, once signed in again: 201 with the
//   page's one-time ticket and the page's address to open it at (the ticket in the fragment, which no request
//   carries), TICKET_SECONDS to redeem. Before the step-up (or from another session, or once it ran out) it is
//   403 STEP_UP_FAILED; a retry of the same request is 409 PASSKEY_TICKET_ALREADY_ISSUED.
// - `GET /v1/auth/passkeys/additions/{id}`: where it got to (STEPPED_UP, WAITING_FOR_KEY or ADDED; 404 NOT_FOUND once
//   none of this session's is under way, as another person's never is), for the
//   console to check until the key is added.
//
// The page's, on the page's host alone (AGENTX_ADD_PASSKEY_ORIGIN), with no session (the session cookie is the app
// host's alone): the page itself, its script and stylesheet (add-passkey-page.ts, served ahead of Fastify, as the
// console's files are), and
// - `POST /v1/passkey-additions/options` with the ticket: 200 with what the browser makes the key with, once the
//   passkey's ID is on the platform chain as the person's own addition;
// - `POST /v1/passkey-additions/confirm` with the ticket and the key made: 200 once the login service took it.
// Each redeems the ticket once; a second is 409 PASSKEY_TICKET_INVALID, so each is safe to repeat by itself. Their
// browser writes must come from the page's own origin (server.ts), and each network makes at most PAGE_CALLS of them
// a minute. Nothing else answers on that host (server.ts's host gate: 404).
//
// Off (no AGENTX_ADD_PASSKEY_ORIGIN, the default): the person's routes answer 404 NOT_FOUND and the page's host
// serves nothing. Nothing here logs a token, a ticket or a passkey's ID.
import {
  type AdditionAnswer,
  type AdditionRefusal,
  OwnPasskeysUnavailable,
  type PasskeyAdditions,
} from '@agentx/core/modules/identity';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { ADD_PASSKEY_PATH } from './add-passkey-page.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { loginHostCheck } from './login-host.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { PERSON_KEYS_TENANT } from './my-activity.ts';
import { createAddressCounter, clientSite, type ProxyTrust, shareOfCopies } from './rate-limit.ts';
import { stepUpAsked } from './route-schemas.ts';

declare module 'fastify' {
  interface FastifyContextConfig {
    /** SA6: a route of the add-a-passkey page's host, the only kind that host answers, its writes from its origin alone. */
    readonly addPasskeyPage?: true;
  }
}

export const PASSKEY_ADD_OPERATION = 'passkey.add';
export const PASSKEY_CONFIRM_OPERATION = 'passkey.add.confirm';

/** The most of the page's calls one network makes a minute, across every `web` copy: a person needs two. */
export const PAGE_CALLS = { most: 20, windowMs: 60_000 } as const;

/** The status each refusal answers with. */
const STATUS_OF: Readonly<Record<AdditionRefusal, number>> = {
  UNAUTHENTICATED: 401,
  STEP_UP_FAILED: 403,
  PASSKEY_TICKET_ALREADY_ISSUED: 409,
  PASSKEY_TICKET_INVALID: 409,
  PASSKEY_REFUSED: 422,
};

const ADDITION_ID = z.object({ id: z.uuid().describe('The addition, by the step-up it began with.') });
const TICKET = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .describe("The page's one-time ticket.");
/** A WebAuthn value in base64url, bounded. */
const B64 = (most: number) =>
  z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/)
    .max(most);

const NO_BODY = z.strictObject({}).nullish().describe('Nothing.');

const BEGIN_SCHEMA = {
  summary: 'Start adding a passkey',
  description:
    'Opens the step-up to sign in again for, with a passkey you already hold, before a new one is added without the 7 days a key added at the login service directly starts.',
  body: NO_BODY,
  response: { 202: stepUpAsked('PasskeyAdditionAsked', 'The step-up to sign in again for, with a passkey.') },
};

const TICKET_SCHEMA = {
  summary: "Confirm adding a passkey: the add-a-passkey page's one-time ticket",
  params: ADDITION_ID,
  body: NO_BODY,
  response: {
    201: z
      .object({
        ticket: TICKET,
        page: z.url().describe('The page to open in a new tab, the ticket in its fragment.'),
        expiresAt: z.iso.datetime().describe('When the ticket runs out unless the page has used it.'),
      })
      .register(API_SCHEMAS, { id: 'PasskeyTicket', description: "The add-a-passkey page's one-time ticket." }),
  },
};

const STATUS_SCHEMA = {
  summary: 'Where adding a passkey got to',
  params: ADDITION_ID,
  response: {
    200: z
      .object({
        status: z
          .enum(['STEPPED_UP', 'WAITING_FOR_KEY', 'ADDED'])
          .describe(
            'STEPPED_UP: signed in again, the ticket not yet asked for; WAITING_FOR_KEY: the page has the ticket; ADDED: the login service took the new passkey. None under way for this session (run out, not added, or another person’s) is 404 NOT_FOUND.',
          ),
      })
      .register(API_SCHEMAS, { id: 'PasskeyAdditionStatus', description: 'Where adding a passkey got to.' }),
  },
};

/** A WebAuthn value as the login service writes it in JSON, bounded. */
const TEXT = (most: number) => z.string().max(most);

/**
 * WebAuthn's creation options (Level 3, PublicKeyCredentialCreationOptionsJSON) as the login service writes them,
 * every field named, so nothing else it says leaves for the page.
 */
const CREATION_OPTIONS = z
  .object({
    challenge: TEXT(1024).describe('The challenge, base64url.'),
    rp: z.object({ id: TEXT(253).optional(), name: TEXT(256) }).describe('The login service, as the relying party.'),
    user: z
      .object({ id: TEXT(1024), name: TEXT(256), displayName: TEXT(256) })
      .describe('The person, as the login service names them.'),
    pubKeyCredParams: z
      .array(z.object({ type: TEXT(32), alg: z.int() }))
      .max(32)
      .describe('The kinds of key the login service takes.'),
    timeout: z.number().optional().describe('How long the browser waits, in milliseconds.'),
    excludeCredentials: z
      .array(z.object({ type: TEXT(32), id: TEXT(1366), transports: z.array(TEXT(32)).max(8).optional() }))
      .max(100)
      .optional()
      .describe("The person's keys already held, which the browser won't make again."),
    authenticatorSelection: z
      .object({
        authenticatorAttachment: TEXT(32).optional(),
        requireResidentKey: z.boolean().optional(),
        residentKey: TEXT(32).optional(),
        userVerification: TEXT(32).optional(),
      })
      .optional()
      .describe('What kind of key to make.'),
    attestation: TEXT(32).optional().describe('What the key says of where it was made.'),
  })
  .describe("WebAuthn's creation options, as JSON.");

const OPTIONS_SCHEMA = {
  summary: 'What the add-a-passkey page makes the key with',
  description: "The add-a-passkey page's own host alone.",
  body: z.strictObject({ ticket: TICKET }),
  response: {
    200: z
      .object({
        options: z.object({ publicKey: CREATION_OPTIONS }).describe("The login service's options for the new passkey."),
      })
      .register(API_SCHEMAS, { id: 'PasskeyOptions', description: 'What the browser makes the new passkey with.' }),
  },
};

const CONFIRM_SCHEMA = {
  summary: 'Send the add-a-passkey page’s new key',
  description: "The add-a-passkey page's own host alone.",
  body: z.strictObject({
    ticket: TICKET,
    credential: z
      .strictObject({
        id: B64(1366),
        rawId: B64(1366),
        type: z.literal('public-key'),
        response: z.strictObject({ attestationObject: B64(16_384), clientDataJSON: B64(4096) }),
      })
      .describe('The key the browser made, as WebAuthn gives it, in base64url.'),
  }),
  response: {
    200: z.object({}).register(API_SCHEMAS, { description: 'The new passkey is added.' }),
  },
};

/** The most a body of the page's calls may be: a key made is a few kilobytes. */
const CONFIRM_BODY_LIMIT = 32 * 1024;
const SMALL_BODY_LIMIT = 256;

export interface PasskeyAdditionRoutes {
  readonly additions: PasskeyAdditions;
  /** The add-a-passkey page's origin (AGENTX_ADD_PASSKEY_ORIGIN). */
  readonly origin: string;
}

export function registerPasskeyAdditions(
  app: FastifyInstance,
  {
    adding,
    logger,
    trust,
    copies,
  }: {
    /** Off (undefined) by default: every route answers 404. */
    readonly adding: PasskeyAdditionRoutes | undefined;
    readonly logger: Logger;
    readonly trust: ProxyTrust;
    readonly copies: number;
  },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  // The Host as it reached the server, never X-Forwarded-Host, which a client writes; as the login host is told (SA1).
  const onPageHost = loginHostCheck(adding?.origin);
  const off = (request: FastifyRequest, reply: FastifyReply) => sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
  /** The person's own session, which the access hook found. */
  const sessionOf = (request: FastifyRequest) => {
    const { person } = request;
    if (person === null) throw new Error('a passkey route ran without a signed-in person');
    return person;
  };
  /** A refusal or the idempotency key's own answer, as the routes send them. */
  const answerNot = (
    answer: Exclude<AdditionAnswer<object>, { readonly outcome: 'done' }>,
    request: FastifyRequest,
    reply: FastifyReply,
  ) =>
    answerRefusal(
      answer.outcome === 'refused' ? { outcome: 'refused', status: STATUS_OF[answer.code], code: answer.code } : answer,
      request,
      reply,
    );
  /** The login service failed the page's call: said plainly, 503 to try again (with a new ticket). */
  const unavailable = (request: FastifyRequest, reply: FastifyReply, error: unknown) => {
    if (!(error instanceof OwnPasskeysUnavailable)) throw error;
    logger.child({ correlationId: request.id }).warn('identity.passkey_login_service_failed', { err: error });
    return sendErrorBody(reply.header('retry-after', '15'), 503, 'SIGN_IN_UNAVAILABLE', request.id);
  };

  routes.post(
    '/v1/auth/passkeys/additions',
    {
      schema: BEGIN_SCHEMA,
      bodyLimit: SMALL_BODY_LIMIT,
      config: { access: ['person'], operation: PASSKEY_ADD_OPERATION },
    },
    async (request, reply) => {
      if (adding === undefined) return off(request, reply);
      const { sessionId, userId } = sessionOf(request);
      const begun = await adding.additions.begin(sessionId, userId, idempotentRequest(request, PERSON_KEYS_TENANT));
      if (begun.outcome !== 'done') return answerNot(begun, request, reply);
      return reply.code(202).send({ stepUpChallengeId: begun.challengeId });
    },
  );

  routes.post(
    '/v1/auth/passkeys/additions/:id/confirm',
    {
      schema: TICKET_SCHEMA,
      bodyLimit: SMALL_BODY_LIMIT,
      config: { access: ['person'], operation: PASSKEY_CONFIRM_OPERATION },
    },
    async (request, reply) => {
      if (adding === undefined) return off(request, reply);
      const { sessionId } = sessionOf(request);
      const issued = await adding.additions.ticket(
        sessionId,
        request.params.id,
        idempotentRequest(request, PERSON_KEYS_TENANT),
      );
      if (issued.outcome !== 'done') return answerNot(issued, request, reply);
      return reply.code(201).send({
        ticket: issued.ticket,
        page: `${adding.origin}${ADD_PASSKEY_PATH}#${issued.ticket}`,
        expiresAt: issued.endsAt.toISOString(),
      });
    },
  );

  routes.get(
    '/v1/auth/passkeys/additions/:id',
    { schema: STATUS_SCHEMA, config: { access: ['person'] } },
    async (request, reply) => {
      if (adding === undefined) return off(request, reply);
      const { sessionId } = sessionOf(request);
      const status = await adding.additions.status(sessionId, request.params.id);
      // Another person's addition, or none, reads exactly as one that never existed (SEC-TEN-01).
      if (status === 'GONE') return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      return { status };
    },
  );

  // The page's host alone: anywhere else, or off, the same 404 as an address that doesn't exist.
  const pageConfig = { access: ['public'], addPasskeyPage: true } as const;
  const pageLimit = createAddressCounter(
    app,
    { most: shareOfCopies(PAGE_CALLS.most, copies), windowMs: PAGE_CALLS.windowMs },
    trust,
    clientSite,
  );
  routes.post(
    '/v1/passkey-additions/options',
    { schema: OPTIONS_SCHEMA, bodyLimit: SMALL_BODY_LIMIT, config: pageConfig, onRequest: pageLimit },
    async (request, reply) => {
      if (adding === undefined || !onPageHost(request.headers.host)) return off(request, reply);
      try {
        const asked = await adding.additions.options(request.body.ticket);
        if (asked.outcome !== 'done') return await answerNot(asked, request, reply);
        return await reply
          .code(200)
          .send({ options: asked.options as { publicKey: z.infer<typeof CREATION_OPTIONS> } });
      } catch (error) {
        return unavailable(request, reply, error);
      }
    },
  );

  routes.post(
    '/v1/passkey-additions/confirm',
    { schema: CONFIRM_SCHEMA, bodyLimit: CONFIRM_BODY_LIMIT, config: pageConfig, onRequest: pageLimit },
    async (request, reply) => {
      if (adding === undefined || !onPageHost(request.headers.host)) return off(request, reply);
      try {
        const confirmed = await adding.additions.confirm(request.body.ticket, request.body.credential);
        if (confirmed.outcome !== 'done') return await answerNot(confirmed, request, reply);
        logger.child({ correlationId: request.id }).info('identity.passkey_added');
        return await reply.code(200).send({});
      } catch (error) {
        return unavailable(request, reply, error);
      }
    },
  );
}
