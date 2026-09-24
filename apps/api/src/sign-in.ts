// The console's sign-in routes (ADR-003 §5-§7, B2-3a-2). The API is the login
// service's OIDC client; the identity module does the work (createSignIn),
// and these routes carry it over HTTP with two cookies:
//
// - the flow cookie, `__Host-agentx-flow`: the random flow ID from the start
//   of a sign-in until the browser comes back, ten minutes at most. It is
//   `SameSite=Lax`, so the login service's redirect back to us carries it;
// - the session cookie, `__Host-agentx-session`: the session's cookie ID,
//   `SameSite=Strict`, set fresh at every sign-in (SEC-HA-07), for as long as
//   the session may live at most.
//
// Both are `__Host-` cookies (`Secure`, `Path=/`, no `Domain`): no other host
// of the site can set or read them. Both are `HttpOnly`, so no script reads
// them. They are set with the `Set-Cookie` header directly: the server refuses
// every onSend hook, which a cookie plugin would need (API.md).
//
// - `GET /v1/auth/sign-in?returnTo=…` starts a sign-in and sends the browser to
//   the login service; `returnTo` is only ever a path on our own origin
//   (SEC-WEB-04), home if none.
// - `GET /v1/auth/callback` is where the login service sends it back: the flow
//   is used once, the code traded and the ID token checked, a session opened,
//   and the browser sent to the path it asked for. Anything wrong is
//   SIGN_IN_FAILED, and no session is opened; the log says which step failed,
//   and the failure is noted as a security event with the client's address
//   (B2-5b).
// - At either, a login service that can't be reached (on staging, often one
//   still waking from zero) is SIGN_IN_UNAVAILABLE, 503 with Retry-After: a
//   failure on our side, so no security event, never the 500 it was (S47).
// - `GET /v1/auth/step-up?challenge=…&returnTo=…` (B3-3a, ADR-003 §9) starts
//   a step-up for a challenge of the signed-in person's own session: a flow
//   cookie, and off to the login service to sign in again (`prompt=login`).
//   The callback then checks the fresh sign-in against the challenge,
//   records its evidence there and gives the session a new cookie ID
//   (SEC-HA-07), keeping its record, and sends the browser back to confirm
//   the change. Anything wrong is STEP_UP_FAILED, 403: the person is signed
//   in, but this change isn't confirmed; noted as a security event with the
//   person (`sign_in_failed`, reason `step_up_<failure>`).
// - `POST /v1/auth/sign-out` ends the session the browser holds. It changes
//   something, so the Origin rule holds it (SEC-WEB-01).
// - `GET /v1/auth/session` (B2-4b) answers a signed-in person with their own
//   session: when and how they signed in, and when it ends. The access hook
//   has found it (access.ts); anyone else gets its 401.
//
// The first three are public: each answers whoever calls it, and each acts
// only on what the caller's own cookies name. With sign-in off (no login service set,
// B2-6), all three answer NOT_FOUND, as a feature that is off does. So does a
// HEAD of either GET (Fastify serves one beside each): a link checker's HEAD
// must neither start a flow nor use one up.
import {
  isReturnPath,
  type SignIn,
  SignInFailed,
  type SignInFailure,
  StepUpFailed,
} from '@agentx/core/modules/identity';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import type { SecurityEventSink } from './security-recorder.ts';

export const FLOW_COOKIE = '__Host-agentx-flow';
export const SESSION_COOKIE = '__Host-agentx-session';

/** How long the flow cookie lasts: the flow's own ten minutes (LOGIN_FLOW_SECONDS). */
const FLOW_COOKIE_SECONDS = 600;

/** A value one of our cookies can hold: 32 random bytes as base64url. */
const COOKIE_VALUE = /^[A-Za-z0-9_-]{43}$/;

export interface SignInRoutesOptions {
  /** The sign-in, or undefined when it is off. */
  readonly signIn: SignIn | undefined;
  /** How long the session cookie lasts: the session's absolute timeout. */
  readonly sessionSeconds: number;
  readonly logger: Logger;
  /** Where each failed sign-in is noted. */
  readonly securityEvents: SecurityEventSink;
}

/** The attributes both cookies share: a `__Host-` cookie must be Secure, on Path=/, with no Domain. */
const cookie = (name: string, value: string, sameSite: 'Lax' | 'Strict', maxAge: number): string =>
  `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${String(maxAge)}`;

/**
 * The value of one of our cookies, from the request's Cookie header. Undefined
 * if it is missing, isn't a value we could have set, or is there twice: a
 * browser sends two only if something other than us set one, and then neither
 * can be trusted to be ours.
 */
export function cookieValue(header: string | undefined, name: string): string | undefined {
  if (header === undefined) return undefined;
  const values = header
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`))
    .map((part) => part.slice(name.length + 1));
  const [value] = values;
  return values.length === 1 && value !== undefined && COOKIE_VALUE.test(value) ? value : undefined;
}

const REDIRECT = z
  .object({})
  .register(API_SCHEMAS, { description: 'Sent on: the Location header names where; the body is an empty object.' });

const SIGN_IN_SCHEMA = {
  summary: 'Start a sign-in',
  querystring: z.object({
    returnTo: z
      .string()
      .max(512)
      .refine(isReturnPath, { error: 'must be a path on this origin' })
      .optional()
      .describe('Where to go once signed in: a path on this origin. Home if none.'),
  }),
  response: { 302: REDIRECT },
};

const CALLBACK_SCHEMA = {
  summary: 'Where the login service sends the browser back',
  querystring: z.object({
    code: z.string().max(2048).optional(),
    state: z.string().max(2048).optional(),
    error: z.string().max(256).optional(),
  }),
  response: { 302: REDIRECT },
};

const STEP_UP_SCHEMA = {
  summary: 'Sign in again to confirm a change',
  querystring: z.object({
    challenge: z.uuid().describe("The step-up challenge the change's own address opened for this session."),
    returnTo: z
      .string()
      .max(512)
      .refine(isReturnPath, { error: 'must be a path on this origin' })
      .optional()
      .describe('Where to go once signed in again, to confirm the change: a path on this origin. Home if none.'),
  }),
  response: { 302: REDIRECT },
};

const SESSION_SCHEMA = {
  summary: 'Your own session',
  response: {
    200: z
      .object({
        userId: z.uuid().describe("The signed-in person's ID in Agent X."),
        authenticatedAt: z.iso.datetime().describe('When they last proved who they are at the login service.'),
        methods: z
          .array(z.string())
          .describe('How they proved it, as the login service named it (RFC 8176): pwd, otp, user, mfa.'),
        idleExpiresAt: z.iso
          .datetime()
          .describe('When the session ends if it goes unused from now; each signed-in request moves it on.'),
        expiresAt: z.iso.datetime().describe('When the session ends however much it is used.'),
      })
      .register(API_SCHEMAS, { id: 'Session', description: "The signed-in person's own session." }),
  },
};

const SIGN_OUT_SCHEMA = {
  summary: 'Sign out',
  response: {
    204: z.object({}).register(API_SCHEMAS, { description: 'Signed out, or there was no session to end.' }),
  },
};

/** Sign-out reads no body; this is the smallest limit the contract takes. */
const SIGN_OUT_BODY_LIMIT = 1;

const PUBLIC = { access: ['public'] } as const;

/** How long to wait before starting again when the login service can't be reached: long enough for it to wake from zero. */
const UNAVAILABLE_RETRY_SECONDS = 15;

/** Why a sign-in failed: the sign-in's own failures, or the login service's answer before them. */
type CallbackFailure = SignInFailure | 'provider_refused' | 'callback_incomplete';

export function registerSignIn(
  app: FastifyInstance,
  { signIn, sessionSeconds, logger, securityEvents }: SignInRoutesOptions,
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  /** Logs a failed sign-in, notes it as a security event, and refuses it. */
  const failed = (request: FastifyRequest, reply: FastifyReply, failure: CallbackFailure, reason?: string) => {
    logger
      .child({ correlationId: request.id })
      .warn('auth.sign_in_failed', reason === undefined ? { failure } : { failure, reason });
    securityEvents.note({ kind: 'sign_in_failed', reason: failure, ip: request.ip });
    return sendErrorBody(reply, 401, 'SIGN_IN_FAILED', request.id);
  };
  const off = (request: FastifyRequest, reply: FastifyReply) => sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
  /** The login service couldn't be reached: logged, and answered 503 to try again; no security event, as the caller did nothing wrong. */
  const unavailable = (request: FastifyRequest, reply: FastifyReply, reason: string) => {
    logger.child({ correlationId: request.id }).warn('auth.sign_in_unavailable', { reason });
    return sendErrorBody(
      reply.header('retry-after', String(UNAVAILABLE_RETRY_SECONDS)),
      503,
      'SIGN_IN_UNAVAILABLE',
      request.id,
    );
  };
  /** Logs a failed step-up, notes it as a security event with the person, and refuses it: they stay signed in. */
  const stepUpFailed = (request: FastifyRequest, reply: FastifyReply, failed: StepUpFailed) => {
    const { failure, userId } = failed;
    logger
      .child({ correlationId: request.id })
      .warn('auth.step_up_failed', userId === undefined ? { failure } : { failure, userId });
    securityEvents.note({
      kind: 'sign_in_failed',
      reason: `step_up_${failure}`,
      ip: request.ip,
      ...(userId !== undefined && { userId }),
    });
    return sendErrorBody(reply, 403, 'STEP_UP_FAILED', request.id);
  };

  routes.get('/v1/auth/sign-in', { schema: SIGN_IN_SCHEMA, config: PUBLIC }, async (request, reply) => {
    if (signIn === undefined || request.method === 'HEAD') return off(request, reply);
    let begun;
    try {
      begun = await signIn.begin(request.query.returnTo);
    } catch (thrown) {
      if (thrown instanceof SignInFailed && thrown.failure === 'provider_unavailable') {
        return unavailable(request, reply, thrown.message);
      }
      throw thrown;
    }
    const { url, flowId } = begun;
    return reply
      .code(302)
      .header('location', url)
      .header('set-cookie', cookie(FLOW_COOKIE, flowId, 'Lax', FLOW_COOKIE_SECONDS))
      .send({});
  });

  routes.get('/v1/auth/callback', { schema: CALLBACK_SCHEMA, config: PUBLIC }, async (request, reply) => {
    if (signIn === undefined || request.method === 'HEAD') return off(request, reply);
    const { code, state, error } = request.query;
    if (error !== undefined || code === undefined || state === undefined) {
      // The login service said no (the person cancelled, say), or the address was cut short.
      return failed(request, reply, error === undefined ? 'callback_incomplete' : 'provider_refused');
    }
    let done;
    try {
      done = await signIn.complete({
        flowId: cookieValue(request.headers.cookie, FLOW_COOKIE),
        code,
        state,
        previousCookie: cookieValue(request.headers.cookie, SESSION_COOKIE),
      });
    } catch (thrown) {
      if (thrown instanceof StepUpFailed) return stepUpFailed(request, reply, thrown);
      if (!(thrown instanceof SignInFailed)) throw thrown;
      if (thrown.failure === 'provider_unavailable') return unavailable(request, reply, thrown.message);
      return failed(request, reply, thrown.failure, thrown.message);
    }
    logger
      .child({ correlationId: request.id })
      .info(done.stepUpChallengeId === undefined ? 'auth.signed_in' : 'auth.stepped_up', { userId: done.userId });
    return reply
      .code(302)
      .header('location', done.returnTo)
      .header('set-cookie', [
        cookie(SESSION_COOKIE, done.cookie, 'Strict', sessionSeconds),
        cookie(FLOW_COOKIE, '', 'Lax', 0),
      ])
      .send({});
  });

  routes.get('/v1/auth/step-up', { schema: STEP_UP_SCHEMA, config: { access: ['person'] } }, async (request, reply) => {
    const session = request.person;
    // The access hook lets no one else through; a route that runs without a person is a bug.
    if (session === null) throw new Error('the step-up route ran without a signed-in person');
    if (signIn === undefined || request.method === 'HEAD') return off(request, reply);
    let begun;
    try {
      begun = await signIn.beginStepUp(session.sessionId, request.query.challenge, request.query.returnTo);
    } catch (thrown) {
      if (thrown instanceof StepUpFailed) {
        return stepUpFailed(request, reply, new StepUpFailed(thrown.failure, thrown.message, session.userId));
      }
      if (thrown instanceof SignInFailed && thrown.failure === 'provider_unavailable') {
        return unavailable(request, reply, thrown.message);
      }
      throw thrown;
    }
    return reply
      .code(302)
      .header('location', begun.url)
      .header('set-cookie', cookie(FLOW_COOKIE, begun.flowId, 'Lax', FLOW_COOKIE_SECONDS))
      .send({});
  });

  routes.get('/v1/auth/session', { schema: SESSION_SCHEMA, config: { access: ['person'] } }, (request) => {
    const session = request.person;
    // The access hook lets no one else through; a route that runs without a person is a bug.
    if (session === null) throw new Error('the session route ran without a signed-in person');
    return {
      userId: session.userId,
      authenticatedAt: session.authTime.toISOString(),
      methods: [...session.amr],
      idleExpiresAt: session.idleEndsAt.toISOString(),
      expiresAt: session.endsAt.toISOString(),
    };
  });

  routes.post(
    '/v1/auth/sign-out',
    { schema: SIGN_OUT_SCHEMA, config: PUBLIC, bodyLimit: SIGN_OUT_BODY_LIMIT },
    async (request, reply) => {
      if (signIn === undefined) return off(request, reply);
      const ended = await signIn.signOut(cookieValue(request.headers.cookie, SESSION_COOKIE));
      if (ended) logger.child({ correlationId: request.id }).info('auth.signed_out');
      return reply
        .code(204)
        .header('set-cookie', cookie(SESSION_COOKIE, '', 'Strict', 0))
        .send({});
    },
  );
}
