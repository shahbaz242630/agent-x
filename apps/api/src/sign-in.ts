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
//   SIGN_IN_FAILED, and no session is opened; the log says which step failed.
// - `POST /v1/auth/sign-out` ends the session the browser holds. It changes
//   something, so the Origin rule holds it (SEC-WEB-01).
//
// All three are public: each answers whoever calls it, and each acts only on
// what the caller's own cookies name. With sign-in off (no login service set,
// B2-6), all three answer NOT_FOUND, as a feature that is off does.
import { isReturnPath, type SignIn, SignInFailed } from '@agentx/core/modules/identity';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';

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

const SIGN_OUT_SCHEMA = {
  summary: 'Sign out',
  response: {
    204: z.object({}).register(API_SCHEMAS, { description: 'Signed out, or there was no session to end.' }),
  },
};

/** Sign-out reads no body; this is the smallest limit the contract takes. */
const SIGN_OUT_BODY_LIMIT = 1;

const PUBLIC = { access: ['public'] } as const;

export function registerSignIn(app: FastifyInstance, { signIn, sessionSeconds, logger }: SignInRoutesOptions): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const off = (request: FastifyRequest, reply: FastifyReply) => sendErrorBody(reply, 404, 'NOT_FOUND', request.id);

  routes.get('/v1/auth/sign-in', { schema: SIGN_IN_SCHEMA, config: PUBLIC }, async (request, reply) => {
    if (signIn === undefined) return off(request, reply);
    const { url, flowId } = await signIn.begin(request.query.returnTo);
    return reply
      .code(302)
      .header('location', url)
      .header('set-cookie', cookie(FLOW_COOKIE, flowId, 'Lax', FLOW_COOKIE_SECONDS))
      .send({});
  });

  routes.get('/v1/auth/callback', { schema: CALLBACK_SCHEMA, config: PUBLIC }, async (request, reply) => {
    if (signIn === undefined) return off(request, reply);
    const log = logger.child({ correlationId: request.id });
    const { code, state, error } = request.query;
    if (error !== undefined || code === undefined || state === undefined) {
      // The login service said no (the person cancelled, say), or the address was cut short.
      log.warn('auth.sign_in_failed', { failure: error === undefined ? 'callback_incomplete' : 'provider_refused' });
      return sendErrorBody(reply, 401, 'SIGN_IN_FAILED', request.id);
    }
    let done;
    try {
      done = await signIn.complete({
        flowId: cookieValue(request.headers.cookie, FLOW_COOKIE),
        code,
        state,
        previousCookie: cookieValue(request.headers.cookie, SESSION_COOKIE),
      });
    } catch (failed) {
      if (!(failed instanceof SignInFailed)) throw failed;
      log.warn('auth.sign_in_failed', { failure: failed.failure, reason: failed.message });
      return sendErrorBody(reply, 401, 'SIGN_IN_FAILED', request.id);
    }
    log.info('auth.signed_in', { userId: done.userId });
    return reply
      .code(302)
      .header('location', done.returnTo)
      .header('set-cookie', [
        cookie(SESSION_COOKIE, done.cookie, 'Strict', sessionSeconds),
        cookie(FLOW_COOKIE, '', 'Lax', 0),
      ])
      .send({});
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
