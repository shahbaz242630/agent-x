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
//   So is a sign-in started while too many are under way, every network's
//   together, from a busy network (S206 V8, login-flows.ts). No flow is kept,
//   and the cap's warning is said at most once a minute, as the OAuth flows'
//   caps are (capWarning). One started past its own network's share still
//   starts, that network's oldest unfinished sign-ins giving way (S208): one
//   caller can't lock everyone behind a shared address out. That is warned of
//   the same way; a flow that gave way finds nothing at its callback, so that
//   browser is refused SIGN_IN_FAILED and starts again. So that one caller
//   can't push the others out at the address's whole rate, sign-ins started
//   are held to SIGN_IN_STARTS a minute per network, as the open flows are
//   counted (an IPv4 address, an IPv6 /48: clientSite) (TR-17):
//   past it RATE_LIMITED, 429 with Retry-After, and no flow begun.
// - S210 TR-7: a person opens at most MOST_SESSIONS_A_DAY sessions and
//   completes MOST_STEP_UPS_A_DAY step-ups in any 24 hours, as each adds to
//   the shared platform chain (person-chain-caps.ts). A sign-in past it is
//   RATE_LIMITED, 429 with Retry-After, and no session opened; a step-up past
//   it STEP_UPS_SPENT, 429 with Retry-After, at its start, and back at its page
//   with `?stepUpFailed=<challenge>&stepUpWhy=spent` at the callback, for the
//   console to say why; no security event, as nothing about the sign-in was
//   wrong. Each refusal warned with the person's ID, at most once a minute a
//   person (personCapWarning). A sign-out is never refused.
// - S210 R2-4: while the shared platform chain has grown PLATFORM_GROWTH_BRAKE
//   past its last anchor (platform-growth-brake.ts), a sign-in or step-up
//   started is SIGN_IN_UNAVAILABLE, 503 with Retry-After, no flow begun,
//   warned at most once a minute; so many accounts at once can't hold every
//   organisation's hand-off `too_far`. A flow begun before the brake still
//   completes at the callback (bounded by the flows' caps and 15 minutes), so
//   no one finished at the login service lands on an error. A sign-out is
//   never refused.
// - `GET /v1/auth/step-up?challenge=…&returnTo=…` (B3-3a, ADR-003 §9) starts
//   a step-up for a challenge of the signed-in person's own session: a flow
//   cookie, and off to the login service to sign in again (`prompt=login`).
//   The callback then checks the fresh sign-in against the challenge,
//   records its evidence there and gives the session a new cookie ID
//   (SEC-HA-07), keeping its record, and sends the browser back to confirm
//   the change. Anything wrong is STEP_UP_FAILED: this change is not
//   confirmed, and a live session stays as it was; noted as a security
//   event with the person (`sign_in_failed`, reason `step_up_<failure>`).
//   Wrong at the callback, the browser is sent back to the page the change
//   was asked on (its path, its query dropped) with `?stepUpFailed=<challenge>`,
//   for the console to say so there (CO2); wrong at the start, before the
//   browser left the console, it is a 403.
//   The session cookie is SameSite=Strict, so the login service must be on
//   the same site as the app (ADR-003 §7: `auth.` beside `app.`), or the
//   browser would bring no session back and every step-up would fail.
// - `POST /v1/auth/sign-out` ends the session the browser holds. It changes
//   something, so the Origin rule holds it (SEC-WEB-01). Then it ends the
//   person's sessions at the login service too (Shannon AUTH-VULN-01, S88),
//   where it may: one it couldn't end is logged, and the sign-out stands.
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
  type LoginSessions,
  MOST_OPEN_SIGN_INS,
  MOST_OPEN_SIGN_INS_A_NETWORK,
  MOST_SESSIONS_A_DAY,
  MOST_STEP_UPS_A_DAY,
  RETURN_PATH,
  SessionsSpent,
  type SignIn,
  SignInBusy,
  SignInFailed,
  type SignInFailure,
  StepUpFailed,
  type Subject,
} from '@agentx/core/modules/identity';
import { type Clock, systemClock } from '@agentx/core/shared-kernel';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import { capWarning, personCapWarning } from './oauth-authorizing.ts';
import { clientSite, createAddressCounter, type ProxyTrust, shareOfCopies } from './rate-limit.ts';
import { PLATFORM_GROWTH_BRAKE, type PlatformGrowthBrake } from './platform-growth-brake.ts';
import type { SecurityEventSink } from './security-recorder.ts';

export const FLOW_COOKIE = '__Host-agentx-flow';
export const SESSION_COOKIE = '__Host-agentx-session';

/** How long the flow cookie lasts: the flow's own ten minutes (LOGIN_FLOW_SECONDS). */
const FLOW_COOKIE_SECONDS = 600;
/** A step-up's: its flow's fifteen (STEP_UP_FLOW_SECONDS, E6-P2), so a late return reads as its time run out. */
const STEP_UP_FLOW_COOKIE_SECONDS = 900;

/** A value one of our cookies can hold: 32 random bytes as base64url. */
const COOKIE_VALUE = /^[A-Za-z0-9_-]{43}$/;

export interface SignInRoutesOptions {
  /** The sign-in, or undefined when it is off. */
  readonly signIn: SignIn | undefined;
  /** How long the session cookie lasts: the session's absolute timeout. */
  readonly sessionSeconds: number;
  /** Where a sign-out ends the person's sessions at the login service; nowhere when not given. */
  readonly loginSessions?: LoginSessions | undefined;
  readonly logger: Logger;
  /** Where each failed sign-in is noted. */
  readonly securityEvents: SecurityEventSink;
  /** When a cap's warning was last said (S206 V8); the system's clock when not given. */
  readonly clock?: Clock;
  /** Which proxies are trusted to name the client's address, for the sign-ins' own limit per address (TR-17). */
  readonly trust: ProxyTrust;
  /** How many `web` copies share that limit, each counting its share. */
  readonly copies: number;
  /** The platform chain's growth brake (R2-4): new sessions and step-ups wait while it is on; never on when not given. */
  readonly growthBrake?: Pick<PlatformGrowthBrake, 'engaged'> | undefined;
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

/** Where to send the browser once done, if anywhere: a path on this origin. */
const returnTo = (description: string) =>
  z
    .string()
    .max(512)
    // A pattern, not a refinement, so the document states the rule (B7: a scanner took any string as valid).
    .regex(RETURN_PATH, { error: 'must be a path on this origin' })
    .optional()
    .describe(description);

const SIGN_IN_SCHEMA = {
  summary: 'Start a sign-in',
  querystring: z.object({
    returnTo: returnTo('Where to go once signed in: a path on this origin. Home if none.'),
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
    returnTo: returnTo('Where to go once signed in again, to confirm the change: a path on this origin. Home if none.'),
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
    // 200 with an empty object, which the contract writes, not a 204: a 204 carries no body, and the document
    // can only describe a JSON one (B7: a scanner found the answer bare where JSON was promised).
    200: z.object({}).register(API_SCHEMAS, { description: 'Signed out, or there was no session to end.' }),
  },
};

/** The query a step-up's page comes back with when it failed at the login service's return: the challenge it was for. */
const STEP_UP_FAILED_QUERY = 'stepUpFailed';

/**
 * Why a failed step-up's page came back, where the console has its own words for it: the day's step-ups spent (TR-7),
 * or its time ran out (E6-P2).
 */
const STEP_UP_WHY_QUERY = 'stepUpWhy';
type StepUpWhy = 'spent' | 'expired';

/** The query a step-up's page comes back with to confirm its change: never kept on a failed one. */
const STEPPED_QUERY = 'stepped';

/**
 * The page a failed step-up was asked on, said failed: its own query kept
 * (its filter, `?org=`, CO5) less `?stepped=`, which would offer the change to
 * confirm, with the challenge, so the console forgets the change it kept for it.
 */
function failedStepUpPage({ returnTo, challengeId }: NonNullable<StepUpFailed['back']>, why?: StepUpWhy): string {
  const at = returnTo.indexOf('?');
  const path = at === -1 ? returnTo : returnTo.slice(0, at);
  // The rest is its query, any later `?` a part of it (URLSearchParams drops the leading one).
  const query = new URLSearchParams(at === -1 ? '' : returnTo.slice(at));
  query.delete(STEPPED_QUERY);
  query.delete(STEP_UP_WHY_QUERY);
  query.set(STEP_UP_FAILED_QUERY, challengeId);
  if (why !== undefined) query.set(STEP_UP_WHY_QUERY, why);
  return `${path}?${query.toString()}`;
}

/** Sign-out reads no body; this is the smallest limit the contract takes. */
const SIGN_OUT_BODY_LIMIT = 1;

const PUBLIC = { access: ['public'] } as const;

/**
 * The most sign-ins one network starts in a minute, across every `web` copy (TR-17): an IPv4 address or an IPv6 /48,
 * as its open flows are counted (`clientSite`), so a caller with many /64s in one /48 can't make that network's oldest
 * unfinished sign-ins give way (S208) at the address's whole rate; yet room for an office behind one address.
 */
export const SIGN_IN_STARTS = { most: 20, windowMs: 60_000 } as const;

/** How long to wait before starting again when the login service can't be reached: long enough for it to wake from zero. */
const UNAVAILABLE_RETRY_SECONDS = 15;

/** How long to wait past a person's day's sessions or step-ups (TR-7): an hour, as the oldest leave the 24 hours. */
const PERSON_SPENT_RETRY_SECONDS = 3600;

/** How long to wait while the platform chain's growth brake is on (R2-4): about an anchor check's run, which lifts it. */
const BRAKED_RETRY_SECONDS = 60;

export function registerSignIn(
  app: FastifyInstance,
  {
    signIn,
    sessionSeconds,
    loginSessions,
    logger,
    securityEvents,
    clock = systemClock,
    trust,
    copies,
    growthBrake,
  }: SignInRoutesOptions,
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  // S206 V8: each cap's refusals said at most once a minute, with how many, so a flood is a line a minute.
  const capped = capWarning(logger, clock, 'auth.sign_ins_capped', { most: MOST_OPEN_SIGN_INS });
  // S208: a network's oldest giving way, said the same way, with how many sign-ins started past its share.
  const gaveWay = capWarning(
    logger,
    clock,
    'auth.sign_ins_gave_way',
    { most: MOST_OPEN_SIGN_INS_A_NETWORK },
    'started',
  );
  // S210 TR-7: a person past their day's sessions or step-ups, said the same way.
  const sessionsSpent = personCapWarning(logger, clock, 'auth.person_sessions_spent', { most: MOST_SESSIONS_A_DAY });
  const stepUpsSpent = personCapWarning(logger, clock, 'auth.person_step_ups_spent', { most: MOST_STEP_UPS_A_DAY });
  // S210 R2-4: new sessions and step-ups refused while the platform chain's growth brake is on, said the same way.
  const brakedLine = capWarning(logger, clock, 'auth.platform_chain_braked', { most: PLATFORM_GROWTH_BRAKE });
  /** Whether the brake is on; and refused, 503 to try again a minute on: no flow begun, the flow cookie cleared. */
  const brakeOn = async (): Promise<boolean> => growthBrake !== undefined && (await growthBrake.engaged());
  const braked = (request: FastifyRequest, reply: FastifyReply) => {
    brakedLine();
    return sendErrorBody(
      reply.header('retry-after', String(BRAKED_RETRY_SECONDS)).header('set-cookie', cookie(FLOW_COOKIE, '', 'Lax', 0)),
      503,
      'SIGN_IN_UNAVAILABLE',
      request.id,
    );
  };
  /** Logs a failed sign-in, notes it as a security event, and refuses it. */
  const failed = (request: FastifyRequest, reply: FastifyReply, failure: SignInFailure, reason?: string) => {
    logger
      .child({ correlationId: request.id })
      .warn('auth.sign_in_failed', reason === undefined ? { failure } : { failure, reason });
    securityEvents.note({ kind: 'sign_in_failed', reason: failure, ip: request.ip });
    return sendErrorBody(reply, 401, 'SIGN_IN_FAILED', request.id);
  };
  const off = (request: FastifyRequest, reply: FastifyReply) => sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
  /**
   * Ends the person's sessions at the login service, where it may. Ours is
   * ended either way, and Agent X never reuses theirs, so a failure doesn't
   * undo the sign-out; it is an error, as a security control failed, and a
   * token refused is logged as LoginTokenRefused, which an alert counts.
   */
  const endLoginSessions = async (log: Logger, who: Subject) => {
    if (loginSessions === undefined) return;
    try {
      log.info('auth.login_service_signed_out', { ended: await loginSessions.endAll(who) });
    } catch (error) {
      log.error('auth.login_service_sign_out_failed', { err: error });
    }
  };
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
  /**
   * Logs a failed step-up, notes it as a security event with the person, and
   * refuses it: they stay signed in. Back from the login service, the browser
   * goes back to the change's page, saying so; at the start, a 403.
   */
  /** Back to the page a failed step-up was asked on, said failed (and why, where the console has words for it). */
  const failedPage = (reply: FastifyReply, back: NonNullable<StepUpFailed['back']>, why?: StepUpWhy) =>
    reply
      .code(302)
      .header('location', failedStepUpPage(back, why))
      .header('set-cookie', cookie(FLOW_COOKIE, '', 'Lax', 0))
      .send({});
  const stepUpFailed = (request: FastifyRequest, reply: FastifyReply, failed: StepUpFailed) => {
    const { failure, userId } = failed;
    // Past the day's step-ups the sign-in itself was sound (S210 TR-7): the cap's own line and code, no security event.
    if (failure === 'step_ups_spent') {
      if (userId !== undefined) stepUpsSpent(userId);
      if (failed.back !== undefined) return failedPage(reply, failed.back, 'spent');
      return sendErrorBody(
        reply.header('retry-after', String(PERSON_SPENT_RETRY_SECONDS)),
        429,
        'STEP_UPS_SPENT',
        request.id,
      );
    }
    logger
      .child({ correlationId: request.id })
      .warn('auth.step_up_failed', userId === undefined ? { failure } : { failure, userId });
    // Tied to no organisation: the step-up routes are a person's own, and verify none (6E1b).
    securityEvents.note({
      kind: 'sign_in_failed',
      reason: `step_up_${failure}`,
      ip: request.ip,
      ...(userId !== undefined && { userId }),
    });
    if (failed.back === undefined) return sendErrorBody(reply, 403, 'STEP_UP_FAILED', request.id);
    return failedPage(reply, failed.back, failure === 'challenge_expired' ? 'expired' : undefined);
  };

  const startLimit = createAddressCounter(
    app,
    { most: shareOfCopies(SIGN_IN_STARTS.most, copies), windowMs: SIGN_IN_STARTS.windowMs },
    trust,
    clientSite,
  );

  routes.get(
    '/v1/auth/sign-in',
    { schema: SIGN_IN_SCHEMA, config: PUBLIC, onRequest: startLimit },
    async (request, reply) => {
      if (signIn === undefined || request.method === 'HEAD') return off(request, reply);
      if (await brakeOn()) return braked(request, reply);
      let begun;
      try {
        begun = await signIn.begin(request.query.returnTo, clientSite(request.ip));
      } catch (thrown) {
        if (thrown instanceof SignInFailed && thrown.failure === 'provider_unavailable') {
          return unavailable(request, reply, thrown.message);
        }
        if (thrown instanceof SignInBusy) {
          capped();
          return sendErrorBody(
            reply.header('retry-after', String(UNAVAILABLE_RETRY_SECONDS)),
            503,
            'SIGN_IN_UNAVAILABLE',
            request.id,
          );
        }
        throw thrown;
      }
      const { url, flowId } = begun;
      if (begun.gaveWay === true) gaveWay();
      return reply
        .code(302)
        .header('location', url)
        .header('set-cookie', cookie(FLOW_COOKIE, flowId, 'Lax', FLOW_COOKIE_SECONDS))
        .send({});
    },
  );

  routes.get('/v1/auth/callback', { schema: CALLBACK_SCHEMA, config: PUBLIC }, async (request, reply) => {
    if (signIn === undefined || request.method === 'HEAD') return off(request, reply);
    const { code, state, error } = request.query;
    // The login service said no (the person cancelled, say), or the address was cut short: the flow is still taken,
    // so a step-up's browser goes back to its page (CO2), and a sign-in's is refused as before.
    const returned =
      error !== undefined || code === undefined || state === undefined
        ? { refused: error === undefined ? ('callback_incomplete' as const) : ('provider_refused' as const) }
        : { code, state };
    let done;
    try {
      done = await signIn.complete({
        flowId: cookieValue(request.headers.cookie, FLOW_COOKIE),
        previousCookie: cookieValue(request.headers.cookie, SESSION_COOKIE),
        ...returned,
      });
    } catch (thrown) {
      if (thrown instanceof StepUpFailed) return stepUpFailed(request, reply, thrown);
      if (thrown instanceof SessionsSpent) {
        sessionsSpent(thrown.userId);
        return sendErrorBody(
          reply
            .header('retry-after', String(PERSON_SPENT_RETRY_SECONDS))
            .header('set-cookie', cookie(FLOW_COOKIE, '', 'Lax', 0)),
          429,
          'RATE_LIMITED',
          request.id,
        );
      }
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
    if (await brakeOn()) return braked(request, reply);
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
      .header('set-cookie', cookie(FLOW_COOKIE, begun.flowId, 'Lax', STEP_UP_FLOW_COOKIE_SECONDS))
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
      const who = await signIn.signOut(cookieValue(request.headers.cookie, SESSION_COOKIE));
      if (who !== undefined) {
        const log = logger.child({ correlationId: request.id });
        log.info('auth.signed_out');
        await endLoginSessions(log, who);
      }
      return reply
        .code(200)
        .header('set-cookie', cookie(SESSION_COOKIE, '', 'Strict', 0))
        .send({});
    },
  );
}
