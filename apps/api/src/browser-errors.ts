// ADR-013 (browser errors): the console's own failures in a person's browser,
// sent to our API on the same origin and written to our log in the UAE, never
// to an outside error service. `POST /v1/client-errors`.
//
// Anyone may send one, signed in or not (a broken sign-in page is worth
// hearing about), so nothing in it is believed:
// - the Origin rule holds it like any write (SEC-WEB-01), and the per-address
//   rate limit counts it (ADR-011 §4);
// - the body is small and every field capped; the page is a path alone, no
//   query; the logger cleans every string (scrub.ts) and caps each event per
//   minute, counting what it holds back (volume-guard.ts);
// - from someone signed in (the session cookie names a live session) it is
//   an error, naming them, and counts toward the SEV-2 error alert; from no
//   one, a warning of its own event, in the daily summary only, so a
//   stranger's forged reports can't set the alert off (partner, S150), nor
//   fill a signed-in report's per-minute cap. A broken sign-in page is still
//   heard about, a day later at most. Looking the session up doesn't count as
//   using it, so an erroring tab left alone still times out.
//
// The answer is the same whatever happens to the line, so a sender learns
// nothing from it.
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { isPagePath } from './console-files.ts';
import { cookieValue, SESSION_COOKIE } from './sign-in.ts';

export const BROWSER_ERROR = 'console.browser_error';
export const ANONYMOUS_BROWSER_ERROR = 'console.browser_error_anonymous';

/** Room for the fields' caps below, and no more. */
const BROWSER_ERROR_BODY_LIMIT = 8 * 1024;

const BODY = z
  .strictObject({
    kind: z
      .enum(['error', 'rejection', 'render'])
      .describe('What failed: a script error, a promise nothing caught, or a screen that could not be drawn.'),
    message: z.string().min(1).max(500).describe("The error's own message."),
    page: z
      .string()
      .max(200)
      .refine(isPagePath, { error: 'must be a console page' })
      .describe('The console page it happened on: its path, no query.'),
    stack: z.string().max(4000).optional().describe('Where in the console’s code, if the browser said.'),
    build: z
      .string()
      .max(64)
      .regex(/^[A-Za-z0-9._-]+$/)
      .optional()
      .describe('The console build that was running.'),
  })
  .describe('One error in the console, as the browser saw it.');

const SCHEMA = {
  summary: 'Report an error in the console',
  description:
    'Written to Agent X’s own log in the UAE (ADR-013). The answer is the same whether or not the line was written.',
  body: BODY,
  response: { 202: z.object({}).describe('Taken.') },
};

/** Who holds the live session a cookie names, if any, without that counting as its use (SignIn.holderOf). */
export type HolderOf = (cookie: string) => Promise<string | undefined>;

/** Who sent it: their user ID if signed in; none for no one, or a session that can't be read just now. */
async function senderOf(cookie: string | undefined, holderOf: HolderOf | undefined): Promise<string | undefined> {
  if (cookie === undefined || holderOf === undefined) return undefined;
  try {
    return await holderOf(cookie);
  } catch {
    // The report still goes in, as no one's: it must never fail for the session's sake.
    return undefined;
  }
}

export function registerBrowserErrors(app: FastifyInstance, logger: Logger, holderOf: HolderOf | undefined): void {
  app
    .withTypeProvider<ZodTypeProvider>()
    .post(
      '/v1/client-errors',
      { schema: SCHEMA, bodyLimit: BROWSER_ERROR_BODY_LIMIT, config: { access: ['public'] } },
      async (request, reply) => {
        const sender = await senderOf(cookieValue(request.headers.cookie, SESSION_COOKIE), holderOf);
        if (sender === undefined)
          logger.child({ correlationId: request.id }).warn(ANONYMOUS_BROWSER_ERROR, request.body);
        else logger.child({ correlationId: request.id, actor: sender }).error(BROWSER_ERROR, request.body);
        return reply.code(202).send({});
      },
    );
}
