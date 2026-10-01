// The fake partner's bank, on staging (ADR-014 §4; Phase 1 D2-3c): the steps
// a business takes at its bank, outside Agent X, played here so a link can be
// approved or turned down without a real bank. They answer only where the
// payment partner is the fake (config.partner), which production refuses;
// anywhere else each answers 404 NOT_FOUND.
//
// - `GET /v1/fake-bank/accounts`: the sandbox's business accounts the bank
//   offers, each its ID at the bank and the safe summary. Admins.
// - `POST /v1/fake-bank/sessions/:sessionRef/approve`: the business approves
//   the link waiting under the session (the last part of the link's
//   `authoriseUrl`) with one of those accounts. Admins.
// - `POST /v1/fake-bank/sessions/:sessionRef/reject`: turns it down. Admins.
// - `POST /v1/fake-bank/payee-forms`: an admin fills in the partner's payee
//   form (E2-2a) at the `url` a registration's start answered, with a
//   supplier's name and IBAN: the partner then holds the payee, masked, and
//   Agent X learns of it only from its own check, server to server. The IBAN
//   reaches no store of Agent X's: the fake keeps its masked parts alone, and
//   the request is logged without its body.
//
// Each step acts only for the caller's organisation: another's session is
// found as none is (SEC-PTR-08). Agent X believes none of it until its own
// confirm asks the partner, server to server. The steps stand in for the
// bank, not for Agent X, so they keep nothing of their own: a repeat is
// answered from the bank's state (409 BANK_LINK_NOT_WAITING once the session
// is approved or turned down), not from the idempotency key the contract asks
// every write for.
import { type FakeBank, FakeBankRefused } from '@agentx/core/modules/providers';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';

/** Approving a link at the bank. */
const BANK_APPROVE_OPERATION = 'fake-bank.approve';
/** Turning it down there. */
const BANK_REJECT_OPERATION = 'fake-bank.reject';
/** Filling in the partner's payee form. */
const BANK_FORM_OPERATION = 'fake-bank.payee-form';

/** The roles that may play the business at its bank: the admins who start and confirm its links. */
const BANK_ROLES = ['admin'] as const;

/** The most a step's body may be: an account's ID and a flag, with room to spare. */
const STEP_BODY_LIMIT = 256;
/**
 * The most a form's body may be: a form's address of at most 200 ASCII
 * characters, a name of at most 140 UTF-16 units, each sent as a `\uXXXX`
 * escape (6 bytes), and an IBAN of at most 64; with room to spare.
 */
const FORM_BODY_LIMIT = 2048;

const ACCOUNT_ID = z
  .string()
  .regex(/^[a-z0-9-]{1,64}$/)
  .describe('The account’s ID at the bank, as the accounts list gives it.');

const ACCOUNTS_SCHEMA = {
  summary: 'The accounts the fake partner’s bank offers (staging only)',
  response: {
    200: z
      .object({
        accounts: z.array(
          z
            .object({
              accountId: ACCOUNT_ID,
              holderName: z.string().describe('The account holder, as the bank names it.'),
              accountType: z.enum(['retail', 'sme', 'corporate']).describe('What kind of account it is.'),
              currency: z.string().describe('The account’s currency.'),
              hint: z.string().describe('The country and the last four characters of the account number.'),
            })
            .register(API_SCHEMAS, {
              id: 'FakeBankAccount',
              description: 'A sandbox business account at the fake bank: never its number.',
            }),
        ),
      })
      .describe('Every account the bank offers.'),
  },
};

const SESSION = z.object({
  sessionRef: z
    .string()
    .regex(/^[A-Za-z0-9-]{1,80}$/)
    .describe('The link’s session at the partner: the last part of its authoriseUrl.'),
});

const DONE = (status: 'approved' | 'rejected') =>
  z.object({ status: z.literal(status).describe('What the bank did.') }).describe(`The link, ${status} at the bank.`);

const APPROVE_SCHEMA = {
  summary: 'Approve a link at the fake partner’s bank (staging only; a retry answers 409 once done)',
  params: SESSION,
  body: z.strictObject({
    accountId: ACCOUNT_ID,
    awaitingOtherAuthorisers: z
      .boolean()
      .optional()
      .describe('The bank waits for another authoriser, so the source is linked but pending. False unless given.'),
  }),
  response: { 200: DONE('approved') },
};

const REJECT_SCHEMA = {
  summary: 'Turn a link down at the fake partner’s bank (staging only; a retry answers 409 once done)',
  params: SESSION,
  body: z
    .strictObject({})
    // Fastify gives a request sent with no body a null one.
    .nullish()
    .describe('Nothing. An empty object, or no body at all.'),
  response: { 200: DONE('rejected') },
};

const FORM_SCHEMA = {
  summary: 'Fill in the fake partner’s payee form with a supplier’s bank details (staging only)',
  body: z.strictObject({
    url: z
      .string()
      .max(200)
      .regex(/^[!-~]+$/)
      .describe('The form’s address, as the registration’s start answered it.'),
    name: z.string().max(140).describe('The account holder’s name.'),
    iban: z
      .string()
      .max(64)
      .regex(/^[A-Za-z0-9 ]+$/)
      .describe('The account’s IBAN: a UAE one, spaces allowed.'),
  }),
  response: {
    200: z
      .object({ status: z.literal('filled').describe('What the form did.') })
      .describe('The form, filled in: check the registration to learn how the partner holds it.'),
  },
};

/** The caller's organisation: the access hook lets only its members through. */
function orgOf(request: FastifyRequest): string {
  if (request.member === null) throw new Error('a fake-bank route ran without a member');
  return request.member.orgId;
}

/** Each refusal of the bank's or its form's, as the routes answer it. */
const BANK_REFUSALS = {
  no_such_account: [400, 'BANK_ACCOUNT_UNKNOWN'],
  no_link_waiting: [409, 'BANK_LINK_NOT_WAITING'],
  no_form_open: [409, 'BANK_FORM_NOT_OPEN'],
  details_refused: [400, 'BANK_FORM_REFUSED'],
} as const;

/** The bank's refusal answered; anything else thrown again. */
function refusedAtBank(error: unknown, request: FastifyRequest, reply: FastifyReply) {
  if (!(error instanceof FakeBankRefused)) throw error;
  const [status, code] = BANK_REFUSALS[error.reason];
  return sendErrorBody(reply, status, code, request.id);
}

/** The routes. `bank` is the fake's, where the partner is the fake; without it they are documented and answer 404. */
export function registerFakeBank(app: FastifyInstance, { bank }: { bank: FakeBank | undefined }) {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get(
    '/v1/fake-bank/accounts',
    { schema: ACCOUNTS_SCHEMA, config: { access: [...BANK_ROLES] } },
    async (request, reply) => {
      orgOf(request);
      if (bank === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      return reply.send({
        accounts: bank.accounts().map(({ accountId, summary }) => ({ accountId, ...summary })),
      });
    },
  );

  routes.post(
    '/v1/fake-bank/sessions/:sessionRef/approve',
    {
      schema: APPROVE_SCHEMA,
      bodyLimit: STEP_BODY_LIMIT,
      config: { access: [...BANK_ROLES], operation: BANK_APPROVE_OPERATION },
    },
    async (request, reply) => {
      const orgId = orgOf(request);
      if (bank === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      const { accountId, awaitingOtherAuthorisers = false } = request.body;
      try {
        await bank.approve(orgId, request.params.sessionRef, accountId, { awaitingOtherAuthorisers });
      } catch (error) {
        return refusedAtBank(error, request, reply);
      }
      return reply.send({ status: 'approved' as const });
    },
  );

  routes.post(
    '/v1/fake-bank/sessions/:sessionRef/reject',
    {
      schema: REJECT_SCHEMA,
      bodyLimit: STEP_BODY_LIMIT,
      config: { access: [...BANK_ROLES], operation: BANK_REJECT_OPERATION },
    },
    async (request, reply) => {
      const orgId = orgOf(request);
      if (bank === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      try {
        await bank.reject(orgId, request.params.sessionRef);
      } catch (error) {
        return refusedAtBank(error, request, reply);
      }
      return reply.send({ status: 'rejected' as const });
    },
  );

  routes.post(
    '/v1/fake-bank/payee-forms',
    {
      schema: FORM_SCHEMA,
      bodyLimit: FORM_BODY_LIMIT,
      config: { access: [...BANK_ROLES], operation: BANK_FORM_OPERATION },
    },
    async (request, reply) => {
      const orgId = orgOf(request);
      if (bank === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      const { url, name, iban } = request.body;
      try {
        await bank.fillForm(orgId, url, { name, iban });
      } catch (error) {
        return refusedAtBank(error, request, reply);
      }
      return reply.send({ status: 'filled' as const });
    },
  );
}
