// The words every choice and change is confirmed with (6A2, Rule Book §1.9),
// served to the console: `GET /v1/statements`. Each set is the same constant
// its use case states in the API's own description and whose version its
// signed event keeps, so the console's confirm shows exactly the words the
// event names, never a copy that could drift. A set's words are by choice
// (`cancel`, `pause`…) or, for a change with no choice, `confirm` alone; the
// answer lists them, as the contract allows no map of open-ended keys.
//
// Signed-in people only: the words aren't secret (the contract states them),
// but nothing else the console reads is open to anyone.
//
// CO3 (Rule Book §1.9): each change confirmed with a set sends back the
// version it was shown (`statementVersion`, or the policy change's own field
// a choice), and a route naming its set (`config.statements`) refuses one the
// API no longer confirms with, or none, 409 STATEMENT_CHANGED, before the use
// case runs: the person reads the words again. So the version the signed
// event keeps is always the one the person was shown. Checked before the
// body's schema (preValidation), so a tab older than the field hears the same.
import type { FastifyInstance, RouteOptions } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { ContractBroken } from './contract.ts';
import { sendErrorBody } from './errors.ts';
import { APPROVAL_WAIT_STATEMENT, APPROVAL_WAIT_STATEMENT_VERSION } from './approval-wait-choice.ts';
import { CONSENT_EXPIRY_STATEMENTS, CONSENT_EXPIRY_STATEMENT_VERSION } from './consent-expiry-choice.ts';
import { OLD_KEY_STATEMENTS, OLD_KEY_STATEMENT_VERSION } from './key-rotation-choice.ts';
import { SUPERSEDE_STATEMENTS, SUPERSEDE_STATEMENT_VERSION } from './mandate-carry.ts';
import { MONTHLY_CAP_STATEMENTS, MONTHLY_CAP_STATEMENT_VERSION } from './monthly-cap-choice.ts';
import { OVER_LIMIT_STATEMENTS, OVER_LIMIT_STATEMENT_VERSION } from './over-limit-choice.ts';
import { MARK_FAILED_STATEMENT, MARK_FAILED_STATEMENT_VERSION } from './payment-marks.ts';
import { WAITING_STATEMENTS, WAITING_STATEMENT_VERSION } from './policy-waiting.ts';
import { RECHECK_STATEMENT, RECHECK_STATEMENT_VERSION } from './spend-request-approvals.ts';
import {
  DETAILS_STATEMENT_VERSION,
  DETAILS_STATEMENTS,
  FREEZE_STATEMENT_VERSION,
  FREEZE_STATEMENTS,
  PAYEE_STATEMENT_VERSION,
  PAYEE_STATEMENTS,
  REACTIVATE_STATEMENT_VERSION,
  REACTIVATE_STATEMENTS,
  STATEMENT_VERSION as SUSPEND_STATEMENT_VERSION,
  STATEMENTS as SUSPEND_STATEMENTS,
  UNFREEZE_STATEMENT_VERSION,
  UNFREEZE_STATEMENTS,
} from './suspensions.ts';

interface Statement {
  readonly id: string;
  readonly version: number;
  readonly words: Readonly<Record<string, string>>;
}

/** Every set, by the id the console asks for it by. */
export const SERVED_STATEMENTS = [
  { id: 'suspend', version: SUSPEND_STATEMENT_VERSION, words: SUSPEND_STATEMENTS },
  { id: 'reactivate', version: REACTIVATE_STATEMENT_VERSION, words: REACTIVATE_STATEMENTS },
  { id: 'freeze', version: FREEZE_STATEMENT_VERSION, words: FREEZE_STATEMENTS },
  { id: 'unfreeze', version: UNFREEZE_STATEMENT_VERSION, words: UNFREEZE_STATEMENTS },
  { id: 'payee', version: PAYEE_STATEMENT_VERSION, words: PAYEE_STATEMENTS },
  { id: 'supplier_details', version: DETAILS_STATEMENT_VERSION, words: DETAILS_STATEMENTS },
  { id: 'consent_expiry', version: CONSENT_EXPIRY_STATEMENT_VERSION, words: CONSENT_EXPIRY_STATEMENTS },
  { id: 'old_key', version: OLD_KEY_STATEMENT_VERSION, words: OLD_KEY_STATEMENTS },
  { id: 'supersede', version: SUPERSEDE_STATEMENT_VERSION, words: SUPERSEDE_STATEMENTS },
  { id: 'monthly_cap', version: MONTHLY_CAP_STATEMENT_VERSION, words: MONTHLY_CAP_STATEMENTS },
  { id: 'over_limit', version: OVER_LIMIT_STATEMENT_VERSION, words: OVER_LIMIT_STATEMENTS },
  { id: 'waiting_requests', version: WAITING_STATEMENT_VERSION, words: WAITING_STATEMENTS },
  { id: 'approval_wait', version: APPROVAL_WAIT_STATEMENT_VERSION, words: { confirm: APPROVAL_WAIT_STATEMENT } },
  { id: 'mark_failed', version: MARK_FAILED_STATEMENT_VERSION, words: { confirm: MARK_FAILED_STATEMENT } },
  { id: 'recheck', version: RECHECK_STATEMENT_VERSION, words: { confirm: RECHECK_STATEMENT } },
] as const satisfies readonly Statement[];

/** A set, by the id the console asks for it by. */
export type StatementId = (typeof SERVED_STATEMENTS)[number]['id'];

/** The version of each set's words the API confirms changes with now. */
const VERSIONS: ReadonlyMap<string, number> = new Map(SERVED_STATEMENTS.map(({ id, version }) => [id, version]));

/** One set a route's change is confirmed with: the body's field sending its version back. */
export interface StatementConfirmed {
  readonly id: StatementId;
  /** The field: `statementVersion`, or the policy change's own one a choice. */
  readonly field: string;
  /** The choice it is for, when it is optional: the version is needed only with it. Always needed without. */
  readonly with?: string;
}

declare module 'fastify' {
  interface FastifyContextConfig {
    /** The words the route's change is confirmed with (CO3): a version not the API's now is refused. */
    readonly statements?: readonly StatementConfirmed[];
  }
}

/** A change confirmed with one set of words, always: its version sent back as `statementVersion`. */
export const confirmedWith = (id: StatementId): readonly StatementConfirmed[] => [{ id, field: 'statementVersion' }];

/** The body's field sending back the version of `id`'s words the person was shown and confirmed. */
export const statementVersion = (id: StatementId) =>
  z
    .int()
    .positive()
    .describe(
      `The version of the \`${id}\` words (GET /v1/statements) the person was shown and confirmed, kept on the ` +
        'change’s signed event. Any other than the version the API confirms with now, or none, is refused 409 ' +
        'STATEMENT_CHANGED: show them the words again.',
    );

/**
 * A body's version for an optional choice (a refinement): given with the
 * choice and only with it, as no words are shown without one.
 */
export const versionWithChoice =
  (choice: string, field = 'statementVersion') =>
  (body: Readonly<Record<string, unknown>>, context: z.RefinementCtx): void => {
    if ((body[choice] === undefined) !== (body[field] === undefined)) {
      context.addIssue({ code: 'custom', path: [field], message: `${field} comes with ${choice}, and only with it` });
    }
  };

/** A field naming a version of words: a body holding one must name its set, or it would go unchecked. */
const VERSION_FIELD = /^(?:statementVersion|\w+StatementVersion)$/;

/** A body's fields: an object's, or those of the object a transform reads. */
const fieldsOf = (body: unknown): readonly string[] => {
  if (body instanceof z.ZodPipe) return fieldsOf(body.in);
  return body instanceof z.ZodObject ? Object.keys(body.shape) : [];
};

/** Why a route's statements can't stand: each field named is in its body, and each version field in its body named. */
export function statementProblems(route: Pick<RouteOptions, 'url' | 'schema' | 'config'>): string[] {
  const named = route.config?.statements ?? [];
  const fields = fieldsOf(route.schema?.body);
  const problems = named.flatMap(({ field, with: choice }) =>
    [field, ...(choice === undefined ? [] : [choice])]
      .filter((name) => !fields.includes(name))
      .map((name) => `${route.url}: its statements name ${name}, which its body doesn't hold`),
  );
  for (const field of fields.filter((name) => VERSION_FIELD.test(name))) {
    if (!named.some((statement) => statement.field === field)) {
      problems.push(
        `${route.url}: its body's ${field} names no set of words (config.statements), so it goes unchecked`,
      );
    }
  }
  return problems;
}

/** A field of a body not yet checked, as sent: undefined for none, or no object. */
const sentIn = (body: unknown, field: string): unknown =>
  typeof body === 'object' && body !== null && Object.hasOwn(body, field)
    ? (body as Readonly<Record<string, unknown>>)[field]
    : undefined;

/** Whether a body sends back a version of each set other than the API's now, or none where one is needed. */
export function isStale(named: readonly StatementConfirmed[], body: unknown): boolean {
  return named.some(({ id, field, with: choice }) => {
    const sent = sentIn(body, field);
    const needed = choice === undefined || sentIn(body, choice) !== undefined;
    return (needed || sent !== undefined) && sent !== VERSIONS.get(id);
  });
}

const STATEMENTS_SCHEMA = {
  summary: 'The words each choice and change is confirmed with',
  response: {
    200: z
      .object({
        statements: z.array(
          z.object({
            id: z.string().describe('The set, as the console asks for it: `freeze`, `mark_failed`…'),
            version: z.int().describe('The version of its words, which the signed event of a confirmed change keeps.'),
            words: z
              .array(
                z.object({
                  choice: z.string().describe('The choice (`cancel`, `pause`…), or `confirm` for a change with none.'),
                  text: z.string().describe('The words the person confirms it with.'),
                }),
              )
              .describe('The words, one entry a choice.'),
          }),
        ),
      })
      .describe('Every set of words, at the version the API confirms changes with now.'),
  },
};

/**
 * The statements route, and the check of each confirm's version: before any
 * route naming statements is added (server.ts adds them all after this).
 */
export function registerStatements(app: FastifyInstance): void {
  app.addHook('onRoute', (route) => {
    const problems = statementProblems(route);
    if (problems.length > 0) throw new ContractBroken(problems);
  });
  app.addHook('preValidation', async (request, reply) => {
    const named = request.routeOptions.config.statements;
    if (named !== undefined && isStale(named, request.body)) {
      return sendErrorBody(reply, 409, 'STATEMENT_CHANGED', request.id);
    }
    return undefined;
  });
  app
    .withTypeProvider<ZodTypeProvider>()
    .get('/v1/statements', { schema: STATEMENTS_SCHEMA, config: { access: ['person'] } }, () => ({
      statements: SERVED_STATEMENTS.map(({ id, version, words }) => ({
        id,
        version,
        words: Object.entries(words).map(([choice, text]) => ({ choice, text })),
      })),
    }));
}
