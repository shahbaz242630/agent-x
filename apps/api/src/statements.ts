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
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

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
export const SERVED_STATEMENTS: readonly Statement[] = [
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
];

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

export function registerStatements(app: FastifyInstance): void {
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
