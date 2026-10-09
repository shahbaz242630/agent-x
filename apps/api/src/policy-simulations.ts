// The policy simulator (PRD §5.2; BR-07; SEC-AG-09; partner decision 9,
// S96; Phase 2 C4): what a request by a mandate's agent would get now, from
// the very engine and totals a real request is decided by (decideAndReserve's
// `weigh`), with nothing made: no request, reservation, claim, agent month or
// idempotency record, no partner call. Read in one transaction, its rows held
// FOR SHARE only until it ends.
//
// - Who (decision 9): admins, approvers and developers; agents later, through
//   the MCP tools with a limit, as a free simulator would let an agent find
//   the approval line it is never shown (B5).
// - What: the mandate's agent as things stand (its mandate in force, both
//   policies, its month's total), and "what if": proposed rules for the
//   organisation's policy, the mandate's, or both, in place of those in force,
//   so an admin sees a change's effect before making it. A proposed mandate
//   policy applies only to the mandate in force, and only one that change
//   could make: never wider than the mandate (POLICY_WIDER_THAN_MANDATE).
// - The answer: the decision and its reasons; the versions weighed; the
//   agent's month and what it holds or spent in it; whether proposed rules
//   were weighed. A request naming an order is checked for a duplicate too.
import { agentMonth } from '@agentx/core/modules/limit-reservations';
import { agentOfMandate, type PolicyRules as Rules, widerThanMandate } from '@agentx/core/modules/mandates';
import { decide, type DecisionMade } from '@agentx/core/modules/policies';
import type { Clock, IdGenerator, Money } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { MandateRefused } from './mandate-reads.ts';
import type { Refused } from './refused.ts';
import {
  agentIn,
  currencyTaken,
  type DecisionTables,
  type MandateWeighed,
  type PoliciesWeighed,
  type SpendWeighed,
  weigh,
} from './spend-request-decisions.ts';
import { createUseCaseWork } from './use-case-work.ts';

/** Who may simulate (decision 9): the organisation's team, never a viewer or an agent. */
export const SIMULATING_ROLES = ['admin', 'approver', 'developer'] as const;

/** The version a proposed policy is weighed as: none was made. */
const PROPOSED = 'proposed';

/** Rules to weigh in place of those in force: either policy, or both. */
export interface WhatIf {
  readonly organizationPolicy?: Rules | undefined;
  readonly mandatePolicy?: Rules | undefined;
}

export interface Simulated {
  readonly outcome: 'simulated';
  readonly made: DecisionMade;
  /** The mandate weighed: the agent's in force, or null for none. */
  readonly mandateId: string | null;
  /** The agent's month (`YYYY-MM`), or null without a mandate in force. */
  readonly month: string | null;
  readonly monthSpent: Money;
  readonly proposed: { readonly organizationPolicy: boolean; readonly mandatePolicy: boolean };
}

export interface PolicySimulations {
  simulate(
    orgId: string,
    mandateId: string,
    asked: SpendWeighed,
    whatIf: WhatIf,
    correlationId: string,
  ): Promise<Simulated | Refused>;
}

/** A proposed policy as the engine weighs it. */
const proposedRules = (rules: Rules) => ({ ...rules, versionId: PROPOSED });

/**
 * The policies to weigh: those in force, each replaced by its proposed rules.
 * A proposed mandate policy needs the mandate asked about in force, and must
 * be one its change could make.
 */
const policiesFor =
  (mandateId: string, whatIf: WhatIf) =>
  (inForce: PoliciesWeighed, mandate: MandateWeighed | null): PoliciesWeighed => {
    const { organizationPolicy, mandatePolicy } = whatIf;
    if (mandatePolicy !== undefined) {
      if (mandate?.id !== mandateId) throw new MandateRefused(409, 'MANDATE_NOT_IN_FORCE');
      if (widerThanMandate(mandatePolicy, mandate).length > 0) {
        throw new MandateRefused(409, 'POLICY_WIDER_THAN_MANDATE');
      }
    }
    return {
      organizationPolicy:
        organizationPolicy === undefined ? inForce.organizationPolicy : proposedRules(organizationPolicy),
      mandatePolicy: mandatePolicy === undefined ? inForce.mandatePolicy : proposedRules(mandatePolicy),
    };
  };

export function createPolicySimulations({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Database<DecisionTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): PolicySimulations {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: MandateRefused });

  return {
    simulate: (orgId, mandateId, asked, whatIf, correlationId) =>
      work.answered(orgId, correlationId, async (tx, states) => {
        const now = clock.now();
        await currencyTaken(tx, asked.amount.currency);
        // The organisation's own mandates alone, by its tenant wall.
        const agentId = await agentOfMandate(tx, orgId, mandateId);
        if (agentId === undefined) throw new MandateRefused(404, 'NOT_FOUND');
        const agent = await agentIn(tx, states, { orgId, agentId });
        const { input, mandate, month } = await weigh(tx, states, orgId, agent, asked, {
          now,
          decides: false,
          monthOf: (zoneIfNew) => agentMonth(tx, { agentId, zoneIfNew, at: now }),
          rules: policiesFor(mandateId, whatIf),
        });
        return {
          outcome: 'simulated' as const,
          made: decide(input),
          mandateId: mandate?.id ?? null,
          month,
          monthSpent: input.monthSpent,
          proposed: {
            organizationPolicy: whatIf.organizationPolicy !== undefined,
            mandatePolicy: whatIf.mandatePolicy !== undefined,
          },
        };
      }),
  };
}
