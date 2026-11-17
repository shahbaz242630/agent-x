import type { ReasonCode } from '@agentx/core/shared-kernel';

/** A refusal, as a use case answers it. */
export interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}

export const refused = (status: number, code: ReasonCode): Refused => ({ outcome: 'refused', status, code });

/** A step-up asked for, as a use case answers it: the challenge its confirm is to name. */
export interface StepUpAsked {
  readonly outcome: 'asked';
  readonly stepUpChallengeId: string;
}

/**
 * An agent's operation answered (6E2, BR-20): the body its route sends, or why not. Its REST route and its MCP tool
 * (mcp-tools.ts) both run the one operation, so the two can't answer differently.
 */
export type AgentAnswer<Body> =
  { readonly outcome: 'answered'; readonly body: Body } | Refused | { readonly outcome: 'conflict' | 'busy' };

/** An operation's body, answered. */
export const answered = <Body>(body: Body): { readonly outcome: 'answered'; readonly body: Body } => ({
  outcome: 'answered',
  body,
});
