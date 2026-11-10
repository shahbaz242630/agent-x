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
