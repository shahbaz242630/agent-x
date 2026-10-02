import type { ReasonCode } from '@agentx/core/shared-kernel';

/** A refusal, as a use case answers it. */
export interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}
