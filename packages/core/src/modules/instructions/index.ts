// The instructions module (ADR-004; PRD §3 `ProviderInstruction`; Phase 4
// B3): the one logical approved intent a spend request hands to the partner,
// made once in the hand-off's Tx A and read through its signed state.
export {
  INSTRUCTIONS,
  instructionOf,
  instructionOfRequest,
  intentHashOf,
  makeInstruction,
  type NewInstruction,
  organizationOfConsent,
  organizationOfInstruction,
} from './infrastructure/instructions.ts';
export type { InstructionsTables } from './infrastructure/tables.ts';
