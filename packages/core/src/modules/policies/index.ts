// The policies module (ADR-004, PRD §5.2; Phase 2 C): the decision engine,
// pure, owning no tables. Its inputs are read by the modules that own them
// (the policies' rules by mandates, C1) and passed in.
export {
  type Decision,
  type DecisionInput,
  decisionInputText,
  type DecisionMade,
  DECISIONS,
  decide,
  DEFAULT_MONTHLY_CAP,
  type MandateInForce,
  monthlyCapOf,
  type MonthlyCapFrom,
  type OverCap,
  type PolicyRules,
  type SpendAsked,
} from './domain/decide.ts';
