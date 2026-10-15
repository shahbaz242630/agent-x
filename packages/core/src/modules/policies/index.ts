// The policies module (ADR-004, PRD §5.2; Phase 2 C): the decision engine,
// pure, owning no tables. Its inputs are read by the modules that own them
// (the policies' rules by mandates, C1) and passed in.
export {
  type Decision,
  type DecisionInput,
  decisionFacts,
  decisionInputText,
  type DecisionMade,
  DECISIONS,
  decide,
  MONTHLY_CAP_FROM,
  type MandateInForce,
  monthlyCapOf,
  type MonthlyCapFrom,
  type OverCap,
  type PolicyRules,
  reasonsShownToAgent,
  type SpendAsked,
} from './domain/decide.ts';
