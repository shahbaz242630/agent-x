// The organizations module (ADR-004, ADR-005 §1): each organisation's own row,
// its tenant boundary, and what limits it (its status: a freeze). The row is
// an authority table, read and changed only through its signed state
// (ADR-012 §2). Creating one joins this interface with the operator's command
// (B1c), its first caller.
export { ORGANIZATION } from './domain/organization.ts';
export { ORGANIZATIONS } from './infrastructure/organizations.ts';
