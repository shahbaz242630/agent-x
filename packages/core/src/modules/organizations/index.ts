// The organizations module (ADR-004, ADR-005 §1): each organisation's own row,
// its tenant boundary, and what limits it (its status: a freeze). The row is
// an authority table, read and changed only through its signed state
// (ADR-012 §2). An organisation is created by the operator's command
// (apps/operator, B1c).
export { ORGANIZATION, OrganizationRefused, organizationName } from './domain/organization.ts';
export { createOrganization, ORGANIZATIONS } from './infrastructure/organizations.ts';
export type { OrganizationsTables } from './infrastructure/tables.ts';
