// The directory module (ADR-004, ADR-005 §6): small global lookup tables of
// IDs only, for the work that runs before an organisation is known or across
// organisations. Other modules write to them only through these functions, in
// the same transaction as the tenant row an entry points to.
export { listedMembership, type MemberEntry, organizationsOf, registerMember } from './infrastructure/members.ts';
export { listedOrganizations, registerOrganization } from './infrastructure/organizations.ts';
export type { DirectoryTables } from './infrastructure/tables.ts';
