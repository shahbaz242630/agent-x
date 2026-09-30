// A payment consent on the UAE Open Finance rail (rail map §2 and §3; the
// standard's `AEConsentStatus` at a3c8b8b), as an adapter for that rail reads
// it. The partner's word is kept as it is, for evidence (PRD §6.2
// `consentStatus`); what Agent X acts on is the source's availability, never
// the rail's word (PRD §2.3 step 5, §6).
import type { SourceAvailability } from './rail.ts';

export const CONSENT_STATUSES = [
  'AwaitingAuthorization',
  'Authorized',
  'Rejected',
  'Revoked',
  'Expired',
  'Consumed',
  'Suspended',
] as const;
export type ConsentStatus = (typeof CONSENT_STATUSES)[number];

const AVAILABILITY: Readonly<Record<ConsentStatus, SourceAvailability>> = {
  AwaitingAuthorization: 'PENDING',
  Authorized: 'ACTIVE',
  Suspended: 'SUSPENDED',
  Rejected: 'UNAVAILABLE',
  Revoked: 'UNAVAILABLE',
  Expired: 'UNAVAILABLE',
  Consumed: 'UNAVAILABLE',
};

/** The availability a consent status gives its source. */
export const availabilityOf = (status: ConsentStatus): SourceAvailability => AVAILABILITY[status];

/**
 * The moves the standard's lifecycle table allows (Pending, In Use,
 * Terminal): a consent waits for the bank, is authorised or rejected there,
 * may be suspended "pending further enquiries" and come back, and ends
 * revoked, expired or consumed. A terminal status is never left.
 */
const MOVES: Readonly<Record<ConsentStatus, readonly ConsentStatus[]>> = {
  AwaitingAuthorization: ['Authorized', 'Rejected', 'Expired'],
  Authorized: ['Suspended', 'Revoked', 'Expired', 'Consumed'],
  Suspended: ['Authorized', 'Revoked', 'Expired'],
  Rejected: [],
  Revoked: [],
  Expired: [],
  Consumed: [],
};

/** Whether the rail lets a consent go from one status to the other. */
export const consentMayMove = (from: ConsentStatus, to: ConsentStatus): boolean => MOVES[from].includes(to);
