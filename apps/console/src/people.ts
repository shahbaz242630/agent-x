// The organisation's people and who vouches for them (6D4b; BR-01, BR-02):
// its members and their roles (GET /v1/members: by Agent X IDs, never names),
// invitations to join, its registered contacts (GET /v1/registered-contacts:
// the trust anchor told of the changes that matter) and resets of a member's
// lost second factor (GET /v1/factor-resets). What each reads, the API's own
// rules checked before anything is sent, and each refusal in plain words. The
// roles only decide what shows; the API checks again whatever is pressed.
import { useQuery } from '@tanstack/react-query';

import { api, isIntegrityFailed, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import type { Role } from './session.tsx';
import type { TextKey } from './text.ts';
import { t } from './text.ts';

/** The four roles, in the order the API names them: offered so, none picked. */
export const ROLES: readonly Role[] = ['admin', 'approver', 'developer', 'viewer'];

export interface Invitation {
  readonly id: string;
  readonly role: Role;
  readonly status: 'DRAFT' | 'OPEN' | 'AWAITING_CONFIRMATION' | 'ACCEPTED' | 'DECLINED';
  readonly expiresAt: string;
}

export interface Contact {
  readonly id: string;
  readonly email: string;
  readonly status: 'DRAFT' | 'ACTIVE' | 'REMOVED';
  /** When it starts to count: 7 days after it was confirmed; null for a draft. */
  readonly countsFrom: string | null;
  readonly counts: boolean;
}

export type ResetStatus = 'DRAFT' | 'AWAITING_CONTACT' | 'COOLING_OFF' | 'COMPLETED' | 'CANCELLED' | 'EXPIRED';

export interface Reset {
  readonly id: string;
  readonly status: ResetStatus;
  /** The membership whose second factor it resets. */
  readonly person: string;
  /** The membership of the admin who asked. */
  readonly requestedBy: string;
  readonly expiresAt: string;
  readonly confirmedBy: string | null;
  readonly coolingOffUntil: string | null;
}

/** The statuses a reset may still be cancelled in, as the API's own (FACTOR_RESET's cancel). */
const CANCELLABLE: readonly ResetStatus[] = ['DRAFT', 'AWAITING_CONTACT', 'COOLING_OFF'];
export const isCancellable = (reset: Reset): boolean => CANCELLABLE.includes(reset.status);

/** The organisation's ACTIVE registered contacts: an admin's alone to read. */
export function useContacts(organization: string) {
  return useQuery({
    queryKey: ['contacts', organization],
    queryFn: () => api.get<{ readonly contacts: readonly Contact[] }>('/v1/registered-contacts', { organization }),
    select: ({ contacts }) => contacts,
  });
}

/** Every reset of the organisation's members' second factors, open or not: an admin's alone to read. */
export function useResets(organization: string, enabled = true) {
  return useQuery({
    queryKey: ['factor-resets', organization],
    enabled,
    queryFn: () => api.get<{ readonly resets: readonly Reset[] }>('/v1/factor-resets', { organization }),
    select: ({ resets }) => resets,
  });
}

/** The most an email address may be, as the API takes it (EMAIL_MAX). */
export const EMAIL_MOST = 254;
/** The API's own check of an address (its schema's email()), word for word. */
const EMAIL = /^(?:[\w'+-]+\.)*[\w'+-]*[\w+-]@(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}$/;
/** Whether an address keeps the API's rules: checked before anything is sent; the API checks again. */
export const isEmail = (typed: string): boolean => typed.length <= EMAIL_MOST && EMAIL.test(typed);

/**
 * Where a draft's ask says to confirm it: `<base>/<id>/confirm`, by the ID of
 * the draft its answer holds under `field`, while it is a DRAFT; none for any
 * other answer, which then names no step-up to sign in again for.
 */
export const draftConfirm =
  (field: 'invitation' | 'contact' | 'reset', base: string) =>
  (answer: unknown): string | undefined => {
    if (typeof answer !== 'object' || answer === null || !(field in answer)) return undefined;
    const draft: unknown = (answer as Readonly<Record<string, unknown>>)[field];
    if (typeof draft !== 'object' || draft === null || !('id' in draft) || !('status' in draft)) return undefined;
    const { id, status } = draft;
    return typeof id === 'string' && isUuid(id) && status === 'DRAFT'
      ? `${base}/${encodeURIComponent(id)}/confirm`
      : undefined;
  };

/** The gates any of these changes can meet, before its own rules: the same words in every area. */
const GATES: Readonly<Record<string, TextKey>> = {
  STEP_UP_NOT_ASKED: 'members.gate.STEP_UP_NOT_ASKED',
  PASSKEY_REQUIRED: 'members.gate.PASSKEY_REQUIRED',
  SECOND_FACTOR_REMOVED: 'members.gate.SECOND_FACTOR_REMOVED',
  RATE_LIMITED: 'members.gate.RATE_LIMITED',
  IDEMPOTENCY_KEY_BUSY: 'members.gate.IDEMPOTENCY_KEY_BUSY',
  STEP_UP_FAILED: 'members.gate.STEP_UP_FAILED',
  FORBIDDEN: 'members.gate.FORBIDDEN',
};

/** Each area's own refusals the person can act on, in plain words; any other by its code. */
const MEMBER_REFUSALS = new Set(['OWN_MEMBERSHIP', 'ROLE_UNCHANGED', 'MEMBER_DEACTIVATED', 'BAD_REQUEST', 'NOT_FOUND']);
const INVITATION_REFUSALS = new Set([
  'INVITATION_CLOSED',
  'INVITATION_INVALID',
  'ALREADY_A_MEMBER',
  'BAD_REQUEST',
  'NOT_FOUND',
]);
const CONTACT_REFUSALS = new Set([
  'CONTACT_EXISTS',
  'CONTACTS_FULL',
  'CONTACT_ADDS_SPENT',
  'TOO_MANY_CONTACTS',
  'CONTACT_CLOSED',
  'CONTACT_NOT_ACTIVE',
  'BAD_REQUEST',
  'NOT_FOUND',
]);
const RESET_REFUSALS = new Set([
  'OWN_RESET',
  'MEMBER_DEACTIVATED',
  'MEMBER_ELSEWHERE',
  'NO_COUNTING_CONTACTS',
  'RESET_OPEN',
  'RESET_CLOSED',
  'RESET_ASKS_SPENT',
  'TOO_MANY_RESETS',
  'TOO_MANY_CONTACTS',
  'CONTACT_NOT_ACTIVE',
  'BAD_REQUEST',
  'NOT_FOUND',
]);

type Area = 'members' | 'invitations' | 'contacts' | 'resets';
const KNOWN: Readonly<Record<Area, ReadonlySet<string>>> = {
  members: MEMBER_REFUSALS,
  invitations: INVITATION_REFUSALS,
  contacts: CONTACT_REFUSALS,
  resets: RESET_REFUSALS,
};

/** What a refusal or failure in one area says: a record that failed the integrity check as itself (a 503). */
const refusalIn =
  (area: Area, own: Readonly<Record<string, TextKey>> = {}) =>
  (error: unknown): string => {
    if (isIntegrityFailed(error)) return t('members.integrity');
    return refusalText(error, KNOWN[area], `${area}.refused`, { ...GATES, ...own });
  };

export const memberRefusal = refusalIn('members');
export const invitationRefusal = refusalIn('invitations');
export const contactRefusal = refusalIn('contacts');
export const resetRefusal = refusalIn('resets');
/** A registered contact's confirm from their link (CO9): a link not known, or not of its form, said as the link's. */
export const contactLinkRefusal = refusalIn('resets', {
  NOT_FOUND: 'resets.contact.notFound',
  BAD_REQUEST: 'resets.contact.badLink',
});
