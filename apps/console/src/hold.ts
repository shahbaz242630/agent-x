// The organisation's integrity hold (6D4a, ADR-012 §2, SEC-DB-10's clearing):
// what the hold page and the banner read (GET /v1/integrity-hold, an admin's
// alone), the investigation an admin records before clearing it, and the
// rules each keeps. The API answers no list of investigations, so the ones
// recorded in this tab are kept in its sessionStorage, by person and
// organisation (an ID, a conclusion and a ticket's reference: nothing
// secret), and only those of the hold as it now stands are offered to clear
// with. The API checks the investigation again whatever is named.
import { useQuery } from '@tanstack/react-query';

import { api, isIntegrityFailed, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import type { Role } from './session.tsx';
import { t, type TextKey } from './text.ts';

export interface Hold {
  readonly status: 'CLEAR' | 'HELD';
  /** Moves on by one each time it is set or cleared. */
  readonly version: number;
  readonly since: string;
  /** For a HELD one, how the tampering showed (a tamper sign); otherwise null. */
  readonly reason: string | null;
  /** For a HELD one, the kind of record it was found on; otherwise null. */
  readonly foundOn: string | null;
}

export const CONCLUSIONS = ['CAUSE_REMOVED', 'NO_TAMPERING'] as const;
export type Conclusion = (typeof CONCLUSIONS)[number];

export interface Investigation {
  readonly id: string;
  readonly holdVersion: number;
  readonly conclusion: Conclusion;
  readonly reference: string;
  /** Who recorded it, by their Agent X ID. */
  readonly recordedBy: string;
  readonly recordedAt: string;
}

/** Who may see, investigate and clear the hold: an admin (each route's access). */
export const HOLDING: readonly Role[] = ['admin'];

export const HOLD_PATH = '/v1/integrity-hold';

/** The hold, read only for an admin: no one else may, so no one else asks. */
export function useHold(organization: string, admin: boolean) {
  return useQuery({
    queryKey: ['integrity-hold', organization],
    enabled: admin,
    queryFn: async () => (await api.get<{ readonly hold: Hold }>(HOLD_PATH, { organization })).hold,
  });
}

/** What a clearing was shown and rests on: the hold's status, version and since. */
export const holdState = (hold: Hold): string => [hold.status, String(hold.version), hold.since].join('/');

/** An incident's reference, as the API takes it: a letter or digit, then letters, digits, `.`, `_` or `-`, 64 at most. */
export const REFERENCE_MOST = 64;
export const isReference = (text: string): boolean => /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(text);

/** The tamper signs the API names (TAMPER_SIGNS), each said in plain words; any other by its code. */
const SIGNS = new Set([
  'row',
  'deleted',
  'unsigned',
  'log',
  'pointer',
  'version',
  'seal',
  'status',
  'chain',
  'holding',
  'moved_back',
]);

/** How the tampering showed, in plain words. */
export const reasonText = (reason: string | null): string => {
  if (reason === null) return t('hold.reason.none');
  return SIGNS.has(reason) ? t(`hold.reason.${reason}` as TextKey) : t('hold.reason.other', { code: reason });
};

/** The kind of record it was found on, as the API names it (`audit_chain`), in words: `audit chain`. */
export const foundOnText = (foundOn: string | null): string =>
  foundOn === null ? t('hold.reason.none') : foundOn.replaceAll('_', ' ');

const KEY = 'agentx.hold-investigations.';
const keyOf = (user: string, organization: string) => `${KEY}${user.toLowerCase()}/${organization}`;

const isInvestigation = (value: unknown): value is Investigation =>
  typeof value === 'object' &&
  value !== null &&
  'id' in value &&
  typeof value.id === 'string' &&
  isUuid(value.id) &&
  'holdVersion' in value &&
  typeof value.holdVersion === 'number' &&
  'conclusion' in value &&
  (CONCLUSIONS as readonly unknown[]).includes(value.conclusion) &&
  'reference' in value &&
  typeof value.reference === 'string' &&
  'recordedBy' in value &&
  typeof value.recordedBy === 'string' &&
  'recordedAt' in value &&
  typeof value.recordedAt === 'string';

function keptAll(user: string, organization: string): readonly Investigation[] {
  try {
    const kept: unknown = JSON.parse(sessionStorage.getItem(keyOf(user, organization)) ?? '[]');
    return Array.isArray(kept) ? kept.filter(isInvestigation) : [];
  } catch {
    return [];
  }
}

/** The investigations recorded in this tab of the hold at `version`, newest first. */
export const investigationsOf = (user: string, organization: string, version: number): readonly Investigation[] =>
  keptAll(user, organization)
    .filter((investigation) => investigation.holdVersion === version)
    .toReversed();

/** Keeps an investigation just recorded, dropping any of an older hold. Storage blocked: none are kept. */
export function keepInvestigation(user: string, organization: string, investigation: Investigation): void {
  const current = keptAll(user, organization).filter((kept) => kept.holdVersion === investigation.holdVersion);
  try {
    sessionStorage.setItem(keyOf(user, organization), JSON.stringify([...current, investigation]));
  } catch {
    // Storage blocked: the page's own state still shows it while open.
  }
}

/** The refusals the hold's changes can meet that the admin can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'NOT_ON_HOLD',
  'NO_INVESTIGATION',
  'HOLD_CHANGED',
  'HISTORY_UNCHECKED',
  'STEP_UP_FAILED',
  'STEP_UP_NOT_ASKED',
  'IDEMPOTENCY_KEY_BUSY',
  'RATE_LIMITED',
  'BAD_REQUEST',
  'FORBIDDEN',
]);

/** What a refusal or failure of the hold's changes says: records failing their check (503) as itself. */
export function holdRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('hold.integrity');
  return refusalText(error, REFUSALS, 'hold.refused');
}
