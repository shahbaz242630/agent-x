// What a refused or failed change says, the same on every screen: a browser
// that keeps no storage can't step up; no answer, or a 5xx, is a failure on
// the way; a refusal the screen knows is said in its plain words (its own for
// this step, where the step words a code differently: a reject's BAD_REQUEST is
// about its reason); any other by its code.
import { isRefusal } from './api.ts';
import { StepUpStorageBlocked } from './step-up.ts';
import { t, type TextKey } from './text.ts';

/** The API's code for the 7 days after a sign-in method is removed or a passkey added (B6-3d). */
export const RESTRICTED = 'SECOND_FACTOR_REMOVED';

export function refusalText(
  error: unknown,
  known: ReadonlySet<string>,
  prefix:
    | 'request.refused'
    | 'brakes.refused'
    | 'payments.refused'
    | 'agents.refused'
    | 'logs.refused'
    | 'evidence.refused'
    | 'suppliers.refused'
    | 'sources.refused'
    | 'hold.refused'
    | 'members.refused'
    | 'invitations.refused'
    | 'contacts.refused'
    | 'resets.refused'
    | 'mandates.refused'
    | 'policies.refused'
    | 'connect.refused',
  ownWords: Readonly<Record<string, TextKey>> = {},
): string {
  if (error instanceof StepUpStorageBlocked) return t('request.storageBlocked');
  if (!isRefusal(error)) return t('request.failed');
  const own = ownWords[error.code];
  if (own !== undefined) return t(own);
  if (known.has(error.code)) return t(`${prefix}.${error.code}` as TextKey);
  // The 7-day restriction after a sign-in method changes refuses reads too: said in words, never by its code.
  if (error.code === RESTRICTED) return t('error.restricted');
  return t('request.refused.other', { code: error.code });
}
