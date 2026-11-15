// What a refused or failed change says, the same on every screen: a browser
// that keeps no storage can't step up; no answer, or a 5xx, is a failure on
// the way; a refusal the screen knows is said in its plain words (its own for
// this step, where the step words a code differently: a reject's BAD_REQUEST is
// about its reason); any other by its code.
import { isRefusal } from './api.ts';
import { StepUpStorageBlocked } from './step-up.ts';
import { t, type TextKey } from './text.ts';

export function refusalText(
  error: unknown,
  known: ReadonlySet<string>,
  prefix: 'request.refused' | 'brakes.refused' | 'payments.refused',
  ownWords: Readonly<Record<string, TextKey>> = {},
): string {
  if (error instanceof StepUpStorageBlocked) return t('request.storageBlocked');
  if (!isRefusal(error)) return t('request.failed');
  const own = ownWords[error.code];
  if (own !== undefined) return t(own);
  return known.has(error.code)
    ? t(`${prefix}.${error.code}` as TextKey)
    : t('request.refused.other', { code: error.code });
}
