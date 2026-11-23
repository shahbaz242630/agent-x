// E6-P1 (S214): a sign-in or step-up whose way back found nothing waiting (too late, used already, or started in
// another window) comes back here with `?signInLate=1`, never left on a bare error at the callback, from which the
// browser's Back led to the login service's dead end. Said once, and the address cleaned when closed.
import { useNavigate, useRouterState } from '@tanstack/react-router';

import { t } from '../text.ts';

/** The query a sign-in that found nothing waiting at its way back comes home with (sign-in.ts, E6-P1). */
export const SIGN_IN_LATE = 'signInLate';

/** The address without it: what a sign-in started from here comes back to. */
export function withoutSignInLate(pathname: string, search: string): string {
  const query = new URLSearchParams(search);
  query.delete(SIGN_IN_LATE);
  const rest = query.toString();
  return rest === '' ? pathname : `${pathname}?${rest}`;
}

/** Whether the address says a sign-in came back late. */
export const cameBackLate = (search: string): boolean => new URLSearchParams(search).has(SIGN_IN_LATE);

/** Signed in: says the sign-in or step-up came back too late, so nothing changed, and how to carry on. */
export function SignInLate() {
  const pathname = useRouterState({ select: ({ location }) => location.pathname });
  const search = useRouterState({ select: ({ location }) => location.searchStr });
  const navigate = useNavigate();
  if (!cameBackLate(search)) return null;
  return (
    <section className="notice stepped" role="alert">
      <p>{t('signIn.lateSignedIn')}</p>
      <button
        type="button"
        className="secondary"
        onClick={() => void navigate({ href: withoutSignInLate(pathname, search), replace: true })}
      >
        {t('stepUp.close')}
      </button>
    </section>
  );
}
