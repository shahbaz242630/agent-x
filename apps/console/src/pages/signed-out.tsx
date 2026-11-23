import { signInAddress } from '../api.ts';
import { goTo } from '../navigate.ts';
import { t } from '../text.ts';
import { Panel } from './panel.tsx';
import { cameBackLate, withoutSignInLate } from './sign-in-late.tsx';

/** No one signed in: the one way in, back to the page they asked for. */
export function SignedOut({ ended }: { readonly ended: boolean }) {
  const signIn = () => {
    goTo(signInAddress(withoutSignInLate(window.location.pathname, window.location.search)));
  };
  const late = cameBackLate(window.location.search);
  return (
    <Panel id="signed-out" title={t('signedOut.title')} narrow>
      {late && (
        <p className="notice" role="alert">
          {t('signIn.late')}
        </p>
      )}
      <p className="muted">{ended ? t('signedOut.ended') : t('signedOut.body')}</p>
      <button type="button" className="primary" onClick={signIn}>
        {t('signedOut.button')}
      </button>
    </Panel>
  );
}
