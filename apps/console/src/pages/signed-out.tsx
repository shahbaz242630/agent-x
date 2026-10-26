import { signInAddress } from '../api.ts';
import { goTo } from '../navigate.ts';
import { t } from '../text.ts';
import { Panel } from './panel.tsx';

/** No one signed in: the one way in, back to the page they asked for. */
export function SignedOut({ ended }: { readonly ended: boolean }) {
  const signIn = () => {
    goTo(signInAddress(window.location.pathname + window.location.search));
  };
  return (
    <Panel id="signed-out" title={t('signedOut.title')} narrow>
      <p className="muted">{ended ? t('signedOut.ended') : t('signedOut.body')}</p>
      <button type="button" className="primary" onClick={signIn}>
        {t('signedOut.button')}
      </button>
    </Panel>
  );
}
