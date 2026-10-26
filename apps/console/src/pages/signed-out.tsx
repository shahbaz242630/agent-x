import { signInAddress } from '../api.ts';
import { goTo } from '../navigate.ts';
import { t } from '../text.ts';

/** No one signed in: the one way in, back to the page they asked for. */
export function SignedOut({ ended }: { readonly ended: boolean }) {
  const signIn = () => {
    goTo(signInAddress(window.location.pathname + window.location.search));
  };
  return (
    <main className="center">
      <section className="panel narrow" aria-labelledby="signed-out">
        <span className="brand">{t('brand')}</span>
        <h1 id="signed-out">{t('signedOut.title')}</h1>
        <p className="muted">{ended ? t('signedOut.ended') : t('signedOut.body')}</p>
        <button type="button" className="primary" onClick={signIn}>
          {t('signedOut.button')}
        </button>
      </section>
    </main>
  );
}
