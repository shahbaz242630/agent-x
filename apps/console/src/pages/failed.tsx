import { Link } from '@tanstack/react-router';

import { t } from '../text.ts';
import { Panel } from './panel.tsx';

/** A page that couldn't load: say so plainly, and offer the one thing to do. */
export function Failed({ onRetry }: { readonly onRetry: () => void }) {
  return (
    <Panel id="failed" title={t('error.title')} narrow branded={false} role="alert">
      <p className="muted">{t('error.body')}</p>
      <button type="button" className="primary" onClick={onRetry}>
        {t('error.retry')}
      </button>
    </Panel>
  );
}

/** A part of a page that couldn't load, inside the shell: said in place, with a retry. */
export function Retry({ onRetry }: { readonly onRetry: () => void }) {
  return (
    <div className="notice" role="alert">
      <p>{t('error.body')}</p>
      <button type="button" className="secondary" onClick={onRetry}>
        {t('error.retry')}
      </button>
    </div>
  );
}

export function NotFound() {
  return (
    <section className="stack">
      <h1>{t('notFound.title')}</h1>
      <Link to="/approvals">{t('notFound.home')}</Link>
    </section>
  );
}
