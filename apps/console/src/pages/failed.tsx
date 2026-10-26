import { Link } from '@tanstack/react-router';

import { t } from '../text.ts';

/** A page that couldn't load: say so plainly, and offer the one thing to do. */
export function Failed({ onRetry }: { readonly onRetry: () => void }) {
  return (
    <main className="center">
      <section className="panel narrow" role="alert" aria-labelledby="failed">
        <h1 id="failed">{t('error.title')}</h1>
        <p className="muted">{t('error.body')}</p>
        <button type="button" className="primary" onClick={onRetry}>
          {t('error.retry')}
        </button>
      </section>
    </main>
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
