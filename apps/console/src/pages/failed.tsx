import { Link } from '@tanstack/react-router';
import type { ReactNode } from 'react';

import { isIntegrityFailed } from '../api.ts';
import { t } from '../text.ts';
import { Panel } from './panel.tsx';

/** A page, or a part of one, still loading. */
export function Loading() {
  return (
    <p className="loading" role="status">
      {t('loading')}
    </p>
  );
}

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

/**
 * One thing's page (a request's, a payment's, an agent's) that can't show it: an address that names none, or the
 * API's 404, is not found, never a failure to retry; a record that failed its integrity check is said as itself
 * where the page has words for it; anything else offers a retry.
 */
export function NotShown({
  back,
  missing,
  error,
  notFound,
  integrity,
  onRetry,
}: {
  readonly back: ReactNode;
  readonly missing: boolean;
  readonly error: unknown;
  readonly notFound: string;
  readonly integrity?: string;
  readonly onRetry: () => void;
}) {
  let said = <Retry onRetry={onRetry} />;
  if (missing) said = <p className="notice">{notFound}</p>;
  else if (integrity !== undefined && isIntegrityFailed(error)) said = <p className="notice">{integrity}</p>;
  return (
    <section className="stack">
      {back}
      {said}
    </section>
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
