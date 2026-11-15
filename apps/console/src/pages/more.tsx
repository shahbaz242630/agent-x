import { useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { api } from '../api.ts';
import { goTo } from '../navigate.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Freeze } from './freeze.tsx';

const UNTIL = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** Everything that isn't a main section yet: the organisation's freeze, the other brakes, the session and signing out. */
export function More() {
  const { session } = useActing();
  const queries = useQueryClient();
  const [leaving, setLeaving] = useState(false);
  const [failed, setFailed] = useState(false);
  const signOut = async () => {
    setLeaving(true);
    setFailed(false);
    try {
      await api.post('/v1/auth/sign-out');
    } catch {
      // Still signed in (the cookie holds a live session), so a fresh start would sign them straight back in:
      // the page says so instead, for someone leaving a shared computer.
      setLeaving(false);
      setFailed(true);
      return;
    }
    queries.clear();
    goTo('/');
  };
  return (
    <section className="stack">
      <h1>{t('more.title')}</h1>
      <Freeze />
      <nav className="stack" aria-label={t('more.brakes')}>
        <h2>{t('more.brakes')}</h2>
        <Link to="/more/suppliers">{t('brakes.suppliers.title')}</Link>
        <Link to="/more/sources">{t('brakes.sources.title')}</Link>
      </nav>
      <h2>{t('more.sessionHeading')}</h2>
      <p className="muted">{t('more.session', { time: UNTIL.format(new Date(session.expiresAt)) })}</p>
      <button type="button" className="secondary" disabled={leaving} onClick={() => void signOut()}>
        {t('more.signOut')}
      </button>
      {failed && (
        <p className="notice" role="alert">
          {t('more.signOutFailed')}
        </p>
      )}
    </section>
  );
}
