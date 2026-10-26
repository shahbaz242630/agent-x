import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { api } from '../api.ts';
import { goTo } from '../navigate.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';

const UNTIL = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** Everything that isn't a main section yet: for now, the session and signing out. */
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
