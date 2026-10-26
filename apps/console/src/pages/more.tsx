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
  const signOut = async () => {
    setLeaving(true);
    try {
      await api.post('/v1/auth/sign-out');
    } catch {
      // Signed out or not, this page forgets the session and starts afresh: the API ends an unused session by itself.
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
    </section>
  );
}
