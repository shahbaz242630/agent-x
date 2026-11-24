import { useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { api } from '../api.ts';
import { dropAllTries } from '../held-tries.ts';
import { dropKept } from '../kept.ts';
import { goTo } from '../navigate.ts';
import { useActing } from '../session.tsx';
import { forgetAll } from '../step-up.ts';
import { t } from '../text.ts';
import { Freeze } from './freeze.tsx';
import { Icon } from './icons.tsx';
import { placesFor } from './places.ts';
import { markSignedOut } from './signed-out.tsx';

const UNTIL = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** Everything that isn't a main section yet: the organisation's freeze, the other brakes, the logs, the session and signing out. */
export function More() {
  const { session, organization } = useActing();
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
    dropAllTries();
    dropKept();
    forgetAll();
    markSignedOut();
    goTo('/');
  };
  return (
    <section className="stack">
      <h1>{t('more.title')}</h1>
      <Freeze />
      {/* Every other place, in the sidebar's groups, as cards: on a phone this page is where they live (CO11). Who is
          shown what is the sidebar's own rule (places.ts): the logs and the integrity hold an admin's alone. */}
      {placesFor(organization.role)
        .filter((group) => group.label !== 'nav.group.work' && group.label !== 'nav.group.organisation')
        .map((group) => (
          <nav key={group.label} className="stack" aria-label={t(group.label)}>
            <h2>{t(group.label)}</h2>
            <div className="place-cards">
              {group.places
                .filter((place) => place.tab !== true)
                .map((place) => (
                  <Link key={place.to} to={place.to} className="place-card">
                    <Icon name={place.icon} />
                    <span>{t(place.label)}</span>
                  </Link>
                ))}
            </div>
          </nav>
        ))}
      <section className="stack session-card" aria-labelledby="session-heading">
        <h2 id="session-heading">{t('more.sessionHeading')}</h2>
        {/* Both ends (E2E6 F8): the one a person away meets first, moved on by each request, and the latest. */}
        <p className="muted">
          {t('more.session', {
            idle: UNTIL.format(new Date(session.idleExpiresAt)),
            time: UNTIL.format(new Date(session.expiresAt)),
          })}
        </p>
        <button type="button" className="secondary" disabled={leaving} onClick={() => void signOut()}>
          {t('more.signOut')}
        </button>
        {failed && (
          <p className="notice" role="alert">
            {t('more.signOutFailed')}
          </p>
        )}
      </section>
    </section>
  );
}
