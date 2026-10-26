// Back from signing in again for a change (6A2, step-up.ts): the page the
// change was asked on, with `?stepped=<challenge>`. The person sees the change
// once more and confirms it, or doesn't; either way the address is cleaned.
// A challenge with nothing kept for it (another tab's, already confirmed,
// storage cleared) is said: the change wasn't made, and can be asked again.
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useMemo, useState } from 'react';

import { isRefusal } from '../api.ts';
import { confirm, forget, pendingFor, STEPPED } from '../step-up.ts';
import { t } from '../text.ts';

type Sent = 'ready' | 'sending' | 'done' | 'refused' | 'failed';

export function SteppedUp() {
  const pathname = useRouterState({ select: ({ location }) => location.pathname });
  // The raw query, not the router's parsed one, which reads values as JSON.
  const query = useRouterState({ select: ({ location }) => location.searchStr });
  const challenge = new URLSearchParams(query).get(STEPPED) ?? undefined;
  const pending = useMemo(() => (challenge === undefined ? undefined : pendingFor(challenge)), [challenge]);
  const [sent, setSent] = useState<Sent>('ready');
  const queries = useQueryClient();
  const navigate = useNavigate();
  if (challenge === undefined) return null;
  const close = () => {
    setSent('ready');
    void navigate({ to: pathname, search: {}, replace: true });
  };
  if (pending === undefined) {
    return (
      <section className="notice stepped" role="alert">
        <p>{t('stepUp.lost')}</p>
        <button type="button" className="secondary" onClick={close}>
          {t('stepUp.close')}
        </button>
      </section>
    );
  }
  const send = async () => {
    setSent('sending');
    try {
      await confirm(pending);
      setSent('done');
      // Whatever the change touched reads again.
      await queries.invalidateQueries();
    } catch (error) {
      setSent(isRefusal(error) ? 'refused' : 'failed');
    }
  };
  if (sent === 'done' || sent === 'refused') {
    return (
      <section className={sent === 'done' ? 'stepped' : 'notice stepped'} role="status">
        <p>{t(sent === 'done' ? 'stepUp.done' : 'stepUp.refused', { change: pending.label })}</p>
        <button type="button" className="secondary" onClick={close}>
          {t('stepUp.close')}
        </button>
      </section>
    );
  }
  return (
    <section className="stepped" aria-labelledby="stepped-title">
      <h2 id="stepped-title">{t('stepUp.title')}</h2>
      <p>{pending.label}</p>
      {sent === 'failed' && (
        <p className="notice" role="alert">
          {t('stepUp.failed')}
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={sent === 'sending'}
          onClick={() => {
            forget(pending.challenge);
            close();
          }}
        >
          {t('stepUp.notNow')}
        </button>
        <button type="button" className="primary" disabled={sent === 'sending'} onClick={() => void send()}>
          {t('stepUp.confirm')}
        </button>
      </div>
    </section>
  );
}
