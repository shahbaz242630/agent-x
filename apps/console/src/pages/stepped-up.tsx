// Back from signing in again for a change (6A2, step-up.ts): the page the
// change was asked on, with `?stepped=<challenge>`. The person sees the change
// once more and confirms it, or doesn't; either way the address is cleaned.
// A challenge with nothing kept for it (another tab's, already confirmed,
// storage cleared) is said: the change wasn't made, and can be asked again.
// Back with `?stepUpFailed=<challenge>` instead (CO2: the API refused the
// fresh sign-in), the change kept for it is forgotten and that is said. A
// confirm refused for words that changed since they were read (CO3) says so:
// asked again, the person reads them as they are now.
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';

import { isRefusal, isUuid } from '../api.ts';
import { confirm, forget, pendingFor, STEP_UP_FAILED, STEPPED } from '../step-up.ts';
import { t } from '../text.ts';

type Sent = 'ready' | 'sending' | 'done' | 'refused' | 'wordsChanged' | 'failed';

/** What a confirm's refusal says: the words changed since read (CO3), or refused otherwise. */
const refusedAs = (error: unknown): Sent => {
  if (!isRefusal(error)) return 'failed';
  return error.code === 'STATEMENT_CHANGED' ? 'wordsChanged' : 'refused';
};

/** Each end's words, with the change named. */
const ENDED = { done: 'stepUp.done', refused: 'stepUp.refused', wordsChanged: 'stepUp.wordsChanged' } as const;

export function SteppedUp() {
  const pathname = useRouterState({ select: ({ location }) => location.pathname });
  // The raw query, not the router's parsed one, which reads values as JSON.
  const query = useRouterState({ select: ({ location }) => location.searchStr });
  const params = new URLSearchParams(query);
  const challenge = params.get(STEPPED) ?? undefined;
  // Only a challenge's ID, as the API sends: a link made up with anything else says nothing.
  const failed = params.get(STEP_UP_FAILED);
  const failedFor = failed !== null && isUuid(failed) ? failed : undefined;
  const pending = useMemo(() => (challenge === undefined ? undefined : pendingFor(challenge)), [challenge]);
  const [sent, setSent] = useState<Sent>('ready');
  const queries = useQueryClient();
  const navigate = useNavigate();
  useEffect(() => {
    // Its sign-in was refused: the change is never confirmed with it, so nothing is kept for it.
    if (failedFor !== undefined) forget(failedFor);
  }, [failedFor]);
  const close = () => {
    setSent('ready');
    void navigate({ to: pathname, search: {}, replace: true });
  };
  if (failedFor !== undefined) {
    return (
      <section className="notice stepped" role="alert">
        <p>{t('stepUp.signInFailed')}</p>
        <button type="button" className="secondary" onClick={close}>
          {t('stepUp.close')}
        </button>
      </section>
    );
  }
  if (challenge === undefined) return null;
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
      setSent(refusedAs(error));
    }
  };
  if (sent === 'done' || sent === 'refused' || sent === 'wordsChanged') {
    return (
      <section className={sent === 'done' ? 'stepped' : 'notice stepped'} role="status">
        <p>{t(ENDED[sent], { change: pending.label })}</p>
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
