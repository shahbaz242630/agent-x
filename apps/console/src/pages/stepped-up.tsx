// Back from signing in again for a change (6A2, step-up.ts): the page the
// change was asked on, with `?stepped=<challenge>` beside its own query. The
// person sees the change once more and confirms it, or doesn't; either way the
// step-up's query is cleaned off, the page's own kept (CO5).
// A challenge with nothing kept for it (another tab's, already confirmed,
// storage cleared) is said: the change wasn't made, and can be asked again.
// Back with `?stepUpFailed=<challenge>` instead (CO2: the API refused the
// fresh sign-in), the change kept for it is forgotten and that is said. A
// confirm refused for words that changed since they were read (CO3) says so:
// asked again, the person reads them as they are now.
// A confirm that answers with a new agent key (6D1: registering, rotating,
// handing over) shows it once (key-once.tsx). The key lives only in the
// confirming view's state, which is drawn afresh for each challenge: it
// unmounts, and the key with it, once the step-up's query leaves the address.
// Until the person presses Done, any other way away is asked about first
// (key-once.tsx), and leaving the page clears it.
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';

import { isRefusal, isUuid } from '../api.ts';
import { confirm, forget, ownQuery, pendingFor, STEP_UP_FAILED, STEPPED } from '../step-up.ts';
import { t } from '../text.ts';
import { KeyOnce, keyIn, linkIn } from './key-once.tsx';

type Sent = 'ready' | 'sending' | 'done' | 'refused' | 'wordsChanged' | 'failed';

/** What a confirm's refusal says: the words changed since read (CO3), or refused otherwise. */
const refusedAs = (error: unknown): Sent => {
  if (!isRefusal(error)) return 'failed';
  return error.code === 'STATEMENT_CHANGED' ? 'wordsChanged' : 'refused';
};

/** Each end's words, with the change named. */
const ENDED = { done: 'stepUp.done', refused: 'stepUp.refused', wordsChanged: 'stepUp.wordsChanged' } as const;

/** The address without the step-up's query, the page's own kept (CO5). */
function useClose() {
  const pathname = useRouterState({ select: ({ location }) => location.pathname });
  const query = useRouterState({ select: ({ location }) => location.searchStr });
  const navigate = useNavigate();
  return () => {
    const rest = ownQuery(query).toString();
    void navigate({ href: rest === '' ? pathname : `${pathname}?${rest}`, replace: true });
  };
}

export function SteppedUp() {
  // The raw query, not the router's parsed one, which reads values as JSON.
  const query = useRouterState({ select: ({ location }) => location.searchStr });
  const params = new URLSearchParams(query);
  const challenge = params.get(STEPPED) ?? undefined;
  // Only a challenge's ID, as the API sends: a link made up with anything else says nothing.
  const failed = params.get(STEP_UP_FAILED);
  const failedFor = failed !== null && isUuid(failed) ? failed : undefined;
  const close = useClose();
  useEffect(() => {
    // Its sign-in was refused: the change is never confirmed with it, so nothing is kept for it.
    if (failedFor !== undefined) forget(failedFor);
  }, [failedFor]);
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
  // Drawn afresh for each challenge, and gone with none: whatever its confirm answered goes with it.
  return challenge === undefined ? null : <Stepped key={challenge} challenge={challenge} close={close} />;
}

function Stepped({ challenge, close }: { readonly challenge: string; readonly close: () => void }) {
  const pending = useMemo(() => pendingFor(challenge), [challenge]);
  const [sent, setSent] = useState<Sent>('ready');
  // A new key from the confirm's answer: this view's memory only, never storage, the query cache or the address.
  // Or an invitation's link (6D4b), held the same way.
  const [answered, setAnswered] = useState<ReturnType<typeof keyIn> | ReturnType<typeof linkIn>>(undefined);
  const queries = useQueryClient();
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
      const answer = await confirm(pending);
      setAnswered(keyIn(answer) ?? linkIn(answer));
      setSent('done');
      // Whatever the change touched reads again.
      await queries.invalidateQueries();
    } catch (error) {
      setSent(refusedAs(error));
    }
  };
  // Its own branch, not the done one below: only the done words are a live region, so the key is never read out.
  if (sent === 'done' && answered !== undefined) {
    return (
      <section className="stepped">
        <p role="status">{t('stepUp.done', { change: pending.label })}</p>
        <KeyOnce secret={answered.key} kind={'kind' in answered ? answered.kind : 'key'} onDone={close} />
      </section>
    );
  }
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
