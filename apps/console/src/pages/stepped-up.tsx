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
// A confirm whose screen has its own words for a refusal (OWN_WORDS, by its
// confirm address: the hold's clearing, 6D4a) says it in them, a record failing
// its integrity check too, which ends it: asking again changes nothing.
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { type ReactNode, useEffect, useMemo, useState } from 'react';

import { isIntegrityFailed, isRefusal, isSignedOut, isUuid } from '../api.ts';
import { HOLD_PATH, holdRefusal } from '../hold.ts';
import { endSession } from '../session.tsx';
import {
  confirm,
  forget,
  isUndecided,
  ownQuery,
  type PendingChange,
  pendingFor,
  STEP_UP_FAILED,
  STEPPED,
} from '../step-up.ts';
import { t, type TextKey } from '../text.ts';
import { KeyOnce, keyIn, linkIn } from './key-once.tsx';

/** How a confirm ended in its screen's own words: refused (`made: false`), or its result unknown (`made: null`). */
interface Said {
  readonly said: string;
  readonly made: false | null;
}

type Sent = 'ready' | 'sending' | 'done' | 'refused' | 'wordsChanged' | 'failed' | 'busy' | Said;

/** A screen's own words for its confirm: a refusal's, and a record failing its integrity check, after which its result is unknown. */
interface OwnWords {
  readonly refused: (error: unknown) => string;
  readonly unsure: TextKey;
}

/**
 * The confirms whose refusals their screen words itself, by confirm address.
 * The hold's clear may fail its integrity check after the clear committed
 * (hold-clearing.ts, the hold read again as signed), so that says only that
 * the result isn't known, and the hold page shows where it stands.
 */
const OWN_WORDS: ReadonlyMap<string, OwnWords> = new Map([
  [`${HOLD_PATH}/clear/confirm`, { refused: holdRefusal, unsure: 'hold.clear.unsure' }],
]);

/** A confirm's end in its screen's own words, if it has them; none for an undecided answer or a failure on the way. */
function ownWords(confirmPath: string, error: unknown): Said | undefined {
  const words = OWN_WORDS.get(confirmPath);
  if (words === undefined || isUndecided(error)) return undefined;
  if (isIntegrityFailed(error)) return { said: t(words.unsure), made: null };
  return isRefusal(error) ? { said: words.refused(error), made: false } : undefined;
}

/** What a confirm's refusal says: undecided (try again), the words changed since read (CO3), or refused otherwise. */
const refusedAs = (error: unknown): Sent => {
  if (!isRefusal(error)) return 'failed';
  if (isUndecided(error)) return 'busy';
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
      // A link comes only from opening an invitation's draft: an approval's answer names the invitation too, with none.
      setAnswered(keyIn(answer) ?? (pending.drafted === true ? linkIn(answer) : undefined));
      setSent('done');
      // Whatever the change touched reads again.
      await queries.invalidateQueries();
    } catch (error) {
      // The session ended: to sign-in, which comes back to this address, `?stepped=` and all, the change still kept
      // (confirm keeps it for a 401); the API then says whether the challenge still stands.
      if (isSignedOut(error)) {
        endSession(queries);
        return;
      }
      const own = ownWords(pending.confirmPath, error);
      if (own === undefined) {
        setSent(refusedAs(error));
        return;
      }
      // Ended: a refusal was forgotten by confirm; a record failing its check is, here. What it touched reads again
      // at once, so its page shows where it truly stands.
      forget(pending.challenge);
      setSent(own);
      await queries.invalidateQueries();
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
  if (typeof sent === 'object') {
    return (
      <Ended onClose={close}>
        {sent.made === false && <p>{t('stepUp.notMade', { change: pending.label })}</p>}
        <p>{sent.said}</p>
      </Ended>
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
  let said: string | undefined;
  if (sent === 'failed' || sent === 'busy') said = t(sent === 'busy' ? 'stepUp.busy' : 'stepUp.failed');
  return (
    <ConfirmKept pending={pending} sending={sent === 'sending'} said={said} onSend={() => void send()} onDrop={close} />
  );
}

/** A confirm that ended: what it said, and Close. */
export function Ended({ onClose, children }: { readonly onClose: () => void; readonly children: ReactNode }) {
  return (
    <section className="notice stepped" role="status">
      {children}
      <button type="button" className="secondary" onClick={onClose}>
        {t('stepUp.close')}
      </button>
    </section>
  );
}

/** The change kept for a step-up, to confirm or not make: `said` what the last try met, if it is to be tried again. */
export function ConfirmKept({
  pending,
  sending,
  said,
  onSend,
  onDrop,
}: {
  readonly pending: PendingChange;
  readonly sending: boolean;
  readonly said: string | undefined;
  readonly onSend: () => void;
  readonly onDrop: () => void;
}) {
  return (
    <section className="stepped" aria-labelledby="stepped-title">
      <h2 id="stepped-title">{t('stepUp.title')}</h2>
      <p>{pending.label}</p>
      {said !== undefined && (
        <p className="notice" role="alert">
          {said}
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={sending}
          onClick={() => {
            forget(pending.challenge);
            onDrop();
          }}
        >
          {t('stepUp.notNow')}
        </button>
        <button type="button" className="primary" disabled={sending} onClick={onSend}>
          {t('stepUp.confirm')}
        </button>
      </div>
    </section>
  );
}
