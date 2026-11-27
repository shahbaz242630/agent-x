// Your passkeys (SA6): `/more/passkeys`, anyone signed in. A person adds a
// passkey here, after signing in again with one they already hold, instead of
// at the login service directly, which would start 7 days of developer or
// viewer powers (said on the page always). passkeys.ts has the way through.
// Back from the step-up (`?adding=<id>`) the page asks for the add-a-passkey
// page's address as it loads, so the person opens it from a click (no pop-up
// blocker), in a new tab with no way back to this one; then it checks every
// few seconds until the passkey is added or gone, the person is signed out
// (as every change of a sign-in method ends their sessions), or ten minutes
// pass. A step-up refused (`?stepUpFailed=`) is said in this page's words too:
// it needs a passkey, never a password or an app's code.
import { useRouterState } from '@tanstack/react-router';
import { useEffect, useRef, useState } from 'react';

import { isRefusal, isSignedOut, isUuid } from '../api.ts';
import { goTo } from '../navigate.ts';
import {
  ADDING,
  type AdditionStatus,
  beginAddition,
  pageFor,
  passkeyRefusal,
  type PasskeyPage,
  statusOf,
  stepUpFor,
} from '../passkeys.ts';
import { STEP_UP_FAILED, STEP_UP_WHY } from '../step-up.ts';
import { t, type TextKey } from '../text.ts';
import { Said, useChange } from './change.tsx';

/** How often the page checks where the addition got to, and for how long at most. */
export const CHECK_EVERY_MS = 3000;
export const CHECK_FOR_MS = 10 * 60_000;

/** Starts adding a passkey: off to sign in again with one already held. */
function Start({ label }: { readonly label: TextKey }) {
  const { busy, said, run } = useChange(passkeyRefusal);
  return (
    <>
      <div className="actions">
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              goTo(stepUpFor(await beginAddition()));
              return 'stepping';
            })
          }
        >
          {t(label)}
        </button>
      </div>
      <Said said={said} />
    </>
  );
}

type Ended = 'signedOut' | 'stopped';

/** Checks where addition `id` got to every few seconds, once `on`, until it ends one way or another. */
function useStatus(id: string, on: boolean): { readonly status: AdditionStatus | undefined; readonly ended?: Ended } {
  const [status, setStatus] = useState<AdditionStatus>();
  const [ended, setEnded] = useState<Ended>();
  useEffect(() => {
    if (!on) return undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    const until = Date.now() + CHECK_FOR_MS;
    const check = async () => {
      try {
        const now = await statusOf(id);
        if (stopped) return;
        setStatus(now);
        if (now === 'ADDED' || now === 'GONE') return;
      } catch (error) {
        if (stopped) return;
        // Signed out is expected once a key is added; any other refusal won't change by asking again.
        if (isSignedOut(error)) {
          setEnded('signedOut');
          return;
        }
        if (isRefusal(error)) {
          setEnded('stopped');
          return;
        }
      }
      if (Date.now() >= until) {
        setEnded('stopped');
        return;
      }
      timer = setTimeout(() => void check(), CHECK_EVERY_MS);
    };
    timer = setTimeout(() => void check(), CHECK_EVERY_MS);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [id, on]);
  return { status, ...(ended !== undefined && { ended }) };
}

/** The add-a-passkey page's address, asked for once as the page loads; kept in this view's memory alone. */
function usePage(id: string): { readonly page?: PasskeyPage; readonly said?: string } {
  const [got, setGot] = useState<{ readonly page?: PasskeyPage; readonly said?: string }>({});
  // One ask, one key: React may run the effect twice, and a second ask would be refused as already given out.
  const asked = useRef<Promise<PasskeyPage> | undefined>(undefined);
  useEffect(() => {
    let gone = false;
    asked.current ??= pageFor(id, crypto.randomUUID());
    asked.current.then(
      (page) => {
        if (!gone) setGot({ page });
      },
      (error: unknown) => {
        if (!gone) setGot({ said: passkeyRefusal(error) });
      },
    );
    return () => {
      gone = true;
    };
  }, [id]);
  return got;
}

/** Whether the one-time link has run out: a timer to `expiresAt`. */
function useRunOut(page: PasskeyPage | undefined): boolean {
  const [runOut, setRunOut] = useState(false);
  useEffect(() => {
    if (page === undefined) return undefined;
    const timer = setTimeout(
      () => {
        setRunOut(true);
      },
      Math.max(0, page.expiresAt - Date.now()),
    );
    return () => {
      clearTimeout(timer);
    };
  }, [page]);
  return runOut;
}

/** Back from signing in again for addition `id`: the page to open, then where it got to. */
function Adding({ id }: { readonly id: string }) {
  const { page, said } = usePage(id);
  const { status, ended } = useStatus(id, page !== undefined);
  const runOut = useRunOut(page);
  if (status === 'ADDED') {
    return (
      <section className="stepped" role="status">
        <p>{t('passkeys.added')}</p>
        <p>{t('passkeys.addedSignOut')}</p>
      </section>
    );
  }
  if (status === 'GONE' || said !== undefined || (runOut && status !== 'WAITING_FOR_KEY')) {
    let words = t('passkeys.gone');
    if (said !== undefined) words = said;
    else if (status !== 'GONE') words = t('passkeys.runOut');
    return (
      <section className="notice stepped" role="alert">
        <p>{words}</p>
        <Start label="passkeys.again" />
      </section>
    );
  }
  if (ended === 'signedOut') {
    return (
      <p className="notice" role="alert">
        {t('passkeys.signedOut')}
      </p>
    );
  }
  if (page === undefined) return <p className="muted">{t('passkeys.getting')}</p>;
  return (
    <section className="stepped" aria-labelledby="passkey-open">
      <h2 id="passkey-open">{t('passkeys.signedInAgain')}</h2>
      <p>
        <a className="primary big" href={page.page} target="_blank" rel="noopener noreferrer">
          {t('passkeys.open')}
        </a>
      </p>
      <p className="muted">{t('passkeys.openHint')}</p>
      <p role="status">{t(ended === 'stopped' ? 'passkeys.stopped' : 'passkeys.waiting')}</p>
    </section>
  );
}

export function Passkeys() {
  // The raw query, not the router's parsed one, which reads values as JSON.
  const query = useRouterState({ select: ({ location }) => location.searchStr });
  const params = new URLSearchParams(query);
  const adding = params.get(ADDING);
  const failed = params.get(STEP_UP_FAILED);
  // The shell says why for a day's step-ups spent or time run out; with no why, it was most likely no passkey.
  const noPasskey = failed !== null && isUuid(failed) && params.get(STEP_UP_WHY) === null;
  return (
    <section className="stack">
      <h1>{t('passkeys.title')}</h1>
      <p className="muted">{t('passkeys.intro')}</p>
      <p className="notice">{t('passkeys.sevenDays')}</p>
      {noPasskey && (
        <p className="notice" role="alert">
          {t('passkeys.needPasskey')}
        </p>
      )}
      {/* Keyed by the addition: another one starts afresh, nothing of the last one kept. */}
      {adding !== null && isUuid(adding) ? <Adding key={adding} id={adding} /> : <Start label="passkeys.add" />}
    </section>
  );
}
