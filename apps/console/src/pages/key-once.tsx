// An agent's new key, shown once (6D1; ADR-011 §1: only the key's MAC is
// kept, so no one can show it again). It arrives in a confirm's answer
// (registering, rotating, handing over) and is held only in the state of the
// view that confirmed: never sessionStorage or localStorage, the address, the
// query cache, a log or an error report. Masked until "Show"; copied by the
// Clipboard API, said copied only once the write is done (and said when it
// fails). Until "Done, I've saved it", leaving is asked about first: any link
// inside the console (the router's blocker), a reload or closing the tab (the
// browser's own question), and switching organisation waits (KeyHold). Once
// the page is hidden for good or kept for Back (pagehide, the back/forward
// cache), the key is cleared, so coming back never shows it again.
import { useBlocker } from '@tanstack/react-router';
import { createContext, type ReactNode, useContext, useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';

import { t } from '../text.ts';

/** What stands for the key while it is hidden: never its length or any of it. */
const MASK = '•'.repeat(24);

/**
 * The key a confirm answered with: none for a change that gives no key; null
 * for one that gives a key but answered without it (a retry of the same
 * confirm: only the first answer carries it).
 */
export function keyIn(answer: unknown): { readonly key: string | null } | undefined {
  if (typeof answer !== 'object' || answer === null || !('key' in answer)) return undefined;
  return { key: typeof answer.key === 'string' ? answer.key : null };
}

/** Told while a key is on screen and not yet saved: the shell holds what would drop it without a navigation. */
const Hold = createContext<(held: boolean) => void>(() => undefined);

export function KeyHold({
  onHeld,
  children,
}: {
  readonly onHeld: (held: boolean) => void;
  readonly children: ReactNode;
}) {
  return <Hold value={onHeld}>{children}</Hold>;
}

type Copied = 'not yet' | 'copied' | 'failed';

/** Asked when a link inside the console would leave the key behind: stay (and save it), or leave without it. */
function LeaveQuestion({ onStay, onLeave }: { readonly onStay: () => void; readonly onLeave: () => void }) {
  const stay = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    stay.current?.focus();
  }, []);
  return (
    <div className="notice" role="alert">
      <p>{t('keyOnce.leaveQuestion')}</p>
      <div className="actions">
        <button type="button" className="secondary" onClick={onLeave}>
          {t('keyOnce.leave')}
        </button>
        <button ref={stay} type="button" className="primary" onClick={onStay}>
          {t('keyOnce.stay')}
        </button>
      </div>
    </div>
  );
}

export function KeyOnce({ secret, onDone }: { readonly secret: string | null; readonly onDone: () => void }) {
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState<Copied>('not yet');
  const [gone, setGone] = useState(false);
  // Set once the person is done with it, or the page is going: the view's own way out is never asked about.
  const released = useRef(false);
  const holding = secret !== null && !gone;
  const leaving = useBlocker({
    shouldBlockFn: () => !released.current,
    // A reload or a closed tab is asked about below, by this page's own listener, whichever history the router has.
    enableBeforeUnload: false,
    disabled: !holding,
    withResolver: true,
  });
  const hold = useContext(Hold);
  // The latest way out, for the page-hide listener: the caller's changes each render, which mustn't re-hold.
  const done = useRef(onDone);
  useEffect(() => {
    done.current = onDone;
  });
  useEffect(() => {
    if (!holding) return undefined;
    hold(true);
    // Leaving or reloading the page loses the key for good: the browser asks first.
    const stay = (event: BeforeUnloadEvent) => {
      if (!released.current) event.preventDefault();
    };
    // Hidden for good, or kept for Back: cleared now (flushed, so the kept page holds no key), and the view closed.
    const clear = () => {
      released.current = true;
      flushSync(() => {
        setGone(true);
      });
      done.current();
    };
    window.addEventListener('beforeunload', stay);
    window.addEventListener('pagehide', clear);
    return () => {
      hold(false);
      window.removeEventListener('beforeunload', stay);
      window.removeEventListener('pagehide', clear);
    };
  }, [holding, hold]);
  if (gone) return null;
  if (secret === null) {
    return (
      <>
        <p className="notice">{t('keyOnce.retried')}</p>
        <button type="button" className="secondary" onClick={onDone}>
          {t('stepUp.close')}
        </button>
      </>
    );
  }
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied('copied');
    } catch {
      // No clipboard here, or the browser refused it: said, so no one pastes an old one.
      setCopied('failed');
    }
  };
  return (
    <section className="key-once" aria-labelledby="key-once-title">
      <h2 id="key-once-title">{t('keyOnce.title')}</h2>
      <p className="notice">{t('keyOnce.warning')}</p>
      <code className="secret mono" aria-label={shown ? t('keyOnce.shownLabel') : t('keyOnce.hiddenLabel')}>
        {shown ? secret : MASK}
      </code>
      <div className="actions">
        <button
          type="button"
          className="secondary"
          aria-pressed={shown}
          onClick={() => {
            setShown(!shown);
          }}
        >
          {t(shown ? 'keyOnce.hide' : 'keyOnce.show')}
        </button>
        <button type="button" className="secondary" onClick={() => void copy()}>
          {t('keyOnce.copy')}
        </button>
        <button
          type="button"
          className="primary"
          onClick={() => {
            released.current = true;
            onDone();
          }}
        >
          {t('keyOnce.done')}
        </button>
      </div>
      {copied !== 'not yet' && (
        <p className={copied === 'failed' ? 'notice' : 'fine'} role="status">
          {t(copied === 'copied' ? 'keyOnce.copied' : 'keyOnce.copyFailed')}
        </p>
      )}
      {leaving.status === 'blocked' && <LeaveQuestion onStay={leaving.reset} onLeave={leaving.proceed} />}
    </section>
  );
}
